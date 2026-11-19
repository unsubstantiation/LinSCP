//! KDrive TCP wire framing and the client-side handshake state machine.
//!
//! This implementation was independently written from observed protocol field
//! layouts; see `docs/x2go-rendering.md` for provenance. It parses messages and
//! returns compressed image/selection bytes, but does not decode the images,
//! render a desktop, negotiate UDP, or implement clipboard or cursor behavior.
//! No remote session is started by this module.

use std::fmt;

pub const SERVER_HEADER_SIZE: usize = 56;
pub const CLIENT_EVENT_SIZE: usize = 41;
const REGION_HEADER_SIZE: usize = 64;
const MAX_MESSAGE: usize = 16 * 1024 * 1024;
// Permit one ordinary read beyond the largest message so a following message
// coalesced with its tail doesn't spuriously overflow the decoder.
const MAX_BUFFER: usize = MAX_MESSAGE + 64 * 1024;
const MAX_SELECTION: usize = 2 * 1024 * 1024;
const MAX_LIST: usize = 65_536;
const MAX_REGIONS: usize = 64;
const MAX_DIMENSION: u32 = 8192;
const MAX_PIXELS: u64 = 16_777_216;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    InvalidCookie,
    InvalidGeometry,
    InvalidHandshakeState,
    UnexpectedHandshakeMessage,
    UnsupportedServerVersion,
    UnsupportedMessage,
    MessageTooLarge,
    InvalidDimensions,
    TooManyRegions,
    AllocationFailed,
    Poisoned,
}

fn u16le(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}
fn u32le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
}
fn i32le(bytes: &[u8], offset: usize) -> i32 { u32le(bytes, offset) as i32 }
fn valid_size(width: u32, height: u32) -> bool {
    width != 0 && height != 0 && width <= MAX_DIMENSION && height <= MAX_DIMENSION &&
        u64::from(width) * u64::from(height) <= MAX_PIXELS
}
fn checked_end(start: usize, length: usize) -> Result<usize, WireError> {
    start.checked_add(length).filter(|&n| n <= MAX_MESSAGE).ok_or(WireError::MessageTooLarge)
}
fn owned(bytes: &[u8]) -> Result<Vec<u8>, WireError> {
    let mut result = Vec::new();
    result.try_reserve_exact(bytes.len()).map_err(|_| WireError::AllocationFailed)?;
    result.extend_from_slice(bytes);
    Ok(result)
}

/// A frame's compressed image region or a rectangular reference to a prior
/// cached frame. `data` is empty for a cache reference. Pixels are not decoded.
pub struct Region {
    pub source_id: u32,
    pub source_x: i32,
    pub source_y: i32,
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub data: Vec<u8>,
}

pub struct Frame {
    pub width: u32,
    pub height: u32,
    pub x: i32,
    pub y: i32,
    pub cache_id: u32,
    pub window_id: u32,
    pub regions: Vec<Region>,
}
impl Frame {
    pub fn is_main_image(&self) -> bool { self.cache_id == 0 && self.x == -1 && self.y == -1 }
}

pub struct Cursor {
    pub foreground: [u8; 3],
    pub background: [u8; 3],
    pub width: u16,
    pub height: u16,
    pub hot_x: u16,
    pub hot_y: u16,
    pub serial: u32,
    pub data: Vec<u8>,
}

pub struct Selection {
    pub selection: u32,
    pub format: u32,
    pub chunk_size: u32,
    pub first: bool,
    pub last: bool,
    pub compressed_size: u32,
    pub total: u32,
    pub data: Vec<u8>,
}

/// The payloads can contain screen contents or clipboard data and therefore
/// are deliberately excluded from debug logs.
pub enum Message {
    Frame(Frame),
    DeletedFrames(Vec<u32>),
    Cursor(Cursor),
    DeletedCursors(Vec<u32>),
    Selection(Selection),
    ServerVersion(u16),
    DemandSelection(u16),
    Reinitialize,
    WindowUpdate(Vec<u8>),
    Keepalive,
    Disconnect,
    UdpOpen,
    UdpFailed,
}
impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Frame(_) => "Frame([redacted])",
            Self::DeletedFrames(_) => "DeletedFrames",
            Self::Cursor(_) => "Cursor([redacted])",
            Self::DeletedCursors(_) => "DeletedCursors",
            Self::Selection(_) => "Selection([redacted])",
            Self::ServerVersion(_) => "ServerVersion",
            Self::DemandSelection(_) => "DemandSelection",
            Self::Reinitialize => "Reinitialize",
            Self::WindowUpdate(_) => "WindowUpdate([redacted])",
            Self::Keepalive => "Keepalive",
            Self::Disconnect => "Disconnect",
            Self::UdpOpen => "UdpOpen",
            Self::UdpFailed => "UdpFailed",
        };
        f.write_str(name)
    }
}

/// Incremental TCP parser. An invalid message or allocation failure poisons
/// the decoder: there is no safe way to find the next message boundary.
/// Callers should close the channel rather than retrying or silently dropping.
pub struct Decoder {
    buffer: Vec<u8>,
    offset: usize,
    failed: bool,
}
impl Default for Decoder {
    fn default() -> Self { Self::new() }
}
impl Decoder {
    pub fn new() -> Self { Self { buffer: Vec::new(), offset: 0, failed: false } }
    pub fn buffered(&self) -> usize { self.buffer.len() - self.offset }

    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), WireError> {
        if self.failed { return Err(WireError::Poisoned); }
        if self.buffered().checked_add(bytes.len()).filter(|&n| n <= MAX_BUFFER).is_none() {
            self.failed = true;
            return Err(WireError::MessageTooLarge);
        }
        // Drop consumed bytes before growing so the allocation limit applies to
        // live bytes even when the parser has read many small messages.
        if self.offset != 0 {
            self.buffer.copy_within(self.offset.., 0);
            self.buffer.truncate(self.buffer.len() - self.offset);
            self.offset = 0;
        }
        if self.buffer.try_reserve(bytes.len()).is_err() {
            self.failed = true;
            return Err(WireError::AllocationFailed);
        }
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }

    pub fn next_message(&mut self) -> Result<Option<Message>, WireError> {
        if self.failed { return Err(WireError::Poisoned); }
        match parse_message(&self.buffer[self.offset..]) {
            Ok(Some((message, consumed))) => { self.offset += consumed; Ok(Some(message)) }
            Ok(None) => Ok(None),
            Err(error) => { self.failed = true; Err(error) }
        }
    }
}

// Parsing is transactional: until the complete message is available it does
// not consume any bytes. Lengths are checked before allocating or copying.
fn parse_message(input: &[u8]) -> Result<Option<(Message, usize)>, WireError> {
    if input.len() < SERVER_HEADER_SIZE { return Ok(None); }
    let ty = u32le(input, 0);
    match ty {
        0 => {
            let width = u32le(input, 4);
            let height = u32le(input, 8);
            if !valid_size(width, height) { return Err(WireError::InvalidDimensions); }
            let count = u32le(input, 20) as usize;
            if count > MAX_REGIONS { return Err(WireError::TooManyRegions); }
            // First walk headers only. Incomplete frames must not repeatedly
            // allocate or copy completed image payloads on every network read.
            let mut cursor = SERVER_HEADER_SIZE;
            for _ in 0..count {
                let end = checked_end(cursor, REGION_HEADER_SIZE)?;
                if end > input.len() { return Ok(None); }
                let region = &input[cursor..end];
                if !valid_size(u32le(region, 20), u32le(region, 24)) { return Err(WireError::InvalidDimensions); }
                let data_length = if u32le(region, 0) == 0 { u32le(region, 28) as usize } else { 0 };
                cursor = checked_end(end, data_length)?;
                if cursor > input.len() { return Ok(None); }
            }
            let mut parts = Vec::new();
            parts.try_reserve_exact(count).map_err(|_| WireError::AllocationFailed)?;
            let mut position = SERVER_HEADER_SIZE;
            for _ in 0..count {
                let end = position + REGION_HEADER_SIZE;
                let region = &input[position..end];
                let source_id = u32le(region, 0);
                let after = end + if source_id == 0 { u32le(region, 28) as usize } else { 0 };
                parts.push(Region {
                    source_id, source_x: i32le(region, 4), source_y: i32le(region, 8),
                    x: i32le(region, 12), y: i32le(region, 16),
                    width: u32le(region, 20), height: u32le(region, 24),
                    data: owned(&input[end..after])?,
                });
                position = after;
            }
            Ok(Some((Message::Frame(Frame {
                width, height, x: i32le(input, 12), y: i32le(input, 16),
                cache_id: u32le(input, 24), window_id: u32le(input, 28), regions: parts,
            }), cursor)))
        }
        1 | 3 => {
            let count = u32le(input, 4) as usize;
            if count > MAX_LIST { return Err(WireError::MessageTooLarge); }
            let end = checked_end(SERVER_HEADER_SIZE, count * 4)?;
            if end > input.len() { return Ok(None); }
            let mut ids = Vec::new();
            ids.try_reserve_exact(count).map_err(|_| WireError::AllocationFailed)?;
            for n in 0..count { ids.push(u32le(input, SERVER_HEADER_SIZE + n * 4)); }
            let message = if ty == 1 { Message::DeletedFrames(ids) } else { Message::DeletedCursors(ids) };
            Ok(Some((message, end)))
        }
        2 => {
            let size = u32le(input, 24) as usize;
            let end = checked_end(SERVER_HEADER_SIZE, size)?;
            if end > input.len() { return Ok(None); }
            let cursor = Cursor {
                foreground: [input[4], input[5], input[6]], background: [input[7], input[8], input[9]],
                width: u16le(input, 10), height: u16le(input, 12),
                hot_x: u16le(input, 14), hot_y: u16le(input, 16), serial: u32le(input, 20),
                data: owned(&input[SERVER_HEADER_SIZE..end])?,
            };
            Ok(Some((Message::Cursor(cursor), end)))
        }
        4 => {
            let chunk_size = u32le(input, 12);
            let compressed_size = u32le(input, 24);
            let total = u32le(input, 28);
            let payload = if compressed_size == 0 { chunk_size } else { compressed_size } as usize;
            if payload > MAX_SELECTION || chunk_size as usize > MAX_SELECTION || total as usize > MAX_SELECTION {
                return Err(WireError::MessageTooLarge);
            }
            let end = checked_end(SERVER_HEADER_SIZE, payload)?;
            if end > input.len() { return Ok(None); }
            Ok(Some((Message::Selection(Selection {
                selection: u32le(input, 4), format: u32le(input, 8), chunk_size,
                first: u32le(input, 16) != 0, last: u32le(input, 20) != 0,
                compressed_size, total, data: owned(&input[SERVER_HEADER_SIZE..end])?,
            }), end)))
        }
        5 => Ok(Some((Message::ServerVersion(u16le(input, 4)), SERVER_HEADER_SIZE))),
        6 => Ok(Some((Message::DemandSelection(u16le(input, 4)), SERVER_HEADER_SIZE))),
        7 => Ok(Some((Message::Reinitialize, SERVER_HEADER_SIZE))),
        8 => {
            let end = checked_end(SERVER_HEADER_SIZE, u32le(input, 4) as usize)?;
            if end > input.len() { return Ok(None); }
            Ok(Some((Message::WindowUpdate(owned(&input[SERVER_HEADER_SIZE..end])?), end)))
        }
        9 => Ok(Some((Message::Keepalive, SERVER_HEADER_SIZE))),
        10 => Ok(Some((Message::Disconnect, SERVER_HEADER_SIZE))),
        // CACHEFRAME is a UDP-only packet and cannot be framed here as TCP.
        11 => Err(WireError::UnsupportedMessage),
        12 => Ok(Some((Message::UdpOpen, SERVER_HEADER_SIZE))),
        13 => Ok(Some((Message::UdpFailed, SERVER_HEADER_SIZE))),
        _ => Err(WireError::UnsupportedMessage),
    }
}

/// Contains the cookie; it must not be logged or sent anywhere except the
/// authenticated graphics channel. Its Debug output is always redacted.
pub struct Hello([u8; 32 + CLIENT_EVENT_SIZE]);
impl Hello { pub fn bytes(&self) -> &[u8] { &self.0 } }
impl fmt::Debug for Hello {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("Hello([redacted])") }
}
impl Drop for Hello {
    fn drop(&mut self) { self.0.fill(0); }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase { Initial, AwaitVersion, Ready, Failed }

/// Performs the wire-level handshake without performing I/O. A caller must write
/// `hello` fully on the SSH graphics channel, await a server-version message,
/// then write the geometry event fully. Timeouts and channel teardown belong to
/// the caller. Ready means version/geometry exchange, not that any pixels were
/// decoded or that the remote desktop started.
pub struct Handshake { phase: Phase, width: u16, height: u16 }
impl Handshake {
    pub fn new(width: u16, height: u16) -> Result<Self, WireError> {
        if !valid_size(u32::from(width), u32::from(height)) { return Err(WireError::InvalidGeometry); }
        Ok(Self { phase: Phase::Initial, width, height })
    }

    pub fn hello(&mut self, cookie: &str) -> Result<Hello, WireError> {
        if self.phase != Phase::Initial { return Err(WireError::InvalidHandshakeState); }
        if cookie.len() != 32 || !cookie.bytes().all(|b| b.is_ascii_hexdigit()) { return Err(WireError::InvalidCookie); }
        let mut bytes = [0; 32 + CLIENT_EVENT_SIZE];
        bytes[..32].copy_from_slice(cookie.as_bytes());
        // CLIENTVERSION (10), feature level 3, Windows-style clipboard mode (1).
        // Mode 1 is the interoperability profile; clipboard is not enabled here.
        bytes[32..36].copy_from_slice(&10u32.to_le_bytes());
        bytes[36..38].copy_from_slice(&3u16.to_le_bytes());
        bytes[38..40].copy_from_slice(&1u16.to_le_bytes());
        self.phase = Phase::AwaitVersion;
        Ok(Hello(bytes))
    }

    pub fn accept_version(&mut self, version: u16) -> Result<[u8; CLIENT_EVENT_SIZE], WireError> {
        if self.phase != Phase::AwaitVersion { return Err(WireError::InvalidHandshakeState); }
        // Restrict the first implementation to feature versions 7 and 8;
        // unknown versions must not silently change parsing rules.
        if !(7..=8).contains(&version) {
            self.phase = Phase::Failed;
            return Err(WireError::UnsupportedServerVersion);
        }
        let mut event = [0; CLIENT_EVENT_SIZE];
        event[0..4].copy_from_slice(&7u32.to_le_bytes());
        event[4..6].copy_from_slice(&self.width.to_le_bytes());
        event[6..8].copy_from_slice(&self.height.to_le_bytes());
        event[9..11].copy_from_slice(&self.width.to_le_bytes());
        event[11..13].copy_from_slice(&self.height.to_le_bytes());
        self.phase = Phase::Ready;
        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put32(buf: &mut [u8], at: usize, value: u32) { buf[at..at + 4].copy_from_slice(&value.to_le_bytes()); }
    fn put16(buf: &mut [u8], at: usize, value: u16) { buf[at..at + 2].copy_from_slice(&value.to_le_bytes()); }
    fn header(ty: u32) -> Vec<u8> {
        let mut h = vec![0; SERVER_HEADER_SIZE];
        put32(&mut h, 0, ty);
        h
    }
    // Synthetic, locally constructed packets; these do not contain captured
    // session data or copyrighted reference-client test fixtures.
    fn synthetic_frame() -> Vec<u8> {
        let mut result = header(0);
        put32(&mut result, 4, 4);
        put32(&mut result, 8, 2);
        put32(&mut result, 12, u32::MAX);
        put32(&mut result, 16, u32::MAX);
        put32(&mut result, 20, 2);
        let mut image = vec![0; REGION_HEADER_SIZE];
        put32(&mut image, 20, 2);
        put32(&mut image, 24, 2);
        put32(&mut image, 28, 3);
        result.extend(image);
        result.extend([0xaa, 0xbb, 0xcc]);
        let mut reference = vec![0; REGION_HEADER_SIZE];
        put32(&mut reference, 0, 123);
        put32(&mut reference, 4, 1);
        put32(&mut reference, 12, 2);
        put32(&mut reference, 20, 2);
        put32(&mut reference, 24, 2);
        // Nonzero source IDs have no inline bytes, regardless of this field.
        put32(&mut reference, 28, u32::MAX);
        result.extend(reference);
        result
    }

    #[test]
    fn hello_and_geometry_are_stateful_and_cookie_is_redacted() {
        let cookie = "0123456789abcdef0123456789abcdef";
        assert!(matches!(Handshake::new(0, 1), Err(WireError::InvalidGeometry)));
        assert!(matches!(Handshake::new(8192, 8192), Err(WireError::InvalidGeometry)));
        let mut h = Handshake::new(1280, 720).unwrap();
        assert_eq!(h.accept_version(8).unwrap_err(), WireError::InvalidHandshakeState);
        assert!(matches!(h.hello("not a cookie"), Err(WireError::InvalidCookie)));
        let hello = h.hello(cookie).unwrap();
        assert_eq!(&hello.bytes()[..32], cookie.as_bytes());
        assert_eq!(&hello.bytes()[32..40], &[10, 0, 0, 0, 3, 0, 1, 0]);
        assert!(hello.bytes()[40..].iter().all(|byte| *byte == 0));
        assert!(!format!("{hello:?}").contains(cookie));
        assert!(matches!(h.hello(cookie), Err(WireError::InvalidHandshakeState)));
        let mut old = Handshake::new(2, 1).unwrap();
        let _hello = old.hello(cookie).unwrap();
        assert_eq!(old.accept_version(6).unwrap_err(), WireError::UnsupportedServerVersion);
        assert_eq!(old.accept_version(8).unwrap_err(), WireError::InvalidHandshakeState);
        let mut future = Handshake::new(2, 1).unwrap();
        let _hello = future.hello(cookie).unwrap();
        assert_eq!(future.accept_version(9).unwrap_err(), WireError::UnsupportedServerVersion);
        let event = h.accept_version(8).unwrap();
        assert_eq!(&event[..13], &[7, 0, 0, 0, 0, 5, 208, 2, 0, 0, 5, 208, 2]);
        assert!(event[13..].iter().all(|byte| *byte == 0));
        assert_eq!(h.accept_version(8).unwrap_err(), WireError::InvalidHandshakeState);
    }

    #[test]
    fn incremental_mixed_stream_preserves_boundaries_at_every_split() {
        let mut version = header(5);
        put16(&mut version, 4, 8);
        let mut deleted = header(1);
        put32(&mut deleted, 4, 2);
        deleted.extend(42u32.to_le_bytes());
        deleted.extend(123u32.to_le_bytes());
        let frame = synthetic_frame();
        let wire = [version, frame, deleted, header(9), header(10)].concat();
        for stride in 1..=wire.len() {
            let mut decoder = Decoder::new();
            let mut seen = Vec::new();
            for part in wire.chunks(stride) {
                decoder.feed(part).unwrap();
                while let Some(message) = decoder.next_message().unwrap() { seen.push(message); }
            }
            assert_eq!(decoder.buffered(), 0, "stride {stride}");
            assert_eq!(seen.len(), 5, "stride {stride}");
            assert!(matches!(seen[0], Message::ServerVersion(8)));
            let Message::Frame(f) = &seen[1] else { panic!("not a frame"); };
            assert!(f.is_main_image());
            assert_eq!((f.width, f.height, f.regions.len()), (4, 2, 2));
            assert_eq!(f.regions[0].data, [0xaa, 0xbb, 0xcc]);
            assert_eq!(f.regions[1].source_id, 123);
            assert_eq!(f.regions[1].source_x, 1);
            assert!(f.regions[1].data.is_empty());
            assert!(matches!(&seen[2], Message::DeletedFrames(ids) if ids == &[42, 123]));
            assert!(matches!(seen[3], Message::Keepalive));
            assert!(matches!(seen[4], Message::Disconnect));
            assert!(!format!("{:?}", seen[1]).contains("170"));
        }
    }

    #[test]
    fn parses_cursor_selection_and_control_types() {
        let mut cursor = header(2);
        cursor[4..10].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        put16(&mut cursor, 10, 2);
        put16(&mut cursor, 12, 1);
        put16(&mut cursor, 14, 1);
        put32(&mut cursor, 20, 99);
        put32(&mut cursor, 24, 2);
        cursor.extend([12, 34]);
        let mut selection = header(4);
        put32(&mut selection, 4, 1);
        put32(&mut selection, 8, 1);
        put32(&mut selection, 12, 9);
        put32(&mut selection, 16, 1);
        put32(&mut selection, 20, 1);
        put32(&mut selection, 24, 3);
        put32(&mut selection, 28, 9);
        selection.extend([7, 8, 9]);
        let mut decoder = Decoder::new();
        decoder.feed(&[cursor, selection, header(7), header(12), header(13)].concat()).unwrap();
        let Some(Message::Cursor(c)) = decoder.next_message().unwrap() else { panic!("cursor"); };
        assert_eq!((c.width, c.height, c.hot_x, c.serial), (2, 1, 1, 99));
        assert_eq!(c.foreground, [1, 2, 3]);
        assert_eq!(c.data, [12, 34]);
        let Some(Message::Selection(s)) = decoder.next_message().unwrap() else { panic!("selection"); };
        assert_eq!((s.selection, s.format, s.chunk_size, s.compressed_size, s.total), (1, 1, 9, 3, 9));
        assert!(s.first && s.last);
        assert_eq!(s.data, [7, 8, 9]);
        assert!(matches!(decoder.next_message().unwrap(), Some(Message::Reinitialize)));
        assert!(matches!(decoder.next_message().unwrap(), Some(Message::UdpOpen)));
        assert!(matches!(decoder.next_message().unwrap(), Some(Message::UdpFailed)));
        assert!(decoder.next_message().unwrap().is_none());
    }

    #[test]
    fn malformed_streams_are_bounded_and_permanently_fail_closed() {
        for bad in [header(11), header(99)] {
            let mut decoder = Decoder::new();
            decoder.feed(&bad).unwrap();
            assert_eq!(decoder.next_message().unwrap_err(), WireError::UnsupportedMessage);
            assert_eq!(decoder.next_message().unwrap_err(), WireError::Poisoned);
            assert_eq!(decoder.feed(&[]).unwrap_err(), WireError::Poisoned);
        }
        let mut too_many = header(0);
        put32(&mut too_many, 4, 1);
        put32(&mut too_many, 8, 1);
        put32(&mut too_many, 20, 65);
        let mut decoder = Decoder::new();
        decoder.feed(&too_many).unwrap();
        assert_eq!(decoder.next_message().unwrap_err(), WireError::TooManyRegions);
        let mut giant = header(4);
        put32(&mut giant, 12, u32::MAX);
        let mut decoder = Decoder::new();
        decoder.feed(&giant).unwrap();
        assert_eq!(decoder.next_message().unwrap_err(), WireError::MessageTooLarge);
        let mut decoder = Decoder::new();
        assert_eq!(decoder.feed(&vec![0; MAX_BUFFER + 1]).unwrap_err(), WireError::MessageTooLarge);
        assert_eq!(decoder.feed(&[]).unwrap_err(), WireError::Poisoned);
    }

    #[test]
    fn largest_message_can_be_coalesced_with_a_following_header() {
        let mut bytes = header(0);
        put32(&mut bytes, 4, 1);
        put32(&mut bytes, 8, 1);
        put32(&mut bytes, 20, 1);
        let mut region = vec![0; REGION_HEADER_SIZE];
        put32(&mut region, 20, 1);
        put32(&mut region, 24, 1);
        put32(&mut region, 28, (MAX_MESSAGE - SERVER_HEADER_SIZE - REGION_HEADER_SIZE) as u32);
        bytes.extend(region);
        bytes.resize(MAX_MESSAGE, 0);
        bytes.extend(header(9));
        let mut decoder = Decoder::new();
        decoder.feed(&bytes).unwrap();
        assert!(matches!(decoder.next_message().unwrap(), Some(Message::Frame(_))));
        assert!(matches!(decoder.next_message().unwrap(), Some(Message::Keepalive)));
        assert_eq!(decoder.buffered(), 0);
    }

    #[test]
    fn malformed_region_and_list_lengths_fail_before_payload_arrives() {
        let mut frame = header(0);
        put32(&mut frame, 4, 2);
        put32(&mut frame, 8, 2);
        put32(&mut frame, 20, 1);
        let mut region = vec![0; REGION_HEADER_SIZE];
        put32(&mut region, 20, 2);
        put32(&mut region, 24, 2);
        put32(&mut region, 28, u32::MAX);
        frame.extend(region);
        let mut d = Decoder::new();
        d.feed(&frame).unwrap();
        assert_eq!(d.next_message().unwrap_err(), WireError::MessageTooLarge);
        let mut list = header(3);
        put32(&mut list, 4, u32::MAX);
        let mut d = Decoder::new();
        d.feed(&list).unwrap();
        assert_eq!(d.next_message().unwrap_err(), WireError::MessageTooLarge);
        let mut dimensions = header(0);
        put32(&mut dimensions, 4, u32::MAX);
        put32(&mut dimensions, 8, 1);
        let mut d = Decoder::new();
        d.feed(&dimensions).unwrap();
        assert_eq!(d.next_message().unwrap_err(), WireError::InvalidDimensions);
    }

    #[test]
    fn arbitrary_fragmented_inputs_never_panic() {
        let mut seed = 0x917a_93d2u32;
        for length in 0..700usize {
            let mut bytes = vec![0; length];
            for byte in &mut bytes {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                *byte = seed as u8;
            }
            // Mix valid-looking and unknown message headers.
            if length >= 4 { bytes[..4].copy_from_slice(&(seed % 20).to_le_bytes()); }
            let mut decoder = Decoder::new();
            for chunk in bytes.chunks(11) {
                if decoder.feed(chunk).is_err() { break; }
                match decoder.next_message() {
                    Ok(_) => {},
                    Err(_) => break,
                }
            }
        }
    }

    #[test]
    fn incomplete_region_does_not_consume_data_or_create_message() {
        let frame = synthetic_frame();
        let mut decoder = Decoder::new();
        decoder.feed(&frame[..frame.len() - 1]).unwrap();
        assert!(decoder.next_message().unwrap().is_none());
        assert_eq!(decoder.buffered(), frame.len() - 1);
        decoder.feed(&frame[frame.len() - 1..]).unwrap();
        assert!(matches!(decoder.next_message().unwrap(), Some(Message::Frame(_))));
        assert_eq!(decoder.buffered(), 0);
    }
}
