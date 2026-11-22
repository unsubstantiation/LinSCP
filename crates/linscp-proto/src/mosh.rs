//! Clean-room Mosh v2 (`MOSH_PROTOCOL_VERSION = 2`) SSH bootstrap, remote
//! server probe, inspectable multi-distro installer script, and encrypted UDP
//! state-synchronization client transport.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use linscp_crypto::ocb3::{
    MoshBase64Key, MoshCryptoSession, MoshDirection, MOSH_MAX_DATAGRAM_BYTES,
    MOSH_MIN_DATAGRAM_BYTES,
};
use rand::RngCore;
use tokio::net::{lookup_host, UdpSocket};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use crate::ssh::SshConnection;
use crate::{ProtoError, RemoteSession};

pub const MOSH_PROTOCOL_VERSION: u32 = 2;
pub const MOSH_DEFAULT_PORT_RANGE: &str = "60000:61000";

/// Remote probe command checking standard and common `PATH` locations for `mosh-server`.
pub const MOSH_PROBE_COMMAND: &str =
    "PATH=\"$PATH:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin\"; command -v mosh-server >/dev/null 2>&1";

const MOSH_DECOMPRESS_CAP_BYTES: usize = 1024 * 1024;
const MOSH_DATAGRAM_TARGET_MTU: usize = 1200;
const MOSH_PACKET_HEADER_BYTES: usize = 4;
const MOSH_FRAGMENT_HEADER_BYTES: usize = 10;
const MOSH_MAX_FRAGMENT_PAYLOAD: usize = MOSH_DATAGRAM_TARGET_MTU
    - MOSH_MIN_DATAGRAM_BYTES
    - MOSH_PACKET_HEADER_BYTES
    - MOSH_FRAGMENT_HEADER_BYTES;
const MOSH_MAX_FRAGMENTS_PER_INSTRUCTION: usize = 512;
const MOSH_MAX_RECEIVED_STATES: usize = 1024;
const MOSH_SEND_MINDELAY: Duration = Duration::from_millis(8);
const MOSH_ACK_DELAY: Duration = Duration::from_millis(100);
const MOSH_ACK_INTERVAL: Duration = Duration::from_millis(3000);
const MOSH_RETRANSMIT_MIN: Duration = Duration::from_millis(200);
const MOSH_RETRANSMIT_MAX: Duration = Duration::from_millis(2000);
const MOSH_PORT_HOP_INTERVAL: Duration = Duration::from_secs(10);
const MOSH_TIMESTAMP_STALE_MS: u128 = 60_000;

/// Validated UDP port or `LOW:HIGH` port range passed via `mosh-server -p`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoshPortSpec {
    Single(u16),
    Range { low: u16, high: u16 },
}

impl MoshPortSpec {
    /// Parses an optional Mosh port specification (`""`, `"60001"`, or `"60000:60010"`).
    pub fn parse_optional(raw: &str) -> Result<Option<Self>, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        if let Some((low_str, high_str)) = trimmed.split_once(':') {
            if high_str.contains(':') {
                return Err(format!(
                    "Invalid Mosh UDP port range '{trimmed}'; expected PORT or LOW:HIGH."
                ));
            }
            let low: u16 = low_str.parse().map_err(|_| {
                format!("Invalid Mosh UDP start port '{low_str}'; expected 1..65535.")
            })?;
            let high: u16 = high_str.parse().map_err(|_| {
                format!("Invalid Mosh UDP end port '{high_str}'; expected 1..65535.")
            })?;
            if low == 0 || high == 0 || low > high {
                return Err(format!(
                    "Invalid Mosh UDP port range '{trimmed}'; expected 1 <= LOW <= HIGH <= 65535."
                ));
            }
            Ok(Some(Self::Range { low, high }))
        } else {
            let port: u16 = trimmed.parse().map_err(|_| {
                format!("Invalid Mosh UDP port '{trimmed}'; expected 1..65535 or LOW:HIGH.")
            })?;
            if port == 0 {
                return Err("Mosh UDP port must be between 1 and 65535.".to_string());
            }
            Ok(Some(Self::Single(port)))
        }
    }

    pub fn as_cli_arg(self) -> String {
        match self {
            Self::Single(port) => port.to_string(),
            Self::Range { low, high } => format!("{low}:{high}"),
        }
    }
}

/// Probes whether `mosh-server` is installed on an authenticated SSH session.
pub async fn check_mosh_via_ssh(session: &dyn RemoteSession) -> Result<bool, ProtoError> {
    let ssh = session.ssh_connection().ok_or_else(|| {
        ProtoError::Transport(
            "Mosh server check requires an active SSH-backed session (SFTP or SCP).".to_string(),
        )
    })?;
    check_mosh_on_ssh_connection(&ssh).await
}

/// Probes whether `mosh-server` is installed using an `SshConnection` directly.
pub async fn check_mosh_on_ssh_connection(ssh: &SshConnection) -> Result<bool, ProtoError> {
    let out = ssh
        .exec_command_bounded(MOSH_PROBE_COMMAND, Duration::from_secs(12), 4096)
        .await?;
    Ok(out.exit_code == Some(0))
}

/// Inspectable multi-distro installer script for `mosh` (`mosh-server`).
///
/// Mirrors the X2Go installer security rules:
/// - Designed to run in an interactive SSH terminal after user review so `sudo`
///   can prompt for authorization interactively.
/// - Uses only pre-configured system package repositories (`apt-get`, `dnf`,
///   `yum`, `pacman`, `zypper`, `apk`, `pkg`) — never downloads unsigned scripts
///   or adds third-party repositories/keys.
/// - Does not silently alter host firewall rules.
/// - Verifies `mosh-server` is executable before reporting completion.
pub fn mosh_install_script() -> String {
    r#"#!/bin/bash
set -e
# Run in an interactive terminal so sudo can ask the user when needed.
# Uses only configured system repositories; ensure UDP 60000:61000 (or your configured Mosh port) is open in any firewall.
PATH="$PATH:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin"
if command -v mosh-server >/dev/null 2>&1; then
  echo "[linscp] mosh-server is already installed at $(command -v mosh-server)."
  exit 0
fi
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo" || true
if [ -f /etc/os-release ]; then . /etc/os-release; OS="${ID:-unknown}"; else OS="$(uname -s 2>/dev/null || echo unknown)"; fi
case "$OS" in
  debian|ubuntu|linuxmint|pop|kali|raspbian)
    $SUDO apt-get update -qq
    $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y mosh ;;
  fedora)
    $SUDO dnf install -y mosh ;;
  rhel|centos|almalinux|rocky|ol)
    $SUDO dnf install -y mosh || $SUDO yum install -y mosh ;;
  arch|manjaro|endeavouros)
    $SUDO pacman -S --needed --noconfirm mosh ;;
  opensuse*|sles)
    $SUDO zypper --non-interactive install mosh ;;
  alpine)
    $SUDO apk add mosh ;;
  FreeBSD|freebsd)
    $SUDO env ASSUME_ALWAYS_YES=yes pkg install mosh ;;
  *)
    echo "[linscp] Automatic Mosh package selection is unavailable for '$OS'; install the 'mosh' package manually from trusted repositories." >&2
    exit 1 ;;
esac
if ! command -v mosh-server >/dev/null 2>&1 && ! test -x /usr/bin/mosh-server && ! test -x /usr/local/bin/mosh-server; then
  echo "[linscp] mosh-server could not be verified after installation; check the server packages and installation paths." >&2
  exit 1
fi
echo "[linscp] Mosh server installation completed; mosh-server detected."
"#
    .to_string()
}

// ---------------------------------------------------------------------------
// Wire-level Protobuf codec (TransportBuffers / ClientBuffers / HostBuffers)
// ---------------------------------------------------------------------------

fn encode_varint(mut val: u64, out: &mut Vec<u8>) {
    while val >= 0x80 {
        out.push(((val as u8) & 0x7f) | 0x80);
        val >>= 7;
    }
    out.push(val as u8);
}

fn decode_varint(buf: &mut &[u8]) -> Result<u64, ProtoError> {
    let mut result = 0u64;
    let mut shift = 0u32;
    for _ in 0..10 {
        let (&byte, rest) = buf
            .split_first()
            .ok_or_else(|| ProtoError::Transport("Truncated Mosh protobuf varint.".to_string()))?;
        *buf = rest;
        if shift == 63 && byte > 1 {
            return Err(ProtoError::Transport(
                "Overflow in Mosh protobuf varint.".to_string(),
            ));
        }
        result |= u64::from(byte & 0x7f) << shift;
        if (byte & 0x80) == 0 {
            return Ok(result);
        }
        shift += 7;
    }
    Err(ProtoError::Transport(
        "Malformed Mosh protobuf varint.".to_string(),
    ))
}

fn encode_tag(field_number: u32, wire_type: u8, out: &mut Vec<u8>) {
    encode_varint((u64::from(field_number) << 3) | u64::from(wire_type), out);
}

fn encode_varint_field(field_number: u32, val: u64, out: &mut Vec<u8>) {
    encode_tag(field_number, 0, out);
    encode_varint(val, out);
}

fn encode_bytes_field(field_number: u32, bytes: &[u8], out: &mut Vec<u8>) {
    encode_tag(field_number, 2, out);
    encode_varint(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

fn decode_length_delimited<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8], ProtoError> {
    let len = usize::try_from(decode_varint(buf)?)
        .map_err(|_| ProtoError::Transport("Mosh protobuf field length overflow.".to_string()))?;
    if buf.len() < len {
        return Err(ProtoError::Transport(
            "Truncated Mosh length-delimited protobuf field.".to_string(),
        ));
    }
    let (head, tail) = buf.split_at(len);
    *buf = tail;
    Ok(head)
}

fn skip_unknown_field(wire_type: u8, buf: &mut &[u8]) -> Result<(), ProtoError> {
    match wire_type {
        0 => {
            decode_varint(buf)?;
            Ok(())
        }
        1 => {
            if buf.len() < 8 {
                return Err(ProtoError::Transport(
                    "Truncated 64-bit protobuf field.".to_string(),
                ));
            }
            *buf = &buf[8..];
            Ok(())
        }
        2 => {
            decode_length_delimited(buf)?;
            Ok(())
        }
        5 => {
            if buf.len() < 4 {
                return Err(ProtoError::Transport(
                    "Truncated 32-bit protobuf field.".to_string(),
                ));
            }
            *buf = &buf[4..];
            Ok(())
        }
        other => Err(ProtoError::Transport(format!(
            "Unsupported Mosh protobuf wire type {other}."
        ))),
    }
}

/// Decoded `TransportBuffers.Instruction`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportInstruction {
    pub protocol_version: u32,
    pub old_num: u64,
    pub new_num: u64,
    pub ack_num: u64,
    pub throwaway_num: u64,
    pub diff: Vec<u8>,
    pub chaff: Vec<u8>,
}

impl Default for TransportInstruction {
    fn default() -> Self {
        Self {
            protocol_version: MOSH_PROTOCOL_VERSION,
            old_num: 0,
            new_num: 0,
            ack_num: 0,
            throwaway_num: 0,
            diff: Vec::new(),
            chaff: Vec::new(),
        }
    }
}

impl TransportInstruction {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.diff.len() + self.chaff.len());
        encode_varint_field(1, u64::from(self.protocol_version), &mut out);
        encode_varint_field(2, self.old_num, &mut out);
        encode_varint_field(3, self.new_num, &mut out);
        encode_varint_field(4, self.ack_num, &mut out);
        encode_varint_field(5, self.throwaway_num, &mut out);
        if !self.diff.is_empty() {
            encode_bytes_field(6, &self.diff, &mut out);
        }
        if !self.chaff.is_empty() {
            encode_bytes_field(7, &self.chaff, &mut out);
        }
        out
    }

    pub fn decode(mut buf: &[u8]) -> Result<Self, ProtoError> {
        let mut inst = Self {
            protocol_version: 0,
            ..Self::default()
        };
        while !buf.is_empty() {
            let tag = decode_varint(&mut buf)?;
            let field = (tag >> 3) as u32;
            let wire_type = (tag & 0x07) as u8;
            match (field, wire_type) {
                (1, 0) => {
                    inst.protocol_version = u32::try_from(decode_varint(&mut buf)?).map_err(|_| {
                        ProtoError::Transport("Mosh protocol_version overflow.".to_string())
                    })?;
                }
                (2, 0) => inst.old_num = decode_varint(&mut buf)?,
                (3, 0) => inst.new_num = decode_varint(&mut buf)?,
                (4, 0) => inst.ack_num = decode_varint(&mut buf)?,
                (5, 0) => inst.throwaway_num = decode_varint(&mut buf)?,
                (6, 2) => inst.diff = decode_length_delimited(&mut buf)?.to_vec(),
                (7, 2) => inst.chaff = decode_length_delimited(&mut buf)?.to_vec(),
                _ => skip_unknown_field(wire_type, &mut buf)?,
            }
        }
        if inst.protocol_version != MOSH_PROTOCOL_VERSION {
            return Err(ProtoError::Transport(format!(
                "Unsupported Mosh protocol version {} (expected {}).",
                inst.protocol_version, MOSH_PROTOCOL_VERSION
            )));
        }
        Ok(inst)
    }
}

/// Client-to-server `ClientBuffers.UserMessage` action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserOp {
    Keystroke(Vec<u8>),
    Resize { width: u16, height: u16 },
}

pub fn encode_user_diff(ops: &[UserOp]) -> Vec<u8> {
    let mut msg = Vec::new();
    let mut inner = Vec::new();
    let mut sub = Vec::new();
    for op in ops {
        inner.clear();
        sub.clear();
        match op {
            UserOp::Keystroke(keys) => {
                encode_bytes_field(4, keys, &mut sub);
                encode_bytes_field(2, &sub, &mut inner);
            }
            UserOp::Resize { width, height } => {
                encode_varint_field(5, u64::from(*width), &mut sub);
                encode_varint_field(6, u64::from(*height), &mut sub);
                encode_bytes_field(3, &sub, &mut inner);
            }
        }
        encode_bytes_field(1, &inner, &mut msg);
    }
    msg
}

pub fn decode_user_diff(mut buf: &[u8]) -> Result<Vec<UserOp>, ProtoError> {
    let mut ops = Vec::new();
    while !buf.is_empty() {
        let tag = decode_varint(&mut buf)?;
        let field = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;
        if field == 1 && wire_type == 2 {
            let mut inst_buf = decode_length_delimited(&mut buf)?;
            while !inst_buf.is_empty() {
                let itag = decode_varint(&mut inst_buf)?;
                let ifield = (itag >> 3) as u32;
                let iwire = (itag & 0x07) as u8;
                match (ifield, iwire) {
                    (2, 2) => {
                        let mut ks_buf = decode_length_delimited(&mut inst_buf)?;
                        let mut keys = Vec::new();
                        while !ks_buf.is_empty() {
                            let ktag = decode_varint(&mut ks_buf)?;
                            if (ktag >> 3) == 4 && (ktag & 0x07) == 2 {
                                keys = decode_length_delimited(&mut ks_buf)?.to_vec();
                            } else {
                                skip_unknown_field((ktag & 0x07) as u8, &mut ks_buf)?;
                            }
                        }
                        ops.push(UserOp::Keystroke(keys));
                    }
                    (3, 2) => {
                        let mut rs_buf = decode_length_delimited(&mut inst_buf)?;
                        let mut width = 80u16;
                        let mut height = 24u16;
                        while !rs_buf.is_empty() {
                            let rtag = decode_varint(&mut rs_buf)?;
                            match (rtag >> 3, rtag & 0x07) {
                                (5, 0) => width = decode_varint(&mut rs_buf)?.clamp(1, u64::from(u16::MAX)) as u16,
                                (6, 0) => height = decode_varint(&mut rs_buf)?.clamp(1, u64::from(u16::MAX)) as u16,
                                (_, wt) => skip_unknown_field(wt as u8, &mut rs_buf)?,
                            }
                        }
                        ops.push(UserOp::Resize { width, height });
                    }
                    _ => skip_unknown_field(iwire, &mut inst_buf)?,
                }
            }
        } else {
            skip_unknown_field(wire_type, &mut buf)?;
        }
    }
    Ok(ops)
}

/// Server-to-client `HostBuffers.HostMessage` action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostOp {
    HostBytes(Vec<u8>),
    Resize { width: u16, height: u16 },
    EchoAck(u64),
}

pub fn encode_host_diff(ops: &[HostOp]) -> Vec<u8> {
    let mut msg = Vec::new();
    let mut inner = Vec::new();
    let mut sub = Vec::new();
    for op in ops {
        inner.clear();
        sub.clear();
        match op {
            HostOp::HostBytes(bytes) => {
                encode_bytes_field(4, bytes, &mut sub);
                encode_bytes_field(2, &sub, &mut inner);
            }
            HostOp::Resize { width, height } => {
                encode_varint_field(5, u64::from(*width), &mut sub);
                encode_varint_field(6, u64::from(*height), &mut sub);
                encode_bytes_field(3, &sub, &mut inner);
            }
            HostOp::EchoAck(num) => {
                encode_varint_field(8, *num, &mut sub);
                encode_bytes_field(7, &sub, &mut inner);
            }
        }
        encode_bytes_field(1, &inner, &mut msg);
    }
    msg
}

pub fn decode_host_diff(mut buf: &[u8]) -> Result<Vec<HostOp>, ProtoError> {
    let mut ops = Vec::new();
    while !buf.is_empty() {
        let tag = decode_varint(&mut buf)?;
        let field = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;
        if field == 1 && wire_type == 2 {
            let mut inst_buf = decode_length_delimited(&mut buf)?;
            while !inst_buf.is_empty() {
                let itag = decode_varint(&mut inst_buf)?;
                let ifield = (itag >> 3) as u32;
                let iwire = (itag & 0x07) as u8;
                match (ifield, iwire) {
                    (2, 2) => {
                        let mut hb_buf = decode_length_delimited(&mut inst_buf)?;
                        let mut bytes = Vec::new();
                        while !hb_buf.is_empty() {
                            let htag = decode_varint(&mut hb_buf)?;
                            if (htag >> 3) == 4 && (htag & 0x07) == 2 {
                                bytes = decode_length_delimited(&mut hb_buf)?.to_vec();
                            } else {
                                skip_unknown_field((htag & 0x07) as u8, &mut hb_buf)?;
                            }
                        }
                        if !bytes.is_empty() {
                            ops.push(HostOp::HostBytes(bytes));
                        }
                    }
                    (3, 2) => {
                        let mut rs_buf = decode_length_delimited(&mut inst_buf)?;
                        let mut width = 80u16;
                        let mut height = 24u16;
                        while !rs_buf.is_empty() {
                            let rtag = decode_varint(&mut rs_buf)?;
                            match (rtag >> 3, rtag & 0x07) {
                                (5, 0) => width = decode_varint(&mut rs_buf)?.clamp(1, u64::from(u16::MAX)) as u16,
                                (6, 0) => height = decode_varint(&mut rs_buf)?.clamp(1, u64::from(u16::MAX)) as u16,
                                (_, wt) => skip_unknown_field(wt as u8, &mut rs_buf)?,
                            }
                        }
                        ops.push(HostOp::Resize { width, height });
                    }
                    (7, 2) => {
                        let mut ea_buf = decode_length_delimited(&mut inst_buf)?;
                        let mut ack = 0u64;
                        while !ea_buf.is_empty() {
                            let etag = decode_varint(&mut ea_buf)?;
                            if (etag >> 3) == 8 && (etag & 0x07) == 0 {
                                ack = decode_varint(&mut ea_buf)?;
                            } else {
                                skip_unknown_field((etag & 0x07) as u8, &mut ea_buf)?;
                            }
                        }
                        ops.push(HostOp::EchoAck(ack));
                    }
                    _ => skip_unknown_field(iwire, &mut inst_buf)?,
                }
            }
        } else {
            skip_unknown_field(wire_type, &mut buf)?;
        }
    }
    Ok(ops)
}

// ---------------------------------------------------------------------------
// Zlib compression & Transport Fragmenter / Reassembler
// ---------------------------------------------------------------------------

pub fn compress_instruction(inst: &TransportInstruction) -> Result<Vec<u8>, ProtoError> {
    let raw = inst.encode();
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&raw)
        .map_err(|e| ProtoError::Transport(format!("Mosh zlib compression failed: {e}")))?;
    encoder
        .finish()
        .map_err(|e| ProtoError::Transport(format!("Mosh zlib finish failed: {e}")))
}

pub fn decompress_instruction(compressed: &[u8]) -> Result<TransportInstruction, ProtoError> {
    let decoder = ZlibDecoder::new(compressed);
    let mut bounded = decoder.take((MOSH_DECOMPRESS_CAP_BYTES + 1) as u64);
    let mut out = Vec::new();
    bounded
        .read_to_end(&mut out)
        .map_err(|e| ProtoError::Transport(format!("Mosh zlib decompression failed: {e}")))?;
    if out.len() > MOSH_DECOMPRESS_CAP_BYTES {
        return Err(ProtoError::Transport(
            "Mosh decompressed instruction exceeded 1 MiB safety limit.".to_string(),
        ));
    }
    TransportInstruction::decode(&out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoshFragment {
    pub instruction_id: u64,
    pub fragment_num: u16,
    pub is_final: bool,
    pub contents: Vec<u8>,
}

impl MoshFragment {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MOSH_FRAGMENT_HEADER_BYTES + self.contents.len());
        out.extend_from_slice(&self.instruction_id.to_be_bytes());
        let word = ((u16::from(self.is_final)) << 15) | (self.fragment_num & 0x7fff);
        out.extend_from_slice(&word.to_be_bytes());
        out.extend_from_slice(&self.contents);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        if bytes.len() < MOSH_FRAGMENT_HEADER_BYTES {
            return Err(ProtoError::Transport(
                "Truncated Mosh transport fragment header.".to_string(),
            ));
        }
        let mut id_bytes = [0u8; 8];
        id_bytes.copy_from_slice(&bytes[..8]);
        let instruction_id = u64::from_be_bytes(id_bytes);
        let word = u16::from_be_bytes([bytes[8], bytes[9]]);
        let is_final = (word & 0x8000) != 0;
        let fragment_num = word & 0x7fff;
        Ok(Self {
            instruction_id,
            fragment_num,
            is_final,
            contents: bytes[MOSH_FRAGMENT_HEADER_BYTES..].to_vec(),
        })
    }
}

pub struct Fragmenter {
    next_instruction_id: u64,
    last_encoded: Option<(TransportInstruction, u16, Vec<MoshFragment>)>,
}

impl Default for Fragmenter {
    fn default() -> Self {
        Self::new()
    }
}

impl Fragmenter {
    pub const fn new() -> Self {
        Self {
            next_instruction_id: 0,
            last_encoded: None,
        }
    }

    pub fn make_fragments(
        &mut self,
        inst: &TransportInstruction,
        max_payload: usize,
    ) -> Result<Vec<MoshFragment>, ProtoError> {
        let block = max_payload.max(64) as u16;
        // Identical instruction + MTU reuses the same instruction_id so lost fragments can reassemble.
        let same = self.last_encoded.as_ref().is_some_and(|(prev, prev_mtu, _)| {
            *prev_mtu == block
                && prev.protocol_version == inst.protocol_version
                && prev.old_num == inst.old_num
                && prev.new_num == inst.new_num
                && prev.ack_num == inst.ack_num
                && prev.throwaway_num == inst.throwaway_num
                && prev.diff == inst.diff
        });
        if same {
            if let Some((_, _, frags)) = &self.last_encoded {
                return Ok(frags.clone());
            }
        }

        let id = self.next_instruction_id;
        self.next_instruction_id = self.next_instruction_id.wrapping_add(1);
        let compressed = compress_instruction(inst)?;
        let step = usize::from(block);
        let mut frags = Vec::new();
        if compressed.is_empty() {
            frags.push(MoshFragment {
                instruction_id: id,
                fragment_num: 0,
                is_final: true,
                contents: Vec::new(),
            });
        } else {
            let total_chunks = compressed.len().div_ceil(step);
            if total_chunks > MOSH_MAX_FRAGMENTS_PER_INSTRUCTION {
                return Err(ProtoError::Transport(
                    "Mosh instruction requires too many UDP fragments.".to_string(),
                ));
            }
            for (idx, chunk) in compressed.chunks(step).enumerate() {
                frags.push(MoshFragment {
                    instruction_id: id,
                    fragment_num: idx as u16,
                    is_final: idx + 1 == total_chunks,
                    contents: chunk.to_vec(),
                });
            }
        }
        self.last_encoded = Some((inst.clone(), block, frags.clone()));
        Ok(frags)
    }
}

#[derive(Default)]
pub struct FragmentAssembly {
    current_id: Option<u64>,
    fragments: Vec<Option<Vec<u8>>>,
    fragments_arrived: usize,
    fragments_total: Option<usize>,
    bytes_accumulated: usize,
}

impl FragmentAssembly {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_fragment(
        &mut self,
        frag: MoshFragment,
    ) -> Result<Option<TransportInstruction>, ProtoError> {
        let idx = usize::from(frag.fragment_num);
        if idx >= MOSH_MAX_FRAGMENTS_PER_INSTRUCTION {
            return Err(ProtoError::Transport(
                "Mosh fragment index exceeded safety cap.".to_string(),
            ));
        }
        if self.current_id != Some(frag.instruction_id) {
            self.current_id = Some(frag.instruction_id);
            self.fragments.clear();
            self.fragments_arrived = 0;
            self.fragments_total = None;
            self.bytes_accumulated = 0;
        }
        if self.fragments.len() <= idx {
            self.fragments.resize(idx + 1, None);
        }
        if let Some(existing) = &self.fragments[idx] {
            if existing != &frag.contents {
                // Conflicting fragment payload on same instruction_id: reset assembly.
                self.current_id = None;
                self.fragments.clear();
                return Ok(None);
            }
        } else {
            if self.bytes_accumulated + frag.contents.len() > MOSH_DECOMPRESS_CAP_BYTES {
                self.current_id = None;
                self.fragments.clear();
                return Err(ProtoError::Transport(
                    "Mosh fragment assembly exceeded 1 MiB cap.".to_string(),
                ));
            }
            self.bytes_accumulated += frag.contents.len();
            self.fragments[idx] = Some(frag.contents);
            self.fragments_arrived += 1;
        }
        if frag.is_final {
            self.fragments_total = Some(idx + 1);
            if self.fragments.len() > idx + 1 {
                // Fragments arrived beyond the final index; discard inconsistent set.
                self.current_id = None;
                self.fragments.clear();
                return Ok(None);
            }
        }
        if let Some(total) = self.fragments_total {
            if self.fragments_arrived == total && self.fragments.iter().take(total).all(Option::is_some)
            {
                let mut joined = Vec::with_capacity(self.bytes_accumulated);
                for part in self.fragments.iter_mut().take(total) {
                    if let Some(bytes) = part.take() {
                        joined.extend_from_slice(&bytes);
                    }
                }
                self.fragments.clear();
                self.fragments_arrived = 0;
                self.fragments_total = None;
                self.bytes_accumulated = 0;
                return decompress_instruction(&joined).map(Some);
            }
        }
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// SSP State Synchronizer (Client Sender + Receiver)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ReceivedHostNode {
    num: u64,
    parent_num: u64,
    ops_from_parent: Vec<HostOp>,
}

/// High-level state transitions emitted by [`MoshStateEngine`] for the terminal view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MoshStateTransition {
    /// Advances the committed anchor screen along the server's `throwaway_num` chain.
    AdvanceAnchor(Vec<HostOp>),
    /// Common-case sequential diff (`old_num == current_head`) applied directly to the live screen.
    Incremental(Vec<HostOp>),
    /// Out-of-sync rebranch (`old_num != current_head`) reconstructed cleanly from the anchor screen.
    RebranchFromAnchor(Vec<HostOp>),
    /// Remote `mosh-server` sent clean shutdown (`new_num == u64::MAX`).
    ServerClosed,
}

pub struct MoshStateEngine {
    // Outgoing UserStream SSP state
    acked_user_num: u64,
    current_user_num: u64,
    transmitted_user_num: u64,
    pending_user_ops: VecDeque<(u64, UserOp)>,

    // Incoming HostMessage SSP state
    anchor_num: u64,
    received_nodes: Vec<ReceivedHostNode>,
}

impl Default for MoshStateEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl MoshStateEngine {
    pub fn new() -> Self {
        Self {
            acked_user_num: 0,
            current_user_num: 0,
            transmitted_user_num: 0,
            pending_user_ops: VecDeque::new(),
            anchor_num: 0,
            received_nodes: vec![ReceivedHostNode {
                num: 0,
                parent_num: 0,
                ops_from_parent: Vec::new(),
            }],
        }
    }

    pub fn head_remote_num(&self) -> u64 {
        self.received_nodes.last().map_or(0, |n| n.num)
    }

    pub fn has_unacked_user_ops(&self) -> bool {
        self.acked_user_num < self.current_user_num
    }

    pub fn has_unsent_user_ops(&self) -> bool {
        self.transmitted_user_num < self.current_user_num
    }

    pub fn push_keystrokes(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        // Coalesce adjacent unsent keystrokes so large pastes stay compact.
        if let Some((last_num, UserOp::Keystroke(existing))) = self.pending_user_ops.back_mut() {
            if *last_num > self.transmitted_user_num && existing.len() + bytes.len() <= 16_384 {
                existing.extend_from_slice(bytes);
                return;
            }
        }
        self.current_user_num += 1;
        self.pending_user_ops
            .push_back((self.current_user_num, UserOp::Keystroke(bytes.to_vec())));
    }

    pub fn push_resize(&mut self, cols: u16, rows: u16) {
        let width = cols.max(1);
        let height = rows.max(1);
        if let Some((last_num, UserOp::Resize { width: w, height: h })) =
            self.pending_user_ops.back_mut()
        {
            if *last_num > self.transmitted_user_num {
                *w = width;
                *h = height;
                return;
            }
        }
        self.current_user_num += 1;
        self.pending_user_ops
            .push_back((self.current_user_num, UserOp::Resize { width, height }));
    }

    pub fn build_outgoing_instruction(&mut self, chaff_len: usize) -> TransportInstruction {
        let mut chaff = vec![0u8; chaff_len.min(16)];
        if !chaff.is_empty() {
            rand::thread_rng().fill_bytes(&mut chaff);
        }
        if self.acked_user_num < self.current_user_num {
            let ops: Vec<UserOp> = self
                .pending_user_ops
                .iter()
                .filter(|(num, _)| *num > self.acked_user_num)
                .map(|(_, op)| op.clone())
                .collect();
            self.transmitted_user_num = self.current_user_num;
            TransportInstruction {
                protocol_version: MOSH_PROTOCOL_VERSION,
                old_num: self.acked_user_num,
                new_num: self.current_user_num,
                ack_num: self.head_remote_num(),
                throwaway_num: self.acked_user_num,
                diff: encode_user_diff(&ops),
                chaff,
            }
        } else {
            TransportInstruction {
                protocol_version: MOSH_PROTOCOL_VERSION,
                old_num: self.current_user_num,
                new_num: self.current_user_num,
                ack_num: self.head_remote_num(),
                throwaway_num: self.acked_user_num,
                diff: Vec::new(),
                chaff,
            }
        }
    }

    pub fn build_shutdown_instruction(&self) -> TransportInstruction {
        TransportInstruction {
            protocol_version: MOSH_PROTOCOL_VERSION,
            old_num: self.acked_user_num,
            new_num: u64::MAX,
            ack_num: self.head_remote_num(),
            throwaway_num: self.acked_user_num,
            diff: Vec::new(),
            chaff: Vec::new(),
        }
    }

    fn collect_chain(&self, from_num: u64, to_num: u64) -> Option<Vec<HostOp>> {
        if from_num == to_num {
            return Some(Vec::new());
        }
        let mut segments: Vec<&[HostOp]> = Vec::new();
        let mut cursor = to_num;
        while cursor != from_num {
            let node = self.received_nodes.iter().find(|n| n.num == cursor)?;
            if node.parent_num == node.num {
                return None;
            }
            segments.push(&node.ops_from_parent);
            cursor = node.parent_num;
        }
        let mut out = Vec::new();
        for seg in segments.into_iter().rev() {
            out.extend_from_slice(seg);
        }
        Some(out)
    }

    /// Processes a verified `TransportInstruction` from `mosh-server`, returning any
    /// resulting state transitions and whether a delayed data ACK should be scheduled.
    pub fn apply_incoming(
        &mut self,
        inst: &TransportInstruction,
    ) -> Result<(Vec<MoshStateTransition>, bool), ProtoError> {
        let mut transitions = Vec::new();

        // 1. Advance outgoing sender acknowledgments.
        if inst.ack_num > self.acked_user_num && inst.ack_num <= self.current_user_num {
            self.acked_user_num = inst.ack_num;
            while self
                .pending_user_ops
                .front()
                .is_some_and(|(num, _)| *num <= self.acked_user_num)
            {
                self.pending_user_ops.pop_front();
            }
            if self.transmitted_user_num < self.acked_user_num {
                self.transmitted_user_num = self.acked_user_num;
            }
        }

        // 2. Ignore duplicate state numbers already present.
        if self.received_nodes.iter().any(|n| n.num == inst.new_num) {
            return Ok((transitions, false));
        }

        // 3. Require reference state `old_num` to exist (idempotency invariant).
        if !self.received_nodes.iter().any(|n| n.num == inst.old_num) {
            return Ok((transitions, false));
        }

        // 4. Clean remote shutdown sentinel (`new_num == u64::MAX`).
        if inst.new_num == u64::MAX {
            transitions.push(MoshStateTransition::ServerClosed);
            return Ok((transitions, false));
        }

        // 5. Advance `anchor_num` up to the highest retained state `<= throwaway_num`
        // that is also an ancestor of `old_num` (or the lowest retained state >= throwaway_num).
        if inst.throwaway_num > self.anchor_num {
            if let Some(target_anchor) = self
                .received_nodes
                .iter()
                .filter(|n| n.num <= inst.throwaway_num && n.num <= inst.old_num)
                .map(|n| n.num)
                .max()
            {
                if target_anchor > self.anchor_num {
                    if let Some(retired_ops) = self.collect_chain(self.anchor_num, target_anchor) {
                        if !retired_ops.is_empty() {
                            transitions.push(MoshStateTransition::AdvanceAnchor(retired_ops));
                        }
                        self.anchor_num = target_anchor;
                        self.received_nodes.retain(|n| n.num >= target_anchor);
                        if let Some(root) =
                            self.received_nodes.iter_mut().find(|n| n.num == target_anchor)
                        {
                            root.parent_num = target_anchor;
                            root.ops_from_parent.clear();
                        }
                    }
                }
            }
        }

        if self.received_nodes.len() >= MOSH_MAX_RECEIVED_STATES {
            return Ok((transitions, false));
        }

        let ops = if inst.diff.is_empty() {
            Vec::new()
        } else {
            decode_host_diff(&inst.diff)?
        };
        let had_diff = !inst.diff.is_empty();

        let previous_head = self.head_remote_num();
        let insert_pos = self
            .received_nodes
            .partition_point(|n| n.num < inst.new_num);
        self.received_nodes.insert(
            insert_pos,
            ReceivedHostNode {
                num: inst.new_num,
                parent_num: inst.old_num,
                ops_from_parent: ops.clone(),
            },
        );

        // Only update the visible terminal when a strictly newer head state arrives.
        if inst.new_num > previous_head {
            if inst.old_num == previous_head {
                if !ops.is_empty() {
                    transitions.push(MoshStateTransition::Incremental(ops));
                }
            } else if let Some(chain_ops) = self.collect_chain(self.anchor_num, inst.new_num) {
                transitions.push(MoshStateTransition::RebranchFromAnchor(chain_ops));
            }
        }

        Ok((transitions, had_diff))
    }
}

// ---------------------------------------------------------------------------
// SSH Bootstrap (`MOSH CONNECT <port> <key>`) + Live UDP Session Handle
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct MoshConnectHandshake {
    pub udp_port: u16,
    pub key: MoshBase64Key,
    pub ssh_reported_ip: Option<IpAddr>,
}

/// Parses `mosh-server new` output for `MOSH CONNECT <port> <22-char-key>`
/// and optional `LINSCP_MOSH_IP <ip>`.
pub fn parse_mosh_connect_output(stdout_and_stderr: &str) -> Result<MoshConnectHandshake, ProtoError> {
    let mut ssh_reported_ip: Option<IpAddr> = None;
    let mut found_port_and_key: Option<(u16, MoshBase64Key)> = None;

    for raw_line in stdout_and_stderr.lines() {
        let line = raw_line.trim();
        if let Some(ip_str) = line.strip_prefix("LINSCP_MOSH_IP ") {
            if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
                ssh_reported_ip = Some(ip);
            }
        } else if let Some(rest) = line.strip_prefix("MOSH CONNECT ") {
            let mut parts = rest.split_whitespace();
            let port_str = parts.next().ok_or_else(|| {
                ProtoError::Transport("Malformed MOSH CONNECT line (missing UDP port).".to_string())
            })?;
            let key_str = parts.next().ok_or_else(|| {
                ProtoError::Transport("Malformed MOSH CONNECT line (missing session key).".to_string())
            })?;
            if parts.next().is_some() {
                return Err(ProtoError::Transport(
                    "Malformed MOSH CONNECT line (unexpected trailing tokens).".to_string(),
                ));
            }
            let port: u16 = port_str.parse().map_err(|_| {
                ProtoError::Transport(format!("Invalid Mosh UDP port '{port_str}'."))
            })?;
            if port == 0 {
                return Err(ProtoError::Transport(
                    "Mosh server returned invalid UDP port 0.".to_string(),
                ));
            }
            let key = MoshBase64Key::from_printable(key_str)
                .map_err(|e| ProtoError::Transport(format!("Invalid Mosh session key: {e}")))?;
            found_port_and_key = Some((port, key));
            break;
        }
    }

    let (udp_port, key) = found_port_and_key.ok_or_else(|| {
        let trimmed: String = stdout_and_stderr
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.trim().starts_with("LINSCP_MOSH_IP "))
            .take(4)
            .collect::<Vec<_>>()
            .join(" | ");
        if trimmed.is_empty() {
            ProtoError::Transport(
                "mosh-server did not return a MOSH CONNECT handshake.".to_string(),
            )
        } else {
            ProtoError::Transport(format!(
                "mosh-server failed to start ({trimmed}). Ensure a UTF-8 locale and UDP ports are available on the server."
            ))
        }
    })?;

    Ok(MoshConnectHandshake {
        udp_port,
        key,
        ssh_reported_ip,
    })
}

fn build_mosh_bootstrap_command(port_spec: Option<MoshPortSpec>) -> String {
    let port_flag = match port_spec {
        Some(spec) => format!(" -p {}", spec.as_cli_arg()),
        None => String::new(),
    };
    format!(
        "PATH=\"$PATH:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin\"; \
         LINSCP_MOSH_IP=$(printf '%s\\n' \"${{SSH_CONNECTION:-}}\" | awk '{{print $3}}'); \
         if [ -n \"$LINSCP_MOSH_IP\" ]; then printf 'LINSCP_MOSH_IP %s\\n' \"$LINSCP_MOSH_IP\"; fi; \
         LINSCP_UTF8_LOCALE=\"\"; \
         for cand in \"${{LC_ALL:-}}\" \"${{LC_CTYPE:-}}\" \"${{LANG:-}}\"; do \
           case \"$cand\" in *UTF-8*|*utf8*|*utf-8*) LINSCP_UTF8_LOCALE=\"$cand\"; break ;; esac; \
         done; \
         if [ -z \"$LINSCP_UTF8_LOCALE\" ] && command -v locale >/dev/null 2>&1; then \
           LINSCP_UTF8_LOCALE=$(locale -a 2>/dev/null | grep -i -E '^(C|en_US|POSIX)\\.(UTF-8|utf8)$' | head -n 1 || true); \
           if [ -z \"$LINSCP_UTF8_LOCALE\" ]; then \
             LINSCP_UTF8_LOCALE=$(locale -a 2>/dev/null | grep -i -E 'utf-?8' | head -n 1 || true); \
           fi; \
         fi; \
         [ -z \"$LINSCP_UTF8_LOCALE\" ] && LINSCP_UTF8_LOCALE=\"C.UTF-8\"; \
         mosh-server new -s -c 256 -l \"LANG=$LINSCP_UTF8_LOCALE\"{port_flag}"
    )
}

#[derive(Debug)]
enum MoshCommand {
    Input(Vec<u8>),
    Resize { cols: u16, rows: u16 },
    Close,
}

/// Events emitted by an active [`MoshSessionHandle`].
#[derive(Debug)]
pub enum MoshSessionEvent {
    AdvanceAnchor(Vec<HostOp>),
    Incremental(Vec<HostOp>),
    RebranchFromAnchor(Vec<HostOp>),
    Closed,
}

/// Interactive client handle to a running `mosh-server` over encrypted UDP.
#[derive(Clone)]
pub struct MoshSessionHandle {
    cmd_tx: mpsc::UnboundedSender<MoshCommand>,
    pub server_addr: SocketAddr,
}

impl MoshSessionHandle {
    pub fn write_bytes(&self, data: Vec<u8>) -> Result<(), ProtoError> {
        if data.is_empty() {
            return Ok(());
        }
        self.cmd_tx
            .send(MoshCommand::Input(data))
            .map_err(|_| ProtoError::Transport("Mosh UDP session is closed.".to_string()))
    }

    pub fn resize(&self, cols: u32, rows: u32) -> Result<(), ProtoError> {
        self.cmd_tx
            .send(MoshCommand::Resize {
                cols: cols.clamp(1, u32::from(u16::MAX)) as u16,
                rows: rows.clamp(1, u32::from(u16::MAX)) as u16,
            })
            .map_err(|_| ProtoError::Transport("Mosh UDP session is closed.".to_string()))
    }

    pub fn close(&self) {
        let _ = self.cmd_tx.send(MoshCommand::Close);
    }
}

async fn bind_connected_udp_socket(server_addr: SocketAddr) -> Result<UdpSocket, ProtoError> {
    let bind_addr = match server_addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let sock = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| ProtoError::Transport(format!("Failed to bind local Mosh UDP socket: {e}")))?;
    sock.connect(server_addr).await.map_err(|e| {
        ProtoError::Transport(format!(
            "Failed to connect Mosh UDP socket to {server_addr}: {e}"
        ))
    })?;
    Ok(sock)
}

fn timestamp16(epoch: Instant) -> u16 {
    let ms = (epoch.elapsed().as_millis() & 0xffff) as u16;
    if ms == 0xffff { 0 } else { ms }
}

fn compute_timestamp_reply(saved_remote_ts: Option<(u16, Instant)>) -> u16 {
    let Some((ts, received_at)) = saved_remote_ts else {
        return 0xffff;
    };
    let held_ms = received_at.elapsed().as_millis();
    if held_ms >= MOSH_TIMESTAMP_STALE_MS {
        return 0xffff;
    }
    let reply = ts.wrapping_add(held_ms as u16);
    if reply == 0xffff { 0 } else { reply }
}

async fn transmit_instruction(
    socket: &UdpSocket,
    crypto: &mut MoshCryptoSession,
    fragmenter: &mut Fragmenter,
    inst: &TransportInstruction,
    epoch: Instant,
    saved_remote_ts: Option<(u16, Instant)>,
) -> Result<(), ProtoError> {
    let frags = fragmenter.make_fragments(inst, MOSH_MAX_FRAGMENT_PAYLOAD)?;
    let ts_reply = compute_timestamp_reply(saved_remote_ts);
    for frag in frags {
        let ts_now = timestamp16(epoch);
        let frag_bytes = frag.encode();
        let mut plaintext = Vec::with_capacity(MOSH_PACKET_HEADER_BYTES + frag_bytes.len());
        plaintext.extend_from_slice(&ts_now.to_be_bytes());
        plaintext.extend_from_slice(&ts_reply.to_be_bytes());
        plaintext.extend_from_slice(&frag_bytes);
        let (_seq, datagram) = crypto
            .seal(MoshDirection::ToServer, &plaintext)
            .map_err(|e| ProtoError::Transport(format!("Mosh OCB3 seal error: {e}")))?;
        let _ = socket.send(&datagram).await;
    }
    Ok(())
}

/// Resolves the target IP address for Mosh UDP traffic:
/// 1. Direct SSH TCP peer IP (accurate across NAT/cloud VMs and dual-stack DNS),
/// 2. Hostname/IP lookup of `fallback_host`,
/// 3. `$SSH_CONNECTION` server IP as a last resort.
async fn resolve_mosh_target_ip(
    ssh: &SshConnection,
    fallback_host: &str,
    ssh_reported_ip: Option<IpAddr>,
    udp_port: u16,
) -> Result<SocketAddr, ProtoError> {
    if let Some(peer_ip) = ssh.direct_peer_ip() {
        return Ok(SocketAddr::new(peer_ip, udp_port));
    }
    if let Ok(ip) = fallback_host.trim().parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, udp_port));
    }
    if let Ok(mut addrs) = lookup_host((fallback_host.trim(), udp_port)).await {
        if let Some(first) = addrs.next() {
            return Ok(first);
        }
    }
    if let Some(reported) = ssh_reported_ip {
        return Ok(SocketAddr::new(reported, udp_port));
    }
    Err(ProtoError::Transport(format!(
        "Could not resolve target IP address for Mosh server on '{fallback_host}'."
    )))
}

/// Bootstraps `mosh-server` over an authenticated SSH connection and establishes
/// the encrypted Mosh v2 UDP state-synchronization session.
pub async fn start_mosh_session(
    ssh: &SshConnection,
    fallback_host: &str,
    port_spec: Option<MoshPortSpec>,
    initial_cols: u16,
    initial_rows: u16,
    initial_udp_timeout: Duration,
) -> Result<(MoshSessionHandle, mpsc::UnboundedReceiver<MoshSessionEvent>), ProtoError> {
    let bootstrap_cmd = build_mosh_bootstrap_command(port_spec);
    let exec_out = ssh
        .exec_command_bounded(&bootstrap_cmd, Duration::from_secs(15), 32 * 1024)
        .await?;
    let mut combined = Zeroizing::new(String::new());
    combined.push_str(&String::from_utf8_lossy(&exec_out.stdout));
    if !exec_out.stderr.is_empty() {
        if !combined.ends_with('\n') {
            combined.push('\n');
        }
        combined.push_str(&String::from_utf8_lossy(&exec_out.stderr));
    }

    let handshake = parse_mosh_connect_output(&combined)?;
    let server_addr =
        resolve_mosh_target_ip(ssh, fallback_host, handshake.ssh_reported_ip, handshake.udp_port)
            .await?;

    connect_mosh_udp_session(
        server_addr,
        &handshake.key,
        initial_cols,
        initial_rows,
        initial_udp_timeout,
    )
    .await
}

/// Connects to an already-started `mosh-server` UDP endpoint, verifying initial
/// bidirectional OCB3 reachability within `initial_udp_timeout` before spawning
/// the roaming transport loop.
pub async fn connect_mosh_udp_session(
    server_addr: SocketAddr,
    key: &MoshBase64Key,
    initial_cols: u16,
    initial_rows: u16,
    initial_udp_timeout: Duration,
) -> Result<(MoshSessionHandle, mpsc::UnboundedReceiver<MoshSessionEvent>), ProtoError> {
    let mut socket = bind_connected_udp_socket(server_addr).await?;
    let mut crypto = MoshCryptoSession::new(key);
    let mut fragmenter = Fragmenter::new();
    let mut assembly = FragmentAssembly::new();
    let mut engine = MoshStateEngine::new();
    let epoch = Instant::now();
    let mut saved_remote_ts: Option<(u16, Instant)> = None;

    let cols = initial_cols.max(1);
    let rows = initial_rows.max(1);
    // mosh-server without a pty starts at 80x24; always send initial resize so PTY matches UI.
    engine.push_resize(cols, rows);

    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<MoshCommand>();
    let (evt_tx, evt_rx) = mpsc::unbounded_channel::<MoshSessionEvent>();

    // Bounded initial UDP association check so blocked UDP ports fail fast with an actionable error.
    let assoc_deadline = Instant::now() + initial_udp_timeout.max(Duration::from_millis(500));
    let mut recv_buf = [0u8; MOSH_MAX_DATAGRAM_BYTES];
    let mut associated = false;
    let mut pending_ack_at: Option<Instant> = None;

    while Instant::now() < assoc_deadline && !associated {
        let initial_inst = engine.build_outgoing_instruction(4);
        transmit_instruction(
            &socket,
            &mut crypto,
            &mut fragmenter,
            &initial_inst,
            epoch,
            saved_remote_ts,
        )
        .await?;

        let wait_slice = assoc_deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(250));
        match tokio::time::timeout(wait_slice, socket.recv(&mut recv_buf)).await {
            Ok(Ok(n)) => {
                if let Ok((_seq, pt)) = crypto.open(MoshDirection::ToClient, &recv_buf[..n]) {
                    if pt.len() >= MOSH_PACKET_HEADER_BYTES + MOSH_FRAGMENT_HEADER_BYTES {
                        associated = true;
                        let r_ts = u16::from_be_bytes([pt[0], pt[1]]);
                        saved_remote_ts = Some((r_ts, Instant::now()));
                        if let Ok(frag) = MoshFragment::decode(&pt[MOSH_PACKET_HEADER_BYTES..]) {
                            if let Ok(Some(inst)) = assembly.add_fragment(frag) {
                                let (transitions, had_diff) = engine.apply_incoming(&inst)?;
                                if had_diff {
                                    pending_ack_at = Some(Instant::now() + MOSH_ACK_DELAY);
                                }
                                for tr in transitions {
                                    match tr {
                                        MoshStateTransition::AdvanceAnchor(ops) => {
                                            let _ = evt_tx.send(MoshSessionEvent::AdvanceAnchor(ops));
                                        }
                                        MoshStateTransition::Incremental(ops) => {
                                            let _ = evt_tx.send(MoshSessionEvent::Incremental(ops));
                                        }
                                        MoshStateTransition::RebranchFromAnchor(ops) => {
                                            let _ = evt_tx.send(MoshSessionEvent::RebranchFromAnchor(ops));
                                        }
                                        MoshStateTransition::ServerClosed => {
                                            let _ = evt_tx.send(MoshSessionEvent::Closed);
                                            return Ok((
                                                MoshSessionHandle {
                                                    cmd_tx,
                                                    server_addr,
                                                },
                                                evt_rx,
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Ok(Err(_)) | Err(_) => {}
        }
    }

    if !associated {
        return Err(ProtoError::Transport(format!(
            "mosh-server started on {server_addr}, but no authenticated UDP response arrived within {:.1}s. Ensure UDP port {} (default range {MOSH_DEFAULT_PORT_RANGE}) is allowed by server and network firewalls, or open a standard SSH terminal.",
            initial_udp_timeout.as_secs_f32(),
            server_addr.port()
        )));
    }

    // Spawn the steady-state roaming Mosh UDP transport loop.
    tokio::spawn(async move {
        let mut last_sent = Instant::now();
        let mut last_heard = Instant::now();
        let mut last_port_hop = Instant::now();
        let mut retransmit_backoff = MOSH_RETRANSMIT_MIN;
        let mut buf = [0u8; MOSH_MAX_DATAGRAM_BYTES];

        loop {
            let now = Instant::now();
            let next_send = if engine.has_unsent_user_ops() {
                (last_sent + MOSH_SEND_MINDELAY).max(now)
            } else if engine.has_unacked_user_ops() {
                last_sent + retransmit_backoff
            } else if let Some(ack_deadline) = pending_ack_at {
                ack_deadline
            } else {
                last_sent + MOSH_ACK_INTERVAL
            };

            let sleep_dur = next_send.saturating_duration_since(now);

            tokio::select! {
                biased;

                maybe_cmd = cmd_rx.recv() => {
                    match maybe_cmd {
                        Some(MoshCommand::Input(bytes)) => {
                            engine.push_keystrokes(&bytes);
                        }
                        Some(MoshCommand::Resize { cols, rows }) => {
                            engine.push_resize(cols, rows);
                        }
                        Some(MoshCommand::Close) | None => {
                            let bye = engine.build_shutdown_instruction();
                            for _ in 0..2 {
                                let _ = transmit_instruction(
                                    &socket,
                                    &mut crypto,
                                    &mut fragmenter,
                                    &bye,
                                    epoch,
                                    saved_remote_ts,
                                ).await;
                            }
                            let _ = evt_tx.send(MoshSessionEvent::Closed);
                            break;
                        }
                    }
                }

                recv_res = socket.recv(&mut buf) => {
                    match recv_res {
                        Ok(n) => {
                            if let Ok((_seq, pt)) = crypto.open(MoshDirection::ToClient, &buf[..n]) {
                                if pt.len() >= MOSH_PACKET_HEADER_BYTES + MOSH_FRAGMENT_HEADER_BYTES {
                                    last_heard = Instant::now();
                                    retransmit_backoff = MOSH_RETRANSMIT_MIN;
                                    let r_ts = u16::from_be_bytes([pt[0], pt[1]]);
                                    saved_remote_ts = Some((r_ts, last_heard));
                                    if let Ok(frag) = MoshFragment::decode(&pt[MOSH_PACKET_HEADER_BYTES..]) {
                                        if let Ok(Some(inst)) = assembly.add_fragment(frag) {
                                            if let Ok((transitions, had_diff)) = engine.apply_incoming(&inst) {
                                                if had_diff && pending_ack_at.is_none() {
                                                    pending_ack_at = Some(last_heard + MOSH_ACK_DELAY);
                                                }
                                                for tr in transitions {
                                                    let evt = match tr {
                                                        MoshStateTransition::AdvanceAnchor(ops) => MoshSessionEvent::AdvanceAnchor(ops),
                                                        MoshStateTransition::Incremental(ops) => MoshSessionEvent::Incremental(ops),
                                                        MoshStateTransition::RebranchFromAnchor(ops) => MoshSessionEvent::RebranchFromAnchor(ops),
                                                        MoshStateTransition::ServerClosed => {
                                                            let _ = evt_tx.send(MoshSessionEvent::Closed);
                                                            return;
                                                        }
                                                    };
                                                    if evt_tx.send(evt).is_err() {
                                                        return;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(_) => {
                            // On mobile app-switches or Wi-Fi <-> cellular handoffs, a
                            // connected UDP socket can surface immediate OS errors
                            // (EPERM/ENETUNREACH/ECONNREFUSED/ENETDOWN). Rebind at most
                            // once per second and yield briefly so the loop never spins.
                            let now_err = Instant::now();
                            if now_err.duration_since(last_port_hop) >= Duration::from_secs(1) {
                                if let Ok(new_sock) = bind_connected_udp_socket(server_addr).await {
                                    socket = new_sock;
                                }
                                last_port_hop = now_err;
                            }
                            tokio::time::sleep(Duration::from_millis(100).min(sleep_dur)).await;
                        }
                    }
                }

                () = tokio::time::sleep(sleep_dur) => {
                    let now_tick = Instant::now();
                    // Roaming port-hop when the server has been silent for >= 10s.
                    if now_tick.duration_since(last_heard) >= MOSH_PORT_HOP_INTERVAL
                        && now_tick.duration_since(last_port_hop) >= MOSH_PORT_HOP_INTERVAL
                    {
                        if let Ok(new_sock) = bind_connected_udp_socket(server_addr).await {
                            socket = new_sock;
                        }
                        last_port_hop = now_tick;
                    }

                    let was_retransmit = !engine.has_unsent_user_ops() && engine.has_unacked_user_ops();
                    let inst = engine.build_outgoing_instruction(4);
                    if transmit_instruction(
                        &socket,
                        &mut crypto,
                        &mut fragmenter,
                        &inst,
                        epoch,
                        saved_remote_ts,
                    ).await.is_err() {
                        let _ = evt_tx.send(MoshSessionEvent::Closed);
                        break;
                    }
                    last_sent = Instant::now();
                    pending_ack_at = None;
                    if was_retransmit {
                        retransmit_backoff = (retransmit_backoff * 2).min(MOSH_RETRANSMIT_MAX);
                    } else {
                        retransmit_backoff = MOSH_RETRANSMIT_MIN;
                    }
                }
            }
        }
    });

    Ok((
        MoshSessionHandle {
            cmd_tx,
            server_addr,
        },
        evt_rx,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_spec_validates_single_range_and_invalid_inputs() {
        assert_eq!(MoshPortSpec::parse_optional("  ").unwrap(), None);
        assert_eq!(
            MoshPortSpec::parse_optional("60005").unwrap(),
            Some(MoshPortSpec::Single(60005))
        );
        assert_eq!(
            MoshPortSpec::parse_optional("60000:60010").unwrap(),
            Some(MoshPortSpec::Range {
                low: 60000,
                high: 60010
            })
        );
        assert!(MoshPortSpec::parse_optional("0").is_err());
        assert!(MoshPortSpec::parse_optional("70000").is_err());
        assert!(MoshPortSpec::parse_optional("60010:60000").is_err());
        assert!(MoshPortSpec::parse_optional("60000:60010:60020").is_err());
        assert!(MoshPortSpec::parse_optional("60000;id").is_err());
    }

    #[test]
    fn parse_mosh_connect_extracts_port_key_and_ssh_ip() {
        let key = MoshBase64Key::from_array([0x24; 16]);
        let key_str = key.printable();
        let output = format!(
            "LINSCP_MOSH_IP 192.0.2.44\n\nMOSH CONNECT 60001 {}\nmosh-server (mosh 1.4.0)\n",
            &*key_str
        );
        let parsed = parse_mosh_connect_output(&output).unwrap();
        assert_eq!(parsed.udp_port, 60001);
        assert_eq!(parsed.key.as_bytes(), key.as_bytes());
        assert_eq!(
            parsed.ssh_reported_ip,
            Some("192.0.2.44".parse::<IpAddr>().unwrap())
        );

        assert!(parse_mosh_connect_output("locale: Cannot set LC_CTYPE\n").is_err());
        assert!(parse_mosh_connect_output("MOSH CONNECT 0 AAAAAAAAAAAAAAAAAAAAAA\n").is_err());
    }

    #[test]
    fn protobuf_user_host_and_transport_round_trip() {
        let user_ops = vec![
            UserOp::Resize {
                width: 120,
                height: 40,
            },
            UserOp::Keystroke(b"ls -la\r".to_vec()),
        ];
        let user_bytes = encode_user_diff(&user_ops);
        assert_eq!(decode_user_diff(&user_bytes).unwrap(), user_ops);

        let host_ops = vec![
            HostOp::HostBytes(b"\x1b[32mhello\x1b[0m\r\n".to_vec()),
            HostOp::Resize {
                width: 120,
                height: 40,
            },
            HostOp::EchoAck(7),
        ];
        let host_bytes = encode_host_diff(&host_ops);
        assert_eq!(decode_host_diff(&host_bytes).unwrap(), host_ops);

        let inst = TransportInstruction {
            protocol_version: MOSH_PROTOCOL_VERSION,
            old_num: 3,
            new_num: 4,
            ack_num: 2,
            throwaway_num: 2,
            diff: host_bytes,
            chaff: vec![1, 2, 3],
        };
        let encoded = inst.encode();
        assert_eq!(TransportInstruction::decode(&encoded).unwrap(), inst);
    }

    #[test]
    fn fragmenter_and_reassembler_handle_out_of_order_and_duplicates() {
        let large_payload = vec![b'X'; 8192];
        let inst = TransportInstruction {
            protocol_version: MOSH_PROTOCOL_VERSION,
            old_num: 0,
            new_num: 1,
            ack_num: 0,
            throwaway_num: 0,
            diff: encode_host_diff(&[HostOp::HostBytes(large_payload)]),
            chaff: vec![9; 8],
        };
        let mut fragmenter = Fragmenter::new();
        // Force small MTU to produce multiple fragments even after zlib compression.
        let mut custom = inst.clone();
        custom.chaff = (0..200).map(|i| (i * 37 % 251) as u8).collect();
        let frags = fragmenter.make_fragments(&custom, 80).unwrap();
        assert!(frags.len() >= 2);

        let mut assembly = FragmentAssembly::new();
        // Feed final fragment first, duplicate it, then feed remaining fragments in reverse.
        for frag in frags.iter().rev() {
            let wire = frag.encode();
            let decoded_frag = MoshFragment::decode(&wire).unwrap();
            let res = assembly.add_fragment(decoded_frag.clone()).unwrap();
            if frag.fragment_num == 0 {
                assert_eq!(res.unwrap(), custom);
            } else {
                assert!(res.is_none());
                assert!(assembly.add_fragment(decoded_frag).unwrap().is_none());
            }
        }
    }

    #[test]
    fn ssp_state_engine_tracks_incremental_rebranch_throwaway_and_shutdown() {
        let mut engine = MoshStateEngine::new();
        engine.push_keystrokes(b"pwd\r");
        let out1 = engine.build_outgoing_instruction(0);
        assert_eq!(out1.old_num, 0);
        assert_eq!(out1.new_num, 1);

        // Server sends 0 -> 1 and ACKs user state 1.
        let s1 = TransportInstruction {
            protocol_version: MOSH_PROTOCOL_VERSION,
            old_num: 0,
            new_num: 1,
            ack_num: 1,
            throwaway_num: 0,
            diff: encode_host_diff(&[HostOp::HostBytes(b"/home/user\r\n".to_vec())]),
            chaff: Vec::new(),
        };
        let (tr1, ack1) = engine.apply_incoming(&s1).unwrap();
        assert!(ack1);
        assert!(!engine.has_unacked_user_ops());
        assert_eq!(
            tr1,
            vec![MoshStateTransition::Incremental(vec![HostOp::HostBytes(
                b"/home/user\r\n".to_vec()
            )])]
        );

        // Server sends 1 -> 2, client displays 2, but client's ACK for 2 is lost,
        // so server later branches 1 -> 3 directly from 1 and retires 0..=1!
        let s2 = TransportInstruction {
            protocol_version: MOSH_PROTOCOL_VERSION,
            old_num: 1,
            new_num: 2,
            ack_num: 1,
            throwaway_num: 0,
            diff: encode_host_diff(&[HostOp::HostBytes(b"draft".to_vec())]),
            chaff: Vec::new(),
        };
        let (tr2, _) = engine.apply_incoming(&s2).unwrap();
        assert_eq!(
            tr2,
            vec![MoshStateTransition::Incremental(vec![HostOp::HostBytes(
                b"draft".to_vec()
            )])]
        );

        let s3 = TransportInstruction {
            protocol_version: MOSH_PROTOCOL_VERSION,
            old_num: 1,
            new_num: 3,
            ack_num: 1,
            throwaway_num: 1,
            diff: encode_host_diff(&[HostOp::HostBytes(b"final".to_vec())]),
            chaff: Vec::new(),
        };
        let (tr3, _) = engine.apply_incoming(&s3).unwrap();
        assert_eq!(
            tr3,
            vec![
                MoshStateTransition::AdvanceAnchor(vec![HostOp::HostBytes(
                    b"/home/user\r\n".to_vec()
                )]),
                MoshStateTransition::RebranchFromAnchor(vec![HostOp::HostBytes(
                    b"final".to_vec()
                )]),
            ]
        );

        // Clean server shutdown (new_num == u64::MAX).
        let bye = TransportInstruction {
            protocol_version: MOSH_PROTOCOL_VERSION,
            old_num: 3,
            new_num: u64::MAX,
            ack_num: 1,
            throwaway_num: 3,
            diff: Vec::new(),
            chaff: Vec::new(),
        };
        let (tr_bye, _) = engine.apply_incoming(&bye).unwrap();
        assert_eq!(tr_bye, vec![MoshStateTransition::ServerClosed]);
    }

    #[tokio::test]
    async fn live_udp_loopback_handshake_keystrokes_and_clean_close() {
        let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let key = MoshBase64Key::generate();
        let key_for_srv = key.clone();

        let srv_task = tokio::spawn(async move {
            let mut srv_crypto = MoshCryptoSession::new(&key_for_srv);
            let mut srv_frag = Fragmenter::new();
            let mut srv_asm = FragmentAssembly::new();
            let epoch = Instant::now();
            let mut buf = [0u8; MOSH_MAX_DATAGRAM_BYTES];

            // 1. Receive initial association + resize from client, reply with welcome prompt.
            let (n, client_addr) = server_sock.recv_from(&mut buf).await.unwrap();
            let (_seq, pt) = srv_crypto.open(MoshDirection::ToServer, &buf[..n]).unwrap();
            let frag = MoshFragment::decode(&pt[4..]).unwrap();
            let inst = srv_asm.add_fragment(frag).unwrap().unwrap();
            assert_eq!(
                decode_user_diff(&inst.diff).unwrap(),
                vec![UserOp::Resize {
                    width: 100,
                    height: 30
                }]
            );

            let welcome = TransportInstruction {
                protocol_version: MOSH_PROTOCOL_VERSION,
                old_num: 0,
                new_num: 1,
                ack_num: inst.new_num,
                throwaway_num: 0,
                diff: encode_host_diff(&[HostOp::HostBytes(b"mosh$ ".to_vec())]),
                chaff: Vec::new(),
            };
            let reply_frag = srv_frag.make_fragments(&welcome, 1100).unwrap().remove(0);
            let mut reply_pt = vec![0, 1, 0xff, 0xff];
            reply_pt.extend_from_slice(&reply_frag.encode());
            let (_s, wire) = srv_crypto.seal(MoshDirection::ToClient, &reply_pt).unwrap();
            server_sock.send_to(&wire, client_addr).await.unwrap();

            // 2. Receive keystroke from client, echo response, then observe u64::MAX close.
            let mut saw_keystroke = false;
            loop {
                let (n2, caddr2) = server_sock.recv_from(&mut buf).await.unwrap();
                let (_seq2, pt2) = srv_crypto
                    .open(MoshDirection::ToServer, &buf[..n2])
                    .unwrap();
                let f2 = MoshFragment::decode(&pt2[4..]).unwrap();
                if let Some(i2) = srv_asm.add_fragment(f2).unwrap() {
                    if i2.new_num == u64::MAX {
                        break;
                    }
                    if !i2.diff.is_empty() && !saw_keystroke {
                        saw_keystroke = true;
                        let uops = decode_user_diff(&i2.diff).unwrap();
                        assert_eq!(uops, vec![UserOp::Keystroke(b"echo ok\r".to_vec())]);
                        let echo = TransportInstruction {
                            protocol_version: MOSH_PROTOCOL_VERSION,
                            old_num: 1,
                            new_num: 2,
                            ack_num: i2.new_num,
                            throwaway_num: 1,
                            diff: encode_host_diff(&[HostOp::HostBytes(b"ok\r\n".to_vec())]),
                            chaff: Vec::new(),
                        };
                        let rf = srv_frag.make_fragments(&echo, 1100).unwrap().remove(0);
                        let mut rpt = Vec::new();
                        rpt.extend_from_slice(&timestamp16(epoch).to_be_bytes());
                        rpt.extend_from_slice(&0xffffu16.to_be_bytes());
                        rpt.extend_from_slice(&rf.encode());
                        let (_s, w) = srv_crypto.seal(MoshDirection::ToClient, &rpt).unwrap();
                        server_sock.send_to(&w, caddr2).await.unwrap();
                    }
                }
            }
            assert!(saw_keystroke);
        });

        let (handle, mut events) =
            connect_mosh_udp_session(server_addr, &key, 100, 30, Duration::from_secs(2))
                .await
                .unwrap();

        match events.recv().await.unwrap() {
            MoshSessionEvent::Incremental(ops) => {
                assert_eq!(ops, vec![HostOp::HostBytes(b"mosh$ ".to_vec())]);
            }
            other => panic!("unexpected initial event: {other:?}"),
        }

        handle.write_bytes(b"echo ok\r".to_vec()).unwrap();
        let mut saw_ok = false;
        while !saw_ok {
            match events.recv().await.unwrap() {
                MoshSessionEvent::AdvanceAnchor(_) => {}
                MoshSessionEvent::Incremental(ops) => {
                    assert_eq!(ops, vec![HostOp::HostBytes(b"ok\r\n".to_vec())]);
                    saw_ok = true;
                }
                other => panic!("unexpected event: {other:?}"),
            }
        }
        handle.close();
        srv_task.await.unwrap();
    }

    #[test]
    fn installer_script_uses_only_system_repositories_and_verifies_binary() {
        let script = mosh_install_script();
        assert!(script.contains("apt-get install -y mosh"));
        assert!(script.contains("dnf install -y mosh"));
        assert!(script.contains("pacman -S --needed --noconfirm mosh"));
        assert!(script.contains("zypper --non-interactive install mosh"));
        assert!(script.contains("apk add mosh"));
        assert!(script.contains("command -v mosh-server"));
        assert!(!script.contains("curl "));
        assert!(!script.contains("wget "));
        assert!(!script.contains("add-apt-repository"));
        assert!(!script.contains("epel-release"));
    }

    #[tokio::test]
    async fn mosh_udp_session_survives_transient_closed_socket_and_recovers() {
        let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let key = MoshBase64Key::generate();
        let key_srv = key.clone();

        let srv_task = tokio::spawn(async move {
            let mut srv_crypto = MoshCryptoSession::new(&key_srv);
            let mut srv_asm = FragmentAssembly::new();
            let mut srv_frag = Fragmenter::new();
            let epoch = Instant::now();
            let mut buf = [0u8; MOSH_MAX_DATAGRAM_BYTES];

            let (n, client_addr) = server_sock.recv_from(&mut buf).await.unwrap();
            let (_seq, pt) = srv_crypto
                .open(MoshDirection::ToServer, &buf[..n])
                .unwrap();
            let frag = MoshFragment::decode(&pt[4..]).unwrap();
            let inst = srv_asm.add_fragment(frag).unwrap().unwrap();

            let reply_inst = TransportInstruction {
                protocol_version: MOSH_PROTOCOL_VERSION,
                old_num: 0,
                new_num: 1,
                ack_num: inst.new_num,
                throwaway_num: 0,
                diff: encode_host_diff(&[HostOp::HostBytes(b"ready$ ".to_vec())]),
                chaff: Vec::new(),
            };
            let reply_frag = srv_frag
                .make_fragments(&reply_inst, 1100)
                .unwrap()
                .remove(0);
            let mut reply_pt = vec![0, 1, 0xff, 0xff];
            reply_pt.extend_from_slice(&reply_frag.encode());
            let (_s, wire) = srv_crypto.seal(MoshDirection::ToClient, &reply_pt).unwrap();
            server_sock.send_to(&wire, client_addr).await.unwrap();

            // Drop the server socket briefly so client keystroke retransmits hit ICMP Port Unreachable.
            drop(server_sock);
            tokio::time::sleep(Duration::from_millis(250)).await;

            let rebound = UdpSocket::bind(server_addr).await.unwrap();
            loop {
                let (n2, caddr2) = rebound.recv_from(&mut buf).await.unwrap();
                let (_seq2, pt2) = srv_crypto
                    .open(MoshDirection::ToServer, &buf[..n2])
                    .unwrap();
                let f2 = MoshFragment::decode(&pt2[4..]).unwrap();
                if let Some(i2) = srv_asm.add_fragment(f2).unwrap() {
                    if i2.new_num == u64::MAX {
                        break;
                    }
                    if !i2.diff.is_empty() {
                        let echo = TransportInstruction {
                            protocol_version: MOSH_PROTOCOL_VERSION,
                            old_num: 1,
                            new_num: 2,
                            ack_num: i2.new_num,
                            throwaway_num: 1,
                            diff: encode_host_diff(&[HostOp::HostBytes(b"still-alive\r\n".to_vec())]),
                            chaff: Vec::new(),
                        };
                        let rf = srv_frag.make_fragments(&echo, 1100).unwrap().remove(0);
                        let mut rpt = Vec::new();
                        rpt.extend_from_slice(&timestamp16(epoch).to_be_bytes());
                        rpt.extend_from_slice(&0xffffu16.to_be_bytes());
                        rpt.extend_from_slice(&rf.encode());
                        let (_s, w) = srv_crypto.seal(MoshDirection::ToClient, &rpt).unwrap();
                        rebound.send_to(&w, caddr2).await.unwrap();
                        break;
                    }
                }
            }
        });

        let (handle, mut events) =
            connect_mosh_udp_session(server_addr, &key, 80, 24, Duration::from_secs(2))
                .await
                .unwrap();

        match events.recv().await.unwrap() {
            MoshSessionEvent::Incremental(ops) => {
                assert_eq!(ops, vec![HostOp::HostBytes(b"ready$ ".to_vec())]);
            }
            other => panic!("unexpected initial event: {other:?}"),
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
        handle.write_bytes(b"pwd\r".to_vec()).unwrap();

        let mut recovered = false;
        while !recovered {
            match tokio::time::timeout(Duration::from_secs(3), events.recv())
                .await
                .expect("mosh session timed out instead of recovering")
                .expect("mosh channel unexpectedly closed")
            {
                MoshSessionEvent::AdvanceAnchor(_) => {}
                MoshSessionEvent::Incremental(ops) => {
                    assert_eq!(ops, vec![HostOp::HostBytes(b"still-alive\r\n".to_vec())]);
                    recovered = true;
                }
                other => panic!("unexpected event during recovery: {other:?}"),
            }
        }
        handle.close();
        srv_task.await.unwrap();
    }
}
