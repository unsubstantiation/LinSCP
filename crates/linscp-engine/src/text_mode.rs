//! ASCII/automatic text transfer mode, EOL newline conversion, and strict
//! `encoding_rs`-backed character-encoding transcoding for `edit`.

use encoding_rs::{Encoding, UTF_8};
use linscp_types::TransferMode;

use crate::filemask::matches_wildcard;
use crate::script_params::{PrefixMatch, resolve_prefixed_name};

/// Default filename masks treated as text when `TransferMode::Automatic` is active.
pub const DEFAULT_ASCII_FILE_MASK: &str = "*.txt;*.htm;*.html;*.php;*.php3;*.cgi;*.c;*.cpp;*.h;\
*.pas;*.bas;*.tex;*.pl;*.js;*.htaccess;*.xhtml;*.css;*.ini;*.inf;*.bat;*.cmd;*.csv;*.log;\
*.md;*.json;*.xml;*.yml;*.yaml;*.py;*.rb;*.sh;*.conf;*.sql;*.srt;*.vtt";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EolStyle {
    Lf,
    Crlf,
    Cr,
}

impl EolStyle {
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "lf" | "unix" => Some(Self::Lf),
            "crlf" | "dos" | "windows" => Some(Self::Crlf),
            "cr" | "mac" => Some(Self::Cr),
            _ => None,
        }
    }

    pub fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Lf => b"\n",
            Self::Crlf => b"\r\n",
            Self::Cr => b"\r",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Lf => "lf",
            Self::Crlf => "crlf",
            Self::Cr => "cr",
        }
    }

    /// Native line ending for the local OS (`\r\n` on Windows, `\n` on POSIX/Android).
    pub fn local_native() -> Self {
        if std::path::MAIN_SEPARATOR == '\\' {
            Self::Crlf
        } else {
            Self::Lf
        }
    }
}

pub fn parse_transfer_mode(text: &str) -> Option<TransferMode> {
    const MODES: &[&str] = &["binary", "ascii", "automatic"];
    match resolve_prefixed_name(MODES, text) {
        PrefixMatch::ExactOrUnique("binary") => Some(TransferMode::Binary),
        PrefixMatch::ExactOrUnique("ascii") => Some(TransferMode::Ascii),
        PrefixMatch::ExactOrUnique("automatic") => Some(TransferMode::Automatic),
        _ => None,
    }
}

pub fn transfer_mode_name(mode: TransferMode) -> &'static str {
    match mode {
        TransferMode::Binary => "binary",
        TransferMode::Ascii => "ascii",
        TransferMode::Automatic => "automatic",
    }
}

pub fn is_ascii_file_name(name: &str) -> bool {
    let leaf = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(name);
    DEFAULT_ASCII_FILE_MASK
        .split(';')
        .filter(|m| !m.is_empty())
        .any(|mask| matches_wildcard(mask, leaf))
}

pub fn wants_ascii_conversion(mode: TransferMode, file_name: &str) -> bool {
    match mode {
        TransferMode::Binary => false,
        TransferMode::Ascii => true,
        TransferMode::Automatic => is_ascii_file_name(file_name),
    }
}

/// Converts any `\r\n`, `\r`, or `\n` sequences in `bytes` into `target`.
pub fn convert_eol_bytes(bytes: &[u8], target: EolStyle) -> Vec<u8> {
    let eol = target.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() + bytes.len() / 16);
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'\r' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                i += 2;
            } else {
                i += 1;
            }
            out.extend_from_slice(eol);
        } else if bytes[i] == b'\n' {
            i += 1;
            out.extend_from_slice(eol);
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

pub fn looks_like_text(bytes: &[u8]) -> bool {
    !bytes.contains(&0)
}

pub fn uses_pure_crlf(bytes: &[u8]) -> bool {
    let mut saw_crlf = false;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'\n' {
            if i == 0 || bytes[i - 1] != b'\r' {
                return false;
            }
            saw_crlf = true;
        }
    }
    saw_crlf
}

pub fn has_utf8_bom(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0xEF, 0xBB, 0xBF])
}

/// Strictly decodes `bytes` from `encoding_label` into UTF-8 `(utf8_string, had_utf8_bom)`.
/// Any invalid byte sequence returns `Err` instead of inserting U+FFFD replacement characters.
pub fn decode_to_utf8_strict(bytes: &[u8], encoding_label: &str) -> Result<(String, bool), String> {
    let label = encoding_label.trim();
    if label.is_empty() || label.eq_ignore_ascii_case("utf-8") || label.eq_ignore_ascii_case("utf8")
    {
        let bom = has_utf8_bom(bytes);
        let slice = if bom { &bytes[3..] } else { bytes };
        let s = std::str::from_utf8(slice)
            .map_err(|e| format!("Invalid byte sequence for encoding 'utf-8': {e}"))?;
        return Ok((s.to_string(), bom));
    }

    let enc = Encoding::for_label(label.as_bytes())
        .ok_or_else(|| format!("Unsupported character encoding '{label}'."))?;
    let (cow, had_errors) = enc.decode_without_bom_handling_and_without_replacement(bytes).map_or_else(
        || (std::borrow::Cow::Borrowed(""), true),
        |c| (c, false),
    );
    if had_errors {
        return Err(format!("Invalid byte sequence for encoding '{label}'."));
    }
    Ok((cow.into_owned(), false))
}

/// Strictly encodes UTF-8 `text` into `encoding_label`, failing if any code point is unrepresentable.
pub fn encode_from_utf8_strict(
    text: &str,
    encoding_label: &str,
    include_utf8_bom: bool,
) -> Result<Vec<u8>, String> {
    let label = encoding_label.trim();
    if label.is_empty() || label.eq_ignore_ascii_case("utf-8") || label.eq_ignore_ascii_case("utf8")
    {
        let mut out = Vec::with_capacity(text.len() + if include_utf8_bom { 3 } else { 0 });
        if include_utf8_bom {
            out.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
        }
        out.extend_from_slice(text.as_bytes());
        return Ok(out);
    }

    let enc = Encoding::for_label(label.as_bytes())
        .ok_or_else(|| format!("Unsupported character encoding '{label}'."))?;
    if enc == UTF_8 {
        return encode_from_utf8_strict(text, "utf-8", include_utf8_bom);
    }
    let (cow, _, had_errors) = enc.encode(text);
    if had_errors {
        return Err(format!(
            "Edited text contains characters that cannot be represented in encoding '{label}'."
        ));
    }
    Ok(cow.into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eol_and_encoding_roundtrip_work_strictly() {
        assert_eq!(convert_eol_bytes(b"a\r\nb\rc\n", EolStyle::Lf), b"a\nb\nc\n");
        assert_eq!(
            convert_eol_bytes(b"a\nb\r\n", EolStyle::Crlf),
            b"a\r\nb\r\n"
        );
        let latin1 = encode_from_utf8_strict("caf\u{00e9}", "iso-8859-1", false).unwrap();
        assert_eq!(latin1, b"caf\xe9");
        let (decoded, bom) = decode_to_utf8_strict(&latin1, "iso-8859-1").unwrap();
        assert_eq!(decoded, "caf\u{00e9}");
        assert!(!bom);
        assert!(encode_from_utf8_strict("\u{1f680}", "iso-8859-1", false).is_err());
    }
}
