//! Named transfer presets (`<config_dir>/transfer-presets.ini`) and automatic
//! session/file-mask preset matching (`presets`, `savepreset`, `rmspreset`).

use std::path::{Path, PathBuf};

use linscp_platform::write_private_file_atomic;
use linscp_types::TransferMode;

use crate::filemask::{FileMask, matches_wildcard_icase};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeSupportMode {
    On,
    Smart(u64),
    Off,
}

impl Default for ResumeSupportMode {
    fn default() -> Self {
        Self::Smart(100 * 1024)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresetPermissions {
    Off,
    FromFile,
    Mode(u32),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransferPreset {
    pub name: String,
    pub transfer_mode: Option<TransferMode>,
    pub preserve_time: Option<bool>,
    pub preserve_time_dirs: Option<bool>,
    pub newer_only: Option<bool>,
    pub permissions: Option<PresetPermissions>,
    pub resume_support: Option<ResumeSupportMode>,
    pub speed_kbytes_per_sec: Option<u64>,
    pub host: String,
    pub username: String,
    pub remote_directory: String,
    pub local_directory: String,
    pub mask: String,
}

impl TransferPreset {
    pub fn has_session_rule(&self) -> bool {
        !self.host.is_empty()
            || !self.username.is_empty()
            || !self.remote_directory.is_empty()
            || !self.local_directory.is_empty()
    }

    pub fn has_mask_rule(&self) -> bool {
        !self.mask.is_empty()
    }

    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(m) = self.transfer_mode {
            let label = match m {
                TransferMode::Binary => "binary",
                TransferMode::Ascii => "ascii",
                TransferMode::Automatic => "automatic",
            };
            parts.push(format!("transfer={label}"));
        }
        if let Some(pt) = self.preserve_time {
            if pt && self.preserve_time_dirs == Some(true) {
                parts.push("preservetime=all".to_string());
            } else {
                parts.push(format!("preservetime={}", if pt { "on" } else { "off" }));
            }
        }
        if let Some(no) = self.newer_only {
            parts.push(format!("neweronly={}", if no { "on" } else { "off" }));
        }
        if let Some(sp) = self.speed_kbytes_per_sec {
            parts.push(format!("speed={sp}"));
        }
        if let Some(rs) = self.resume_support {
            match rs {
                ResumeSupportMode::On => parts.push("resumesupport=on".to_string()),
                ResumeSupportMode::Off => parts.push("resumesupport=off".to_string()),
                ResumeSupportMode::Smart(bytes) => {
                    parts.push(format!("resumesupport={}", bytes / 1024));
                }
            }
        }
        if let Some(perms) = self.permissions {
            match perms {
                PresetPermissions::Off => parts.push("permissions=off".to_string()),
                PresetPermissions::FromFile => parts.push("permissions=fromfile".to_string()),
                PresetPermissions::Mode(m) => parts.push(format!("permissions={m:o}")),
            }
        }
        if self.has_session_rule() {
            parts.push("for".to_string());
            if !self.host.is_empty() {
                parts.push(format!("host={}", self.host));
            }
            if !self.username.is_empty() {
                parts.push(format!("user={}", self.username));
            }
            if !self.remote_directory.is_empty() {
                parts.push(format!("remotedir={}", self.remote_directory));
            }
            if !self.local_directory.is_empty() {
                parts.push(format!("localdir={}", self.local_directory));
            }
        }
        if self.has_mask_rule() {
            parts.push(format!("mask={}", self.mask));
        }
        if parts.is_empty() {
            "(no settings)".to_string()
        } else {
            parts.join(" ")
        }
    }

    pub fn parse_setting(&mut self, raw_key: &str, raw_val: &str) -> Result<(), String> {
        let key = raw_key.trim().to_ascii_lowercase();
        let val = trim_quotes(raw_val.trim());
        match key.as_str() {
            "transfer" | "transfermode" => {
                self.transfer_mode = Some(match val.to_ascii_lowercase().as_str() {
                    "binary" => TransferMode::Binary,
                    "ascii" => TransferMode::Ascii,
                    "automatic" | "auto" => TransferMode::Automatic,
                    _ => {
                        return Err(format!(
                            "The value of '{raw_key}' must be binary, ascii or automatic."
                        ));
                    }
                });
            }
            "preservetime" => match val.to_ascii_lowercase().as_str() {
                "all" => {
                    self.preserve_time = Some(true);
                    self.preserve_time_dirs = Some(true);
                }
                _ => {
                    let b = parse_on_off(val)
                        .ok_or_else(|| "The value of 'preservetime' must be on, off or all.".to_string())?;
                    self.preserve_time = Some(b);
                    self.preserve_time_dirs = Some(false);
                }
            },
            "neweronly" => {
                let b = if val.is_empty() {
                    true
                } else {
                    parse_on_off(val)
                        .ok_or_else(|| "The value of 'neweronly' must be on or off.".to_string())?
                };
                self.newer_only = Some(b);
            }
            "speed" | "speedlimit" => {
                let kb: u64 = val
                    .parse()
                    .map_err(|_| "The value of 'speed' must be a non-negative number of KB/s.".to_string())?;
                self.speed_kbytes_per_sec = Some(kb);
            }
            "resumesupport" => match val.to_ascii_lowercase().as_str() {
                "on" => self.resume_support = Some(ResumeSupportMode::On),
                "off" => self.resume_support = Some(ResumeSupportMode::Off),
                "default" => self.resume_support = Some(ResumeSupportMode::Smart(100 * 1024)),
                _ => {
                    let kb: u64 = val.parse().map_err(|_| {
                        "The value of 'resumesupport' must be on, off or a threshold in KB."
                            .to_string()
                    })?;
                    self.resume_support = Some(ResumeSupportMode::Smart(kb.saturating_mul(1024)));
                }
            },
            "permissions" => match val.to_ascii_lowercase().as_str() {
                "off" => self.permissions = Some(PresetPermissions::Off),
                "fromfile" => self.permissions = Some(PresetPermissions::FromFile),
                _ => {
                    if val.is_empty() || val.len() > 4 || !val.bytes().all(|b| (b'0'..=b'7').contains(&b))
                    {
                        return Err(
                            "The value of 'permissions' must be off, fromfile or an octal mode."
                                .to_string(),
                        );
                    }
                    let mode = u32::from_str_radix(val, 8).unwrap_or(0o644);
                    self.permissions = Some(PresetPermissions::Mode(mode));
                }
            },
            "host" => self.host = val.to_string(),
            "user" | "username" => self.username = val.to_string(),
            "remotedir" | "remotedirectory" => self.remote_directory = val.to_string(),
            "localdir" | "localdirectory" => self.local_directory = val.to_string(),
            "mask" | "filemask" => {
                if !val.is_empty() {
                    FileMask::parse(val)?;
                }
                self.mask = val.to_string();
            }
            _ => {
                return Err(format!("Unknown preset setting '{raw_key}'."));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct TransferPresetStore {
    presets: Vec<TransferPreset>,
}

impl TransferPresetStore {
    pub fn default_path(config_dir: &Path) -> PathBuf {
        config_dir.join("transfer-presets.ini")
    }

    pub fn presets_path(config_dir: &Path) -> PathBuf {
        Self::default_path(config_dir)
    }

    pub fn presets(&self) -> &[TransferPreset] {
        &self.presets
    }

    pub fn load_from_dir(config_dir: &Path) -> Result<Self, String> {
        let path = Self::default_path(config_dir);
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(format!("Cannot read '{}': {e}", path.display())),
        };
        Self::parse_ini(&text, &path.display().to_string())
    }

    pub fn parse_ini(text: &str, path_label: &str) -> Result<Self, String> {
        let mut store = Self::default();
        let mut current: Option<TransferPreset> = None;

        for raw_line in text.lines() {
            let trimmed = raw_line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                continue;
            }
            if trimmed.starts_with('[') {
                if let Some(prev) = current.take() {
                    if !prev.name.is_empty() {
                        store.presets.push(prev);
                    }
                }
                let Some(close) = trimmed.find(']') else {
                    return Err(format!(
                        "The preset file '{path_label}' has a section header without a closing ']': {trimmed}"
                    ));
                };
                let name = trimmed[1..close].trim().to_string();
                if name.is_empty() {
                    return Err(format!(
                        "The preset file '{path_label}' has an unnamed section."
                    ));
                }
                current = Some(TransferPreset {
                    name,
                    ..TransferPreset::default()
                });
                continue;
            }
            let Some(ref mut p) = current else {
                return Err(format!(
                    "The preset file '{path_label}' has a setting before any section: {trimmed}"
                ));
            };
            let Some((k, v)) = trimmed.split_once('=') else {
                return Err(format!(
                    "The preset file '{path_label}' has a line that is not 'key = value': {trimmed}"
                ));
            };
            p.parse_setting(k, v)
                .map_err(|e| format!("The preset '{}' in '{path_label}': {e}", p.name))?;
        }
        if let Some(prev) = current {
            if !prev.name.is_empty() {
                store.presets.push(prev);
            }
        }
        Ok(store)
    }

    pub fn serialize_ini(&self) -> String {
        let mut out = String::from(
            "# Named transfer settings and the rules that apply them;\n\
             # see 'help savepreset'. Sections are the preset names.\n",
        );
        for p in &self.presets {
            out.push_str(&format!("\n[{}]\n", p.name));
            if let Some(m) = p.transfer_mode {
                let label = match m {
                    TransferMode::Binary => "binary",
                    TransferMode::Ascii => "ascii",
                    TransferMode::Automatic => "automatic",
                };
                out.push_str(&format!("transfer = {label}\n"));
            }
            if let Some(pt) = p.preserve_time {
                let label = if pt && p.preserve_time_dirs == Some(true) {
                    "all"
                } else if pt {
                    "on"
                } else {
                    "off"
                };
                out.push_str(&format!("preservetime = {label}\n"));
            }
            if let Some(no) = p.newer_only {
                out.push_str(&format!("neweronly = {}\n", if no { "on" } else { "off" }));
            }
            if let Some(sp) = p.speed_kbytes_per_sec {
                out.push_str(&format!("speed = {sp}\n"));
            }
            if let Some(rs) = p.resume_support {
                match rs {
                    ResumeSupportMode::On => out.push_str("resumesupport = on\n"),
                    ResumeSupportMode::Off => out.push_str("resumesupport = off\n"),
                    ResumeSupportMode::Smart(b) => {
                        out.push_str(&format!("resumesupport = {}\n", b / 1024));
                    }
                }
            }
            if let Some(perms) = p.permissions {
                match perms {
                    PresetPermissions::Off => out.push_str("permissions = off\n"),
                    PresetPermissions::FromFile => out.push_str("permissions = fromfile\n"),
                    PresetPermissions::Mode(m) => out.push_str(&format!("permissions = {m:o}\n")),
                }
            }
            if !p.host.is_empty() {
                out.push_str(&format!("host = {}\n", p.host));
            }
            if !p.username.is_empty() {
                out.push_str(&format!("user = {}\n", p.username));
            }
            if !p.remote_directory.is_empty() {
                out.push_str(&format!("remotedir = {}\n", p.remote_directory));
            }
            if !p.local_directory.is_empty() {
                out.push_str(&format!("localdir = {}\n", p.local_directory));
            }
            if !p.mask.is_empty() {
                out.push_str(&format!("mask = {}\n", p.mask));
            }
        }
        out
    }

    pub fn save_to_dir(&self, config_dir: &Path) -> Result<(), String> {
        let path = Self::default_path(config_dir);
        write_private_file_atomic(&path, self.serialize_ini().as_bytes()).map_err(|e| e.to_string())
    }

    pub fn find(&self, name: &str) -> Option<&TransferPreset> {
        self.presets
            .iter()
            .find(|p| p.name == name)
            .or_else(|| self.presets.iter().find(|p| p.name.eq_ignore_ascii_case(name)))
    }

    pub fn add_or_update(&mut self, preset: TransferPreset) -> Result<(), String> {
        if !is_valid_preset_name(&preset.name) {
            return Err(format!("'{}' is not a usable preset name.", preset.name));
        }
        if let Some(existing) = self
            .presets
            .iter_mut()
            .find(|p| p.name.eq_ignore_ascii_case(&preset.name))
        {
            *existing = preset;
        } else {
            self.presets.push(preset);
        }
        Ok(())
    }

    pub fn remove(&mut self, name: &str) -> Result<(), String> {
        if let Some(pos) = self
            .presets
            .iter()
            .position(|p| p.name.eq_ignore_ascii_case(name))
        {
            self.presets.remove(pos);
            Ok(())
        } else {
            Err(format!("There is no transfer preset named '{name}'."))
        }
    }

    pub fn match_session(
        &self,
        host: &str,
        user: &str,
        remote_dir: &str,
        local_dir: &str,
    ) -> Option<&TransferPreset> {
        self.presets.iter().find(|p| {
            p.has_session_rule()
                && host_rule_matches(&p.host, host)
                && field_matches(&p.username, user)
                && field_matches(&p.remote_directory, remote_dir)
                && field_matches(&p.local_directory, local_dir)
        })
    }

    pub fn match_mask(&self, file_name: &str) -> Option<&TransferPreset> {
        self.presets.iter().find(|p| {
            if !p.has_mask_rule() {
                return false;
            }
            FileMask::parse(&p.mask)
                .map(|m| m.accepts_name(file_name, false))
                .unwrap_or(false)
        })
    }
}

fn is_valid_preset_name(name: &str) -> bool {
    let t = name.trim();
    !t.is_empty()
        && !t.eq_ignore_ascii_case("off")
        && !t.eq_ignore_ascii_case("none")
        && !t.contains('[')
        && !t.contains(']')
        && !t.contains('\n')
        && !t.contains('\r')
}

fn trim_quotes(s: &str) -> &str {
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

fn parse_on_off(s: &str) -> Option<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "on" | "1" | "true" | "yes" => Some(true),
        "off" | "0" | "false" | "no" => Some(false),
        _ => None,
    }
}

fn strip_host_and_port(value: &str) -> &str {
    let t = value.trim();
    if let Some(rest) = t.strip_prefix('[') {
        if let Some(close) = rest.find(']') {
            return &rest[..close];
        }
    }
    if let Some(colon) = t.rfind(':') {
        if t.find(':') == Some(colon)
            && colon + 1 < t.len()
            && t[colon + 1..].bytes().all(|b| b.is_ascii_digit())
        {
            return &t[..colon];
        }
    }
    t
}

pub fn host_rule_matches(rule: &str, host: &str) -> bool {
    if rule.is_empty() {
        return true;
    }
    let r = strip_host_and_port(rule).to_ascii_lowercase();
    let h = strip_host_and_port(host).to_ascii_lowercase();
    if r.is_empty() || h.is_empty() {
        return false;
    }
    if r.contains('*') || r.contains('?') {
        return matches_wildcard_icase(&r, &h);
    }
    if let Some(bare) = r.strip_prefix('.') {
        return h == bare || h.ends_with(&r);
    }
    if r == h {
        return true;
    }
    // Short hostname ('dev') matches 'dev.corp.example' on a label boundary
    !r.contains('.') && h.starts_with(&format!("{r}."))
}

fn field_matches(rule: &str, value: &str) -> bool {
    if rule.is_empty() {
        return true;
    }
    if rule.contains('*') || rule.contains('?') {
        return matches_wildcard_icase(rule, value);
    }
    rule.eq_ignore_ascii_case(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preset_ini_roundtrips_and_matches_host_and_mask() {
        let mut p = TransferPreset {
            name: "logs".to_string(),
            ..TransferPreset::default()
        };
        p.parse_setting("transfer", "ascii").unwrap();
        p.parse_setting("preservetime", "all").unwrap();
        p.parse_setting("resumesupport", "64").unwrap();
        p.parse_setting("host", ".example.com").unwrap();
        p.parse_setting("mask", "*.log").unwrap();
        let mut store = TransferPresetStore::default();
        store.add_or_update(p).unwrap();
        let ini = store.serialize_ini();
        let parsed = TransferPresetStore::parse_ini(&ini, "mem").unwrap();
        assert!(parsed.match_session("app.example.com:2222", "alice", "/", "/tmp").is_some());
        assert!(parsed.match_mask("server.log").is_some());
    }
}
