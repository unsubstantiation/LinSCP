//! Plain-text diagnostic logger (`-log=`, `-loglevel=`, `-logsize=`) and
//! XSD-valid XML action logger (`-xmllog=`, `-xmlgroups`) conforming to
//! `docs/linscp-session-1.0.xsd`.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use linscp_platform::terminal::utc_ymdhms;
use linscp_types::FileEntry;

use crate::filemask::{format_permissions_9, mode_from_permissions_str};
use crate::script_params::{censored_for_log, mask_url_credentials_inline};

/// Upstream XML session log namespace preserved intentionally for automation consumers.
pub const SESSION_XML_NAMESPACE: &str = "http://winscp.net/schema/session/1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogRotationPolicy {
    pub max_files: u32,
    pub max_bytes: u64,
}

impl LogRotationPolicy {
    /// Parses `[COUNT*]SIZE[K|M|G]` (e.g. `5*10M`, `1024K`, `4096`).
    pub fn parse(spec: &str) -> Result<Self, String> {
        let trimmed = spec.trim();
        if trimmed.is_empty() {
            return Err(
                "The value of '-logsize' is [<count>*]<size>, with a size in bytes and an optional K, M, G or T suffix."
                    .to_string(),
            );
        }
        let (count_part, size_part) = match trimmed.split_once('*') {
            Some((c, s)) => (Some(c.trim()), s.trim()),
            None => (None, trimmed),
        };
        let max_files = match count_part {
            Some(c) => {
                let n: u32 = c.parse().map_err(|_| {
                    "The value of '-logsize' is [<count>*]<size>, with the count from 1 through 100."
                        .to_string()
                })?;
                if !(1..=100).contains(&n) {
                    return Err(
                        "The value of '-logsize' is [<count>*]<size>, with the count from 1 through 100."
                            .to_string(),
                    );
                }
                n
            }
            None => 1,
        };
        if size_part.is_empty() {
            return Err(
                "The value of '-logsize' is [<count>*]<size>, with a size in bytes and an optional K, M, G or T suffix."
                    .to_string(),
            );
        }
        let digits = size_part
            .bytes()
            .take_while(|b| b.is_ascii_digit())
            .count();
        if digits == 0 {
            return Err(
                "The value of '-logsize' is [<count>*]<size>, with a size in bytes and an optional K, M, G or T suffix."
                    .to_string(),
            );
        }
        let base: u64 = size_part[..digits].parse().map_err(|_| {
            "The value of '-logsize' is [<count>*]<size>, with a size in bytes and an optional K, M, G or T suffix."
                .to_string()
        })?;
        let suffix = &size_part[digits..];
        let shift = match suffix.to_ascii_uppercase().as_str() {
            "" | "B" => 0u32,
            "K" | "KB" => 10u32,
            "M" | "MB" => 20u32,
            "G" | "GB" => 30u32,
            "T" | "TB" => 40u32,
            _ => {
                return Err(
                    "The value of '-logsize' is [<count>*]<size>, with a size in bytes and an optional K, M, G or T suffix."
                        .to_string(),
                );
            }
        };
        let max_bytes = base.checked_shl(shift).filter(|&b| b > 0).ok_or_else(|| {
            "The value of '-logsize' is [<count>*]<size>, with a size in bytes and an optional K, M, G or T suffix."
                .to_string()
        })?;
        Ok(Self {
            max_files,
            max_bytes,
        })
    }
}

pub fn format_utc_iso_millis(epoch_secs: i64, millis: u32) -> String {
    let (y, m, d, hh, mm, ss) = utc_ymdhms(epoch_secs.max(0));
    format!(
        "{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{:03}Z",
        millis % 1000
    )
}

fn now_utc_iso() -> String {
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format_utc_iso_millis(dur.as_secs() as i64, dur.subsec_millis())
}

/// Escapes text for an XML 1.0 attribute value, preserving `\n`, `\r`, and `\t`
/// as character references so XML parsers do not collapse whitespace to `' '`.
pub fn xml_escape_attr(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\n' => out.push_str("&#10;"),
            '\r' => out.push_str("&#13;"),
            '\t' => out.push_str("&#9;"),
            c if (c as u32) < 0x20 => {}
            c => out.push(c),
        }
    }
    out
}

/// Escapes text for an XML 1.0 element body (`<message>...</message>`).
pub fn xml_escape_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\n' | '\r' | '\t' => out.push(ch),
            c if (c as u32) < 0x20 => {}
            c => out.push(c),
        }
    }
    out
}

#[derive(Debug, Clone)]
pub struct XmlDiffRecord {
    pub action: String,
    pub is_directory: bool,
    pub filename: String,
    pub size: Option<u64>,
    pub mtime: Option<i64>,
}

/// Combined diagnostic text log and XSD-valid XML session action log.
pub struct SessionLogger {
    text_path: Option<PathBuf>,
    text_level: i32,
    text_log_sensitive: bool,
    rotation: Option<LogRotationPolicy>,

    xml_file: Option<File>,
    xml_session_name: String,
    xml_header_written: bool,
    pending_group_line: Option<String>,
    xml_groups: bool,
    group_open: bool,
    xml_closed: bool,
}

impl Default for SessionLogger {
    fn default() -> Self {
        Self {
            text_path: None,
            text_level: 0,
            text_log_sensitive: false,
            rotation: None,
            xml_file: None,
            xml_session_name: "nosession".to_string(),
            xml_header_written: false,
            pending_group_line: None,
            xml_groups: true,
            group_open: false,
            xml_closed: true,
        }
    }
}

impl SessionLogger {
    pub fn open(
        text_log_path: Option<&Path>,
        text_level: i32,
        text_log_sensitive: bool,
        rotation: Option<LogRotationPolicy>,
        xml_log_path: Option<&Path>,
        xml_groups: bool,
        initial_session_name: &str,
    ) -> Result<Self, String> {
        if let Some(tp) = text_log_path {
            if let Some(parent) = tp.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("Cannot create log directory '{}': {e}", parent.display()))?;
            }
            // Touch/verify writability up front so bad `-log=` fails immediately
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(tp)
                .map_err(|e| format!("Cannot open log file '{}': {e}", tp.display()))?;
        }

        let mut xml_file = None;
        let mut xml_closed = true;
        if let Some(xp) = xml_log_path {
            if let Some(parent) = xp.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent).map_err(|e| {
                    format!("Cannot create XML log directory '{}': {e}", parent.display())
                })?;
            }
            let f = File::create(xp)
                .map_err(|e| format!("Cannot open XML log file '{}': {e}", xp.display()))?;
            let _ = linscp_platform::terminal::set_local_permissions(xp, 0o600);
            xml_file = Some(f);
            xml_closed = false;
        }

        let xml_session_name = if initial_session_name.is_empty() || initial_session_name == "session" {
            "nosession".to_string()
        } else {
            initial_session_name.to_string()
        };

        let logger = Self {
            text_path: text_log_path.map(Path::to_path_buf),
            text_level,
            text_log_sensitive,
            rotation,
            xml_file,
            xml_session_name,
            xml_header_written: false,
            pending_group_line: None,
            xml_groups,
            group_open: false,
            xml_closed,
        };
        logger.log_text(0, "LinSCP session log started.");
        Ok(logger)
    }

    pub fn set_session_name(&mut self, name: &str) {
        if !name.is_empty() && !self.xml_header_written {
            self.xml_session_name = name.to_string();
        }
        if self.pending_group_line.is_some() {
            self.ensure_xml_header();
        }
    }

    fn ensure_xml_header(&mut self) {
        if self.xml_file.is_none() || self.xml_header_written {
            return;
        }
        let safe_name = xml_escape_attr(&mask_url_credentials_inline(&self.xml_session_name));
        let start = now_utc_iso();
        let mut header = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <session xmlns=\"{SESSION_XML_NAMESPACE}\" name=\"{safe_name}\" start=\"{start}\">\n"
        );
        if let Some(pg) = self.pending_group_line.take() {
            header.push_str(&pg);
        }
        self.xml_header_written = true;
        if let Some(ref mut f) = self.xml_file {
            let _ = f.write_all(header.as_bytes());
            let _ = f.flush();
        }
    }

    pub fn log_event(&self, message: &str) {
        self.log_text(0, message);
    }

    pub fn log_text(&self, min_level: i32, message: &str) {
        if self.text_level < min_level {
            return;
        }
        let Some(ref path) = self.text_path else {
            return;
        };
        if let Some(rot) = self.rotation {
            rotate_if_needed(path, rot);
        }
        let line_body = if self.text_log_sensitive {
            message.to_string()
        } else {
            censored_for_log(message)
        };
        let ts = now_utc_iso();
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(f, ". {ts} {line_body}");
            let _ = f.flush();
            let _ = linscp_platform::terminal::set_local_permissions(path, 0o600);
        }
    }

    pub fn begin_command_group(&mut self, raw_command_line: &str) {
        self.log_text(0, &format!("> {}", censored_for_log(raw_command_line)));
        if self.xml_file.is_none() || !self.xml_groups {
            return;
        }
        self.end_command_group();
        let safe_cmd = xml_escape_attr(&censored_for_log(raw_command_line));
        let start = now_utc_iso();
        let line = format!("  <group name=\"{safe_cmd}\" start=\"{start}\">\n");
        self.group_open = true;
        if self.xml_header_written {
            self.write_xml(&line);
        } else {
            self.pending_group_line = Some(line);
        }
    }

    pub fn record_group_failure(&mut self, message: &str) {
        self.log_text(-1, &format!("! {message}"));
        if self.xml_file.is_none() {
            return;
        }
        let indent = self.op_indent();
        let mut buf = format!("{indent}<failure>\n");
        let mut any = false;
        for line in message.lines().map(str::trim).filter(|l| !l.is_empty()) {
            any = true;
            buf.push_str(&format!(
                "{indent}  <message>{}</message>\n",
                xml_escape_text(&mask_url_credentials_inline(line))
            ));
        }
        if !any {
            buf.push_str(&format!("{indent}  <message>Command failed.</message>\n"));
        }
        buf.push_str(&format!("{indent}</failure>\n"));
        self.write_xml(&buf);
    }

    pub fn end_command_group(&mut self) {
        if self.group_open {
            self.write_xml("  </group>\n");
            self.group_open = false;
        }
    }

    fn op_indent(&self) -> &'static str {
        if self.group_open { "    " } else { "  " }
    }

    fn write_xml(&mut self, chunk: &str) {
        if self.xml_file.is_none() {
            return;
        }
        self.ensure_xml_header();
        if let Some(ref mut f) = self.xml_file {
            let _ = f.write_all(chunk.as_bytes());
            let _ = f.flush();
        }
    }

    fn push_param(buf: &mut String, indent: &str, name: &str, value: &str) {
        if value.is_empty() {
            buf.push_str(&format!("{indent}  <{name} />\n"));
        } else {
            buf.push_str(&format!(
                "{indent}  <{name} value=\"{}\" />\n",
                xml_escape_attr(value)
            ));
        }
    }

    fn push_result(buf: &mut String, indent: &str, result: Result<(), &str>) {
        match result {
            Ok(()) => buf.push_str(&format!("{indent}  <result success=\"true\" />\n")),
            Err(err) => {
                buf.push_str(&format!("{indent}  <result success=\"false\">\n"));
                let mut any = false;
                for line in err.lines().map(str::trim).filter(|l| !l.is_empty()) {
                    any = true;
                    buf.push_str(&format!(
                        "{indent}    <message>{}</message>\n",
                        xml_escape_text(&mask_url_credentials_inline(line))
                    ));
                }
                if !any {
                    buf.push_str(&format!("{indent}    <message>Operation failed.</message>\n"));
                }
                buf.push_str(&format!("{indent}  </result>\n"));
            }
        }
    }

    fn push_file_element(buf: &mut String, indent: &str, entry: &FileEntry, include_name: bool) {
        buf.push_str(&format!("{indent}<file>\n"));
        if include_name {
            Self::push_param(buf, indent, "filename", &entry.name);
        }
        let type_ch = if entry.is_symlink {
            "L"
        } else if entry.is_dir {
            "D"
        } else {
            "-"
        };
        Self::push_param(buf, indent, "type", type_ch);
        if !entry.is_dir {
            Self::push_param(buf, indent, "size", &entry.size.to_string());
        }
        if entry.mtime > 0 {
            let mod_iso = format_utc_iso_millis(entry.mtime, 0);
            Self::push_param(buf, indent, "modification", &mod_iso);
        }
        let mode = mode_from_permissions_str(&entry.permissions);
        if mode != 0 {
            let perms = format_permissions_9(mode);
            Self::push_param(buf, indent, "permissions", &perms);
        } else if entry.permissions.len() == 9 {
            Self::push_param(buf, indent, "permissions", &entry.permissions);
        } else if entry.permissions.len() == 10 {
            Self::push_param(buf, indent, "permissions", &entry.permissions[1..]);
        }
        if let Some(owner) = entry.owner.as_deref().filter(|s| !s.is_empty()) {
            Self::push_param(buf, indent, "owner", owner);
        }
        if let Some(group) = entry.group.as_deref().filter(|s| !s.is_empty()) {
            Self::push_param(buf, indent, "group", group);
        }
        buf.push_str(&format!("{indent}</file>\n"));
    }

    pub fn record_transfer(
        &mut self,
        is_upload: bool,
        filename: &str,
        destination: &str,
        size: Option<u64>,
        result: Result<(), &str>,
    ) {
        let tag = if is_upload { "upload" } else { "download" };
        self.log_text(
            0,
            &format!("{tag} '{filename}' -> '{destination}' ({})", if result.is_ok() { "ok" } else { "failed" }),
        );
        if self.xml_file.is_none() {
            return;
        }
        let indent = self.op_indent();
        let mut buf = format!("{indent}<{tag}>\n");
        Self::push_param(&mut buf, indent, "filename", filename);
        Self::push_param(&mut buf, indent, "destination", destination);
        if let Some(sz) = size {
            Self::push_param(&mut buf, indent, "size", &sz.to_string());
        }
        Self::push_result(&mut buf, indent, result);
        buf.push_str(&format!("{indent}</{tag}>\n"));
        self.write_xml(&buf);
    }

    pub fn record_rm(&mut self, filename: &str, recursive: bool, result: Result<(), &str>) {
        if self.xml_file.is_none() {
            return;
        }
        let indent = self.op_indent();
        let attr = if recursive { " recursive=\"true\"" } else { "" };
        let mut buf = format!("{indent}<rm{attr}>\n");
        Self::push_param(&mut buf, indent, "filename", filename);
        Self::push_result(&mut buf, indent, result);
        buf.push_str(&format!("{indent}</rm>\n"));
        self.write_xml(&buf);
    }

    pub fn record_mkdir(&mut self, filename: &str, result: Result<(), &str>) {
        if self.xml_file.is_none() {
            return;
        }
        let indent = self.op_indent();
        let mut buf = format!("{indent}<mkdir>\n");
        Self::push_param(&mut buf, indent, "filename", filename);
        Self::push_result(&mut buf, indent, result);
        buf.push_str(&format!("{indent}</mkdir>\n"));
        self.write_xml(&buf);
    }

    pub fn record_mv_or_cp(
        &mut self,
        is_copy: bool,
        filename: &str,
        destination: &str,
        result: Result<(), &str>,
    ) {
        if self.xml_file.is_none() {
            return;
        }
        let tag = if is_copy { "cp" } else { "mv" };
        let indent = self.op_indent();
        let mut buf = format!("{indent}<{tag}>\n");
        Self::push_param(&mut buf, indent, "filename", filename);
        Self::push_param(&mut buf, indent, "destination", destination);
        Self::push_result(&mut buf, indent, result);
        buf.push_str(&format!("{indent}</{tag}>\n"));
        self.write_xml(&buf);
    }

    pub fn record_chmod(
        &mut self,
        filename: &str,
        mode: u32,
        recursive: bool,
        result: Result<(), &str>,
    ) {
        if self.xml_file.is_none() {
            return;
        }
        let indent = self.op_indent();
        let attr = if recursive { " recursive=\"true\"" } else { "" };
        let mut buf = format!("{indent}<chmod{attr}>\n");
        Self::push_param(&mut buf, indent, "filename", filename);
        Self::push_param(&mut buf, indent, "permissions", &format_permissions_9(mode));
        Self::push_result(&mut buf, indent, result);
        buf.push_str(&format!("{indent}</chmod>\n"));
        self.write_xml(&buf);
    }

    pub fn record_touch(&mut self, filename: &str, mtime: i64, result: Result<(), &str>) {
        if self.xml_file.is_none() {
            return;
        }
        let indent = self.op_indent();
        let mut buf = format!("{indent}<touch>\n");
        Self::push_param(&mut buf, indent, "filename", filename);
        Self::push_param(&mut buf, indent, "modification", &format_utc_iso_millis(mtime, 0));
        Self::push_result(&mut buf, indent, result);
        buf.push_str(&format!("{indent}</touch>\n"));
        self.write_xml(&buf);
    }

    pub fn record_call(
        &mut self,
        command: &str,
        destination: &str,
        output: &str,
        error_output: &str,
        exit_code: i32,
        result: Result<(), &str>,
    ) {
        if self.xml_file.is_none() {
            return;
        }
        let indent = self.op_indent();
        let mut buf = format!("{indent}<call>\n");
        Self::push_param(&mut buf, indent, "command", &censored_for_log(command));
        Self::push_param(&mut buf, indent, "destination", destination);
        if !output.is_empty() {
            Self::push_param(&mut buf, indent, "output", output);
        }
        if !error_output.is_empty() {
            Self::push_param(&mut buf, indent, "erroroutput", error_output);
        }
        Self::push_param(&mut buf, indent, "exitcode", &exit_code.to_string());
        Self::push_result(&mut buf, indent, result);
        buf.push_str(&format!("{indent}</call>\n"));
        self.write_xml(&buf);
    }

    pub fn record_ls(
        &mut self,
        destination: &str,
        entries: Option<&[FileEntry]>,
        result: Result<(), &str>,
    ) {
        if self.xml_file.is_none() {
            return;
        }
        let indent = self.op_indent();
        let mut buf = format!("{indent}<ls>\n");
        Self::push_param(&mut buf, indent, "destination", destination);
        if let Some(list) = entries {
            buf.push_str(&format!("{indent}  <files>\n"));
            let file_indent = format!("{indent}    ");
            for entry in list {
                Self::push_file_element(&mut buf, &file_indent, entry, true);
            }
            buf.push_str(&format!("{indent}  </files>\n"));
        }
        Self::push_result(&mut buf, indent, result);
        buf.push_str(&format!("{indent}</ls>\n"));
        self.write_xml(&buf);
    }

    pub fn record_stat(
        &mut self,
        filename: &str,
        entry: Option<&FileEntry>,
        result: Result<(), &str>,
    ) {
        if self.xml_file.is_none() {
            return;
        }
        let indent = self.op_indent();
        let mut buf = format!("{indent}<stat>\n");
        Self::push_param(&mut buf, indent, "filename", filename);
        if let Some(e) = entry {
            let file_indent = format!("{indent}  ");
            Self::push_file_element(&mut buf, &file_indent, e, false);
        }
        Self::push_result(&mut buf, indent, result);
        buf.push_str(&format!("{indent}</stat>\n"));
        self.write_xml(&buf);
    }

    pub fn record_checksum(
        &mut self,
        filename: &str,
        algorithm: &str,
        hex_digest: Option<&str>,
        result: Result<(), &str>,
    ) {
        if self.xml_file.is_none() {
            return;
        }
        let indent = self.op_indent();
        let mut buf = format!("{indent}<checksum>\n");
        Self::push_param(&mut buf, indent, "filename", filename);
        Self::push_param(&mut buf, indent, "algorithm", algorithm);
        if let Some(hex) = hex_digest {
            Self::push_param(&mut buf, indent, "checksum", hex);
        }
        Self::push_result(&mut buf, indent, result);
        buf.push_str(&format!("{indent}</checksum>\n"));
        self.write_xml(&buf);
    }

    pub fn record_cwd(&mut self, cwd: &str, result: Result<(), &str>) {
        if self.xml_file.is_none() {
            return;
        }
        let indent = self.op_indent();
        let mut buf = format!("{indent}<cwd>\n");
        Self::push_param(&mut buf, indent, "cwd", cwd);
        Self::push_result(&mut buf, indent, result);
        buf.push_str(&format!("{indent}</cwd>\n"));
        self.write_xml(&buf);
    }

    pub fn record_difference(&mut self, diff: &XmlDiffRecord, result: Result<(), &str>) {
        if self.xml_file.is_none() {
            return;
        }
        let indent = self.op_indent();
        let mut buf = format!("{indent}<difference>\n");
        Self::push_param(&mut buf, indent, "action", &diff.action);
        Self::push_param(
            &mut buf,
            indent,
            "type",
            if diff.is_directory { "D" } else { "-" },
        );
        Self::push_param(&mut buf, indent, "filename", &diff.filename);
        if let Some(sz) = diff.size {
            Self::push_param(&mut buf, indent, "size", &sz.to_string());
        }
        if let Some(mt) = diff.mtime.filter(|&m| m > 0) {
            Self::push_param(&mut buf, indent, "modification", &format_utc_iso_millis(mt, 0));
        }
        Self::push_result(&mut buf, indent, result);
        buf.push_str(&format!("{indent}</difference>\n"));
        self.write_xml(&buf);
    }

    pub fn finish(&mut self) {
        if !self.xml_closed {
            self.end_command_group();
            self.write_xml("</session>\n");
            self.xml_closed = true;
        }
    }
}

impl Drop for SessionLogger {
    fn drop(&mut self) {
        self.finish();
    }
}

fn rotate_if_needed(path: &Path, policy: LogRotationPolicy) {
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    if meta.len() < policy.max_bytes {
        return;
    }
    let base = path.display().to_string();
    if policy.max_files == 0 {
        let _ = std::fs::remove_file(path);
        return;
    }
    let oldest = PathBuf::from(format!("{base}.{}", policy.max_files));
    let _ = std::fs::remove_file(&oldest);
    for idx in (1..policy.max_files).rev() {
        let from = PathBuf::from(format!("{base}.{idx}"));
        let to = PathBuf::from(format!("{base}.{}", idx + 1));
        if from.exists() {
            let _ = std::fs::rename(&from, &to);
        }
    }
    let first = PathBuf::from(format!("{base}.1"));
    let _ = std::fs::rename(path, &first);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_log_writes_valid_root_groups_and_escapes_multiline_output() {
        let tmp = std::env::temp_dir().join(format!(
            "linscp_xmllog_test_{}.xml",
            std::process::id()
        ));
        {
            let mut logger = SessionLogger::open(
                None,
                0,
                false,
                None,
                Some(&tmp),
                true,
                "sftp://alice:secret@example.com/",
            )
            .unwrap();
            logger.begin_command_group("call echo hi");
            logger.record_call("echo hi", "/", "line1\nline2", "", 0, Ok(()));
            logger.end_command_group();
        }
        let xml = std::fs::read_to_string(&tmp).unwrap();
        let _ = std::fs::remove_file(&tmp);
        assert!(xml.contains("alice:***@example.com"));
        assert!(xml.contains("line1&#10;line2"));
        assert!(xml.ends_with("</session>\n"));
    }
}
