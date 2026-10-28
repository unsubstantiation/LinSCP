//! Wildcard matching, extended LinSCP file masks (`include|exclude`, size & date
//! criteria, path/directory tokens), POSIX symbolic/octal permissions, and remote
//! path/listing formatting utilities.

use linscp_platform::terminal::{local_ymdhms_wday, mktime_local_ymdhms};

/// Returns `true` when `path` contains wildcard characters `*` or `?`.
pub fn has_wildcard(path: &str) -> bool {
    path.contains('*') || path.contains('?')
}

/// Iterative wildcard matcher supporting `*` and `?` (case-sensitive).
pub fn matches_wildcard(mask: &str, name: &str) -> bool {
    let m = mask.as_bytes();
    let n = name.as_bytes();
    let mut mi = 0usize;
    let mut ni = 0usize;
    let mut last_star: Option<usize> = None;
    let mut retry_ni = 0usize;

    while ni < n.len() {
        if mi < m.len() && (m[mi] == b'?' || m[mi] == n[ni]) {
            mi += 1;
            ni += 1;
        } else if mi < m.len() && m[mi] == b'*' {
            last_star = Some(mi);
            mi += 1;
            retry_ni = ni;
        } else if let Some(star_pos) = last_star {
            mi = star_pos + 1;
            retry_ni += 1;
            ni = retry_ni;
        } else {
            return false;
        }
    }

    while mi < m.len() && m[mi] == b'*' {
        mi += 1;
    }
    mi == m.len()
}

/// Case-insensitive wildcard matcher used by host and preset rules.
pub fn matches_wildcard_icase(mask: &str, name: &str) -> bool {
    matches_wildcard(&mask.to_ascii_lowercase(), &name.to_ascii_lowercase())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaskOp {
    Eq,
    Lt,
    Gt,
    Le,
    Ge,
}

impl MaskOp {
    fn compare_u64(self, actual: u64, expected: u64) -> bool {
        match self {
            Self::Eq => actual == expected,
            Self::Lt => actual < expected,
            Self::Gt => actual > expected,
            Self::Le => actual <= expected,
            Self::Ge => actual >= expected,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaskCriterion {
    Size { op: MaskOp, bytes: u64 },
    Time { op: MaskOp, epoch_secs: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMaskToken {
    pub text: String,
    pub pattern: String,
    pub directory_only: bool,
    pub is_path: bool,
    pub criteria: Vec<MaskCriterion>,
}

/// Extended include/exclude file mask (`include1;include2 | exclude1;exclude2`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileMask {
    pub include: Vec<FileMaskToken>,
    pub exclude: Vec<FileMaskToken>,
}

impl FileMask {
    pub fn is_empty(&self) -> bool {
        self.include.is_empty() && self.exclude.is_empty()
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let trimmed = text.trim_matches(|c| c == ' ' || c == '"');
        if trimmed.is_empty() {
            return Ok(Self::default());
        }
        let groups: Vec<&str> = trimmed.split('|').collect();
        if groups.len() > 2 {
            return Err(
                "A file mask has at most one '|' (include masks|exclude masks).".to_string(),
            );
        }
        let mut out = Self::default();
        for (idx, group) in groups.iter().enumerate() {
            let target = if idx == 0 {
                &mut out.include
            } else {
                &mut out.exclude
            };
            for raw_item in group.split([';', ',']) {
                let item = raw_item.trim();
                if item.is_empty() {
                    continue;
                }
                target.push(parse_mask_token(item)?);
            }
        }
        Ok(out)
    }

    pub fn accepts(
        &self,
        name: &str,
        is_directory: bool,
        size: u64,
        mtime: u64,
        relative_path: &str,
    ) -> bool {
        let rel = relative_path.trim_matches('/');
        for token in &self.exclude {
            if matches_token(token, name, is_directory, size, mtime, rel, true) {
                return false;
            }
        }
        if self.include.is_empty() {
            return true;
        }
        if is_directory {
            // Directories are traversed unless every include rule is an explicit directory/path rule
            // that cannot possibly match anything inside or equal to this directory.
            let any_file_rule = self
                .include
                .iter()
                .any(|t| !t.directory_only && !t.is_path);
            if any_file_rule {
                return true;
            }
            for token in &self.include {
                if token.directory_only
                    && matches_token(token, name, true, size, mtime, rel, false)
                {
                    return true;
                }
                if token.is_path {
                    // Allow descending into prefix directories of `docs/*.txt`
                    let prefix = token.pattern.split('/').next().unwrap_or("");
                    let top = rel.split('/').next().unwrap_or(name);
                    if matches_wildcard(prefix, top)
                        || matches_directory_path(token, rel, name)
                    {
                        return true;
                    }
                }
            }
            return false;
        }
        self.include
            .iter()
            .any(|t| matches_token(t, name, false, size, mtime, rel, false))
    }

    pub fn accepts_name(&self, name: &str, is_directory: bool) -> bool {
        self.accepts(name, is_directory, 0, 0, name)
    }

    pub fn describe(&self) -> String {
        if self.is_empty() {
            return String::new();
        }
        let inc: Vec<&str> = self.include.iter().map(|t| t.text.as_str()).collect();
        let exc: Vec<&str> = self.exclude.iter().map(|t| t.text.as_str()).collect();
        if exc.is_empty() {
            inc.join(";")
        } else {
            format!("{}|{}", inc.join(";"), exc.join(";"))
        }
    }
}

fn matches_directory_path(token: &FileMaskToken, relative_path: &str, name: &str) -> bool {
    if !token.is_path {
        return matches_wildcard(&token.pattern, name);
    }
    let pat = token.pattern.trim_matches('/');
    let rel = relative_path.trim_matches('/');
    if matches_wildcard(pat, rel) {
        return true;
    }
    let pat_parts: Vec<&str> = pat.split('/').collect();
    let rel_parts: Vec<&str> = if rel.is_empty() {
        vec![name]
    } else {
        rel.split('/').collect()
    };
    if pat_parts.len() <= rel_parts.len() {
        let start = rel_parts.len() - pat_parts.len();
        if pat_parts
            .iter()
            .zip(&rel_parts[start..])
            .all(|(p, r)| matches_wildcard(p, r))
        {
            return true;
        }
    }
    false
}

fn matches_file_path(token: &FileMaskToken, relative_path: &str) -> bool {
    let pat = token.pattern.trim_start_matches('/');
    let rel = relative_path.trim_start_matches('/');
    matches_wildcard(pat, rel)
}

fn matches_criteria(token: &FileMaskToken, size: u64, mtime: u64) -> bool {
    for c in &token.criteria {
        match *c {
            MaskCriterion::Size { op, bytes } => {
                if !op.compare_u64(size, bytes) {
                    return false;
                }
            }
            MaskCriterion::Time { op, epoch_secs } => {
                if mtime == 0 || !op.compare_u64(mtime, epoch_secs) {
                    return false;
                }
            }
        }
    }
    true
}

fn matches_token(
    token: &FileMaskToken,
    name: &str,
    is_directory: bool,
    size: u64,
    mtime: u64,
    relative_path: &str,
    for_exclude: bool,
) -> bool {
    if is_directory {
        if !token.criteria.is_empty() {
            return false;
        }
        if !token.directory_only && !token.is_path {
            return for_exclude && matches_wildcard(&token.pattern, name);
        }
        return matches_directory_path(token, relative_path, name);
    }
    if token.directory_only {
        return false;
    }
    if !token.criteria.is_empty() && !matches_criteria(token, size, mtime) {
        return false;
    }
    if token.is_path {
        return matches_file_path(token, relative_path);
    }
    matches_wildcard(&token.pattern, name)
}

fn parse_criterion_value(value: &str, op: MaskOp) -> Result<MaskCriterion, String> {
    if value.is_empty() {
        return Err("A mask criterion is missing its value.".to_string());
    }
    let bytes = value.as_bytes();
    if bytes.len() >= 10 && bytes[4] == b'-' && bytes[7] == b'-' {
        let digits_ok = (0..10).all(|i| i == 4 || i == 7 || bytes[i].is_ascii_digit());
        if !digits_ok {
            return Err(format!(
                "The date '{value}' in a file mask is not valid (use yyyy-mm-dd or yyyy-mm-ddThh:mm[:ss])."
            ));
        }
        let year: i32 = value[0..4].parse().unwrap_or(0);
        let month: i32 = value[5..7].parse().unwrap_or(0);
        let day: i32 = value[8..10].parse().unwrap_or(0);
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) || year < 1970 {
            return Err(format!("The date '{value}' in a file mask is not valid."));
        }
        let mut hour = 0i32;
        let mut min = 0i32;
        let mut sec = 0i32;
        if bytes.len() > 10 {
            let sep = bytes[10];
            if (sep != b'T' && sep != b' ') || (bytes.len() != 16 && bytes.len() != 19) {
                return Err(format!(
                    "The date '{value}' in a file mask is not valid (use yyyy-mm-dd or yyyy-mm-ddThh:mm[:ss])."
                ));
            }
            if !bytes[11].is_ascii_digit()
                || !bytes[12].is_ascii_digit()
                || bytes[13] != b':'
                || !bytes[14].is_ascii_digit()
                || !bytes[15].is_ascii_digit()
            {
                return Err(format!(
                    "The date '{value}' in a file mask is not valid (use yyyy-mm-dd or yyyy-mm-ddThh:mm[:ss])."
                ));
            }
            hour = value[11..13].parse().unwrap_or(99);
            min = value[14..16].parse().unwrap_or(99);
            if bytes.len() == 19 {
                if bytes[16] != b':'
                    || !bytes[17].is_ascii_digit()
                    || !bytes[18].is_ascii_digit()
                {
                    return Err(format!(
                        "The date '{value}' in a file mask is not valid (use yyyy-mm-dd or yyyy-mm-ddThh:mm[:ss])."
                    ));
                }
                sec = value[17..19].parse().unwrap_or(99);
            }
            if hour > 23 || min > 59 || sec > 59 {
                return Err(format!("The date '{value}' in a file mask is not valid."));
            }
        }
        let epoch = mktime_local_ymdhms(year, month, day, hour, min, sec)
            .filter(|&s| s >= 0)
            .ok_or_else(|| format!("The date '{value}' in a file mask is not valid."))?;
        return Ok(MaskCriterion::Time {
            op,
            epoch_secs: epoch as u64,
        });
    }

    // Relative age suffix (`1D`, `2H`, `30N`, `10S`, `1Y`) when unit is a time-only unit
    let digit_len = bytes.iter().take_while(|b| b.is_ascii_digit()).count();
    if digit_len == 0 {
        return Err(format!(
            "The value '{value}' of a file mask criterion is neither a size (with optional K, M or G) nor a date."
        ));
    }
    let num: u64 = value[..digit_len]
        .parse()
        .map_err(|_| format!("The size '{value}' in a file mask is too large."))?;
    let suffix = &value[digit_len..];
    if suffix.is_empty() {
        return Ok(MaskCriterion::Size { op, bytes: num });
    }
    if suffix.len() == 1 {
        let unit = suffix.as_bytes()[0].to_ascii_uppercase();
        let shift = match unit {
            b'K' => Some(10u32),
            b'M' => Some(20u32),
            b'G' => Some(30u32),
            b'T' => Some(40u32),
            _ => None,
        };
        if let Some(sh) = shift {
            let scaled = num
                .checked_shl(sh)
                .ok_or_else(|| format!("The size '{value}' in a file mask is too large."))?;
            return Ok(MaskCriterion::Size { op, bytes: scaled });
        }
        // Relative age (`>1D` means modified within the last 1 day / after `now - 1D`, matching upstream)
        let secs_per_unit = match unit {
            b'S' => Some(1u64),
            b'N' => Some(60u64),
            b'H' => Some(3_600u64),
            b'D' => Some(86_400u64),
            b'Y' => Some(365 * 86_400u64),
            _ => None,
        };
        if let Some(mult) = secs_per_unit {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let threshold = now.saturating_sub(num.saturating_mul(mult));
            return Ok(MaskCriterion::Time {
                op,
                epoch_secs: threshold,
            });
        }
    }
    Err(format!(
        "The size suffix '{suffix}' in a file mask is not supported (use K, M, G or T)."
    ))
}

fn parse_mask_token(text: &str) -> Result<FileMaskToken, String> {
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() && bytes[i] != b'<' && bytes[i] != b'>' && bytes[i] != b'=' {
        i += 1;
    }
    let mut pattern = text[..i].to_string();
    let mut criteria = Vec::new();

    while i < bytes.len() {
        let op = match bytes[i] {
            b'<' => {
                i += 1;
                if i < bytes.len() && bytes[i] == b'=' {
                    i += 1;
                    MaskOp::Le
                } else {
                    MaskOp::Lt
                }
            }
            b'>' => {
                i += 1;
                if i < bytes.len() && bytes[i] == b'=' {
                    i += 1;
                    MaskOp::Ge
                } else {
                    MaskOp::Gt
                }
            }
            b'=' => {
                i += 1;
                if i < bytes.len() && bytes[i] == b'=' {
                    return Err(format!(
                        "The operator in the file mask '{text}' is not valid (use <, >, =, <= or >=)."
                    ));
                }
                MaskOp::Eq
            }
            ch => {
                return Err(format!(
                    "Unexpected character '{}' in the file mask '{text}'.",
                    ch as char
                ));
            }
        };
        let v_start = i;
        while i < bytes.len() && bytes[i] != b'<' && bytes[i] != b'>' && bytes[i] != b'=' {
            i += 1;
        }
        criteria.push(parse_criterion_value(&text[v_start..i], op)?);
    }

    let mut directory_only = false;
    if pattern.ends_with('/') {
        directory_only = true;
        pattern.pop();
    }
    let is_path = pattern.contains('/');
    if pattern.is_empty() {
        pattern = "*".to_string();
    }
    Ok(FileMaskToken {
        text: text.to_string(),
        pattern,
        directory_only,
        is_path,
        criteria,
    })
}

/// Parses an octal (`644`, `0755`, `4755`) or POSIX `chmod(1)` symbolic expression (`u+x,go-w`)
/// against `current` mode bits.
pub fn parse_permissions_expr(
    text: &str,
    current: u32,
    is_directory: bool,
) -> Result<u32, String> {
    let wanted = text.trim();
    if wanted.is_empty() {
        return Err("the permission mode is empty".to_string());
    }
    if wanted.len() <= 4 && wanted.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        return u32::from_str_radix(wanted, 8)
            .map_err(|_| format!("invalid octal mode '{text}'"));
    }

    let mut mode = current & 0o7777;
    let bytes = wanted.as_bytes();
    let mut i = 0usize;
    let mut clauses = 0usize;

    while i < bytes.len() {
        while i < bytes.len() && (bytes[i] == b',' || bytes[i].is_ascii_whitespace()) {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        clauses += 1;

        let mut who = 0u32;
        while i < bytes.len() {
            match bytes[i].to_ascii_lowercase() {
                b'u' => who |= 1,
                b'g' => who |= 2,
                b'o' => who |= 4,
                b'a' => who |= 7,
                _ => break,
            }
            i += 1;
        }

        let mut groups = 0usize;
        while i < bytes.len() && matches!(bytes[i], b'+' | b'-' | b'=') {
            let op = bytes[i];
            i += 1;
            if who == 0 {
                if op != b'=' {
                    return Err(format!(
                        "'+' and '-' need u, g, o or a in front of them in '{text}'"
                    ));
                }
                who = 7;
            }
            groups += 1;
            let p_start = i;
            while i < bytes.len()
                && !matches!(bytes[i], b',' | b'+' | b'-' | b'=')
                && !bytes[i].is_ascii_whitespace()
            {
                i += 1;
            }
            let perms = &wanted[p_start..i];
            if perms.is_empty() && op != b'=' {
                return Err(format!("expected a permission letter in '{text}'"));
            }

            let base_snapshot = mode;
            let mut bits = 0u32;
            for ch in perms.chars() {
                match ch {
                    'r' => {
                        if (who & 1) != 0 {
                            bits |= 0o400;
                        }
                        if (who & 2) != 0 {
                            bits |= 0o040;
                        }
                        if (who & 4) != 0 {
                            bits |= 0o004;
                        }
                    }
                    'w' => {
                        if (who & 1) != 0 {
                            bits |= 0o200;
                        }
                        if (who & 2) != 0 {
                            bits |= 0o020;
                        }
                        if (who & 4) != 0 {
                            bits |= 0o002;
                        }
                    }
                    'x' => {
                        if (who & 1) != 0 {
                            bits |= 0o100;
                        }
                        if (who & 2) != 0 {
                            bits |= 0o010;
                        }
                        if (who & 4) != 0 {
                            bits |= 0o001;
                        }
                    }
                    'X' => {
                        if is_directory || (base_snapshot & 0o111) != 0 {
                            if (who & 1) != 0 {
                                bits |= 0o100;
                            }
                            if (who & 2) != 0 {
                                bits |= 0o010;
                            }
                            if (who & 4) != 0 {
                                bits |= 0o001;
                            }
                        }
                    }
                    's' => {
                        if (who & 1) != 0 {
                            bits |= 0o4000;
                        }
                        if (who & 2) != 0 {
                            bits |= 0o2000;
                        }
                    }
                    't' => {
                        if (who & 4) != 0 || who == 7 {
                            bits |= 0o1000;
                        }
                    }
                    'u' | 'g' | 'o' => {
                        let triad = match ch {
                            'u' => (base_snapshot >> 6) & 0o7,
                            'g' => (base_snapshot >> 3) & 0o7,
                            _ => base_snapshot & 0o7,
                        };
                        if (who & 1) != 0 {
                            bits |= triad << 6;
                        }
                        if (who & 2) != 0 {
                            bits |= triad << 3;
                        }
                        if (who & 4) != 0 {
                            bits |= triad;
                        }
                    }
                    _ => {
                        return Err(format!(
                            "unknown permission letter '{ch}' in '{text}'"
                        ));
                    }
                }
            }

            match op {
                b'+' => mode |= bits,
                b'-' => mode &= !bits,
                b'=' => {
                    let mut clear_mask = 0u32;
                    if (who & 1) != 0 {
                        clear_mask |= 0o4700;
                    }
                    if (who & 2) != 0 {
                        clear_mask |= 0o2070;
                    }
                    if (who & 4) != 0 {
                        clear_mask |= 0o1007;
                    }
                    mode = (mode & !clear_mask) | bits;
                }
                _ => {}
            }
        }

        if groups == 0 || (i < bytes.len() && bytes[i] != b',' && !bytes[i].is_ascii_whitespace()) {
            return Err(format!("invalid symbolic permission '{text}'"));
        }
    }

    if clauses == 0 {
        return Err("the permission mode is empty".to_string());
    }
    Ok(mode)
}

/// Parses `FileEntry.permissions` (either `"drwxr-xr-x"` / `"-rw-r--r--"` / `"rwxr-xr-x"`
/// or octal `"0644"` / `"644"`) back into POSIX `u32` mode bits (`0` when unset/unparseable).
pub fn mode_from_permissions_str(perms: &str) -> u32 {
    let t = perms.trim();
    if t.is_empty() {
        return 0;
    }
    if t.len() <= 5 && t.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        return u32::from_str_radix(t, 8).unwrap_or(0) & 0o7777;
    }
    let slice = if t.len() == 10 {
        &t[1..]
    } else if t.len() == 9 {
        t
    } else {
        return 0;
    };
    let b = slice.as_bytes();
    let mut m = 0u32;
    if b[0] == b'r' {
        m |= 0o400;
    }
    if b[1] == b'w' {
        m |= 0o200;
    }
    match b[2] {
        b'x' => m |= 0o100,
        b's' => m |= 0o4100,
        b'S' => m |= 0o4000,
        _ => {}
    }
    if b[3] == b'r' {
        m |= 0o040;
    }
    if b[4] == b'w' {
        m |= 0o020;
    }
    match b[5] {
        b'x' => m |= 0o010,
        b's' => m |= 0o2010,
        b'S' => m |= 0o2000,
        _ => {}
    }
    if b[6] == b'r' {
        m |= 0o004;
    }
    if b[7] == b'w' {
        m |= 0o002;
    }
    match b[8] {
        b'x' => m |= 0o001,
        b't' => m |= 0o1001,
        b'T' => m |= 0o1000,
        _ => {}
    }
    m
}

/// Formats 10-character `ls -l` permissions (`drwxr-xr-x`, `-rw-r--r--`, `lrwxrwxrwx`) or 9-character XML `<permissions value="rwxr-xr-x"/>`.
pub fn format_permissions_10(mode: u32, is_dir: bool, is_symlink: bool) -> String {
    let ftype = if is_symlink || (mode & 0o170000) == 0o120000 {
        'l'
    } else if is_dir || (mode & 0o170000) == 0o040000 {
        'd'
    } else {
        '-'
    };
    let mut s = String::with_capacity(10);
    s.push(ftype);
    s.push_str(&format_permissions_9(mode));
    s
}

pub fn format_permissions_9(mode: u32) -> String {
    let mut s = String::with_capacity(9);
    s.push(if (mode & 0o400) != 0 { 'r' } else { '-' });
    s.push(if (mode & 0o200) != 0 { 'w' } else { '-' });
    s.push(match ((mode & 0o100) != 0, (mode & 0o4000) != 0) {
        (true, true) => 's',
        (false, true) => 'S',
        (true, false) => 'x',
        (false, false) => '-',
    });
    s.push(if (mode & 0o040) != 0 { 'r' } else { '-' });
    s.push(if (mode & 0o020) != 0 { 'w' } else { '-' });
    s.push(match ((mode & 0o010) != 0, (mode & 0o2000) != 0) {
        (true, true) => 's',
        (false, true) => 'S',
        (true, false) => 'x',
        (false, false) => '-',
    });
    s.push(if (mode & 0o004) != 0 { 'r' } else { '-' });
    s.push(if (mode & 0o002) != 0 { 'w' } else { '-' });
    s.push(match ((mode & 0o001) != 0, (mode & 0o1000) != 0) {
        (true, true) => 't',
        (false, true) => 'T',
        (true, false) => 'x',
        (false, false) => '-',
    });
    s
}

/// Joins two remote POSIX-style paths.
pub fn join_remote_path(dir: &str, name: &str) -> String {
    if name.is_empty() {
        return if dir.is_empty() {
            "/".to_string()
        } else {
            dir.to_string()
        };
    }
    if name.starts_with('/') {
        return name.to_string();
    }
    if dir.is_empty() || dir == "/" {
        format!("/{name}")
    } else if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// Resolves `path` against `cwd`, collapsing `.` and `..`.
pub fn resolve_remote_path(cwd: &str, path: &str) -> String {
    let full = if path.starts_with('/') {
        path.to_string()
    } else {
        join_remote_path(if cwd.is_empty() { "/" } else { cwd }, path)
    };
    let mut parts: Vec<&str> = Vec::new();
    for seg in full.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            parts.pop();
        } else {
            parts.push(seg);
        }
    }
    if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parts.join("/"))
    }
}

pub fn remote_parent_and_name(path: &str) -> (String, String) {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return ("/".to_string(), String::new());
    }
    match trimmed.rfind('/') {
        None => (".".to_string(), trimmed.to_string()),
        Some(0) => ("/".to_string(), trimmed[1..].to_string()),
        Some(idx) => (trimmed[..idx].to_string(), trimmed[idx + 1..].to_string()),
    }
}

const MONTHS_SHORT: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

pub fn format_ls_time(epoch_secs: i64) -> String {
    if epoch_secs <= 0 {
        return "Jan  1  1970".to_string();
    }
    let (y, m, d, hh, mm, _, _) = local_ymdhms_wday(epoch_secs);
    let mon = MONTHS_SHORT[((m.saturating_sub(1)) as usize) % 12];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|dur| dur.as_secs() as i64)
        .unwrap_or(0);
    if epoch_secs > now - 180 * 86_400 && epoch_secs < now + 180 * 86_400 {
        format!("{mon} {d:2} {hh:02}:{mm:02}")
    } else {
        format!("{mon} {d:2}  {y}")
    }
}

pub fn format_file_date(epoch_secs: i64) -> String {
    let (y, m, d, _, _, _, _) = local_ymdhms_wday(epoch_secs.max(0));
    let mon = MONTHS_SHORT[((m.saturating_sub(1)) as usize) % 12];
    format!("{mon} {d:2} {y}")
}

pub fn format_file_clock(epoch_secs: i64) -> String {
    let (_, _, _, hh, mm, _, _) = local_ymdhms_wday(epoch_secs.max(0));
    format!("{hh:02}:{mm:02}")
}

pub fn format_sync_time(epoch_secs: i64) -> String {
    if epoch_secs <= 0 {
        return "unknown".to_string();
    }
    let (y, m, d, hh, mm, _, _) = local_ymdhms_wday(epoch_secs);
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extended_filemask_supports_include_exclude_size_and_date() {
        let mask = FileMask::parse("*.txt>=1K;docs/*.md | *.bak;build/").unwrap();
        assert!(mask.accepts("notes.txt", false, 2048, 1_700_000_000, "notes.txt"));
        assert!(!mask.accepts("tiny.txt", false, 512, 1_700_000_000, "tiny.txt"));
        assert!(!mask.accepts("notes.bak", false, 4096, 1_700_000_000, "notes.bak"));
        assert!(!mask.accepts("build", true, 0, 0, "sub/build"));
        assert!(mask.accepts("readme.md", false, 100, 1_700_000_000, "docs/readme.md"));
    }

    #[test]
    fn symbolic_and_octal_permissions_match_chmod_semantics() {
        assert_eq!(parse_permissions_expr("0755", 0o644, false).unwrap(), 0o755);
        assert_eq!(
            parse_permissions_expr("u+x-w,go=r", 0o640, false).unwrap(),
            0o544
        );
        assert_eq!(parse_permissions_expr("u=", 0o4755, false).unwrap(), 0o055);
    }
}
