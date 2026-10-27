//! Hardened remote directory listing parsers shared by FTP (`MLSD`/`MLST` +
//! `LIST`) and native SCP (`ls -la --full-time`), porting `ListingParse.cpp`:
//! - RFC 3659 `MLSD` / `MLST` structured facts
//! - POSIX / GNU `ls -l` (including `--full-time`, symlinks, setuid/setgid/sticky,
//!   and character/block device `major, minor` columns)
//! - Windows / IIS DOS `DIR` listings (`04:00PM` and `04:00 PM`, `<DIR>`)
//! - OpenVMS Multinet / UCX listings (case-insensitive `;version` stripping,
//!   `.DIR` directory detection, and 4-class `(RWED,RWED,RE,RE)` permissions)

use linscp_types::FileEntry;

pub const S_IFMT: u32 = 0o170000;
pub const S_IFIFO: u32 = 0o010000;
pub const S_IFCHR: u32 = 0o020000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFBLK: u32 = 0o060000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFSOCK: u32 = 0o140000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedListingEntry {
    pub name: String,
    pub longname: String,
    pub type_known: bool,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub permissions: u32,
    pub size: u64,
    pub time_known: bool,
    pub mtime: i64,
    pub owner: Option<String>,
    pub group: Option<String>,
}

impl Default for ParsedListingEntry {
    fn default() -> Self {
        Self {
            name: String::new(),
            longname: String::new(),
            type_known: false,
            is_dir: false,
            is_symlink: false,
            permissions: S_IFREG | 0o644,
            size: 0,
            time_known: false,
            mtime: 0,
            owner: None,
            group: None,
        }
    }
}

impl ParsedListingEntry {
    pub fn into_file_entry(self) -> FileEntry {
        FileEntry {
            name: self.name,
            size: if self.is_dir { 0 } else { self.size },
            is_dir: self.is_dir,
            is_symlink: self.is_symlink,
            broken_link: false,
            date: if self.time_known {
                format_utc_timestamp(self.mtime)
            } else {
                String::new()
            },
            mtime: if self.time_known { self.mtime } else { 0 },
            permissions: if self.type_known {
                permissions_string(self.permissions)
            } else {
                String::new()
            },
            owner: self.owner,
            group: self.group,
        }
    }
}

/// Converts civil `(year, month 1..=12, day 1..=31)` in UTC to days since
/// `1970-01-01` (Howard Hinnant's algorithm, pure integer arithmetic).
pub fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || !(1970..=9999).contains(&year) {
        return None;
    }
    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap {
                29
            } else {
                28
            }
        }
        _ => return None,
    };
    if day > max_day {
        return None;
    }
    let y = year as i64 - if month <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let m = month as u64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146097 + doe as i64 - 719468)
}

pub fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year as i32, m as u32, d as u32)
}

pub fn utc_ymdhms_to_unix(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Option<i64> {
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    let clamped_sec = second.min(59) as i64;
    Some(days * 86_400 + (hour as i64) * 3600 + (minute as i64) * 60 + clamped_sec)
}

pub fn format_utc_timestamp(ts: i64) -> String {
    if ts <= 0 {
        return String::new();
    }
    let days = ts.div_euclid(86_400);
    let rem = ts.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}")
}

fn split_long_listing_into(line: &str, limit: usize) -> Option<Vec<&str>> {
    if limit < 2 {
        return None;
    }
    let mut fields = Vec::with_capacity(limit);
    let bytes = line.as_bytes();
    let mut idx = 0usize;
    let len = bytes.len();

    while fields.len() + 1 < limit {
        while idx < len && (bytes[idx] == b' ' || bytes[idx] == b'\t') {
            idx += 1;
        }
        if idx >= len {
            return None;
        }
        let start = idx;
        while idx < len && bytes[idx] != b' ' && bytes[idx] != b'\t' {
            idx += 1;
        }
        fields.push(&line[start..idx]);
    }

    while idx < len && (bytes[idx] == b' ' || bytes[idx] == b'\t') {
        idx += 1;
    }
    let rest = line[idx..].trim_end_matches(['\r', '\n']);
    if rest.is_empty() {
        return None;
    }
    fields.push(rest);
    Some(fields)
}

pub fn split_long_listing(line: &str) -> Option<Vec<String>> {
    split_long_listing_into(line, 9).map(|v| v.into_iter().map(str::to_string).collect())
}

pub fn looks_like_permissions(text: &str) -> bool {
    let b = text.as_bytes();
    if b.len() != 10 {
        return false;
    }
    if !matches!(b[0], b'-' | b'd' | b'l' | b'b' | b'c' | b'p' | b's') {
        return false;
    }
    b[1..]
        .iter()
        .all(|c| matches!(c, b'r' | b'w' | b'x' | b's' | b't' | b'S' | b'T' | b'-'))
}

pub fn permissions_from_string(text: &str) -> u32 {
    let b = text.as_bytes();
    let mut mode = match b.first().copied().unwrap_or(b'-') {
        b'd' => S_IFDIR,
        b'l' => S_IFLNK,
        b'c' => S_IFCHR,
        b'b' => S_IFBLK,
        b'p' => S_IFIFO,
        b's' => S_IFSOCK,
        _ => S_IFREG,
    };
    const BITS: [u32; 9] = [0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001];
    for (i, &bit) in BITS.iter().enumerate() {
        if let Some(&ch) = b.get(i + 1) {
            if matches!(ch, b'r' | b'w' | b'x' | b's' | b'S' | b't' | b'T') {
                mode |= bit;
            }
        }
    }
    if let Some(&ch) = b.get(3) {
        if ch == b's' || ch == b'S' {
            mode |= 0o4000;
            if ch == b'S' {
                mode &= !0o100;
            }
        }
    }
    if let Some(&ch) = b.get(6) {
        if ch == b's' || ch == b'S' {
            mode |= 0o2000;
            if ch == b'S' {
                mode &= !0o010;
            }
        }
    }
    if let Some(&ch) = b.get(9) {
        if ch == b't' || ch == b'T' {
            mode |= 0o1000;
            if ch == b'T' {
                mode &= !0o001;
            }
        }
    }
    mode
}

pub fn permissions_string(mode: u32) -> String {
    let kind = match mode & S_IFMT {
        S_IFDIR => 'd',
        S_IFLNK => 'l',
        S_IFCHR => 'c',
        S_IFBLK => 'b',
        S_IFIFO => 'p',
        S_IFSOCK => 's',
        _ => '-',
    };
    let mut s = String::with_capacity(10);
    s.push(kind);
    s.push(if (mode & 0o400) != 0 { 'r' } else { '-' });
    s.push(if (mode & 0o200) != 0 { 'w' } else { '-' });
    s.push(match (mode & 0o4000 != 0, mode & 0o100 != 0) {
        (true, true) => 's',
        (true, false) => 'S',
        (false, true) => 'x',
        (false, false) => '-',
    });
    s.push(if (mode & 0o040) != 0 { 'r' } else { '-' });
    s.push(if (mode & 0o020) != 0 { 'w' } else { '-' });
    s.push(match (mode & 0o2000 != 0, mode & 0o010 != 0) {
        (true, true) => 's',
        (true, false) => 'S',
        (false, true) => 'x',
        (false, false) => '-',
    });
    s.push(if (mode & 0o004) != 0 { 'r' } else { '-' });
    s.push(if (mode & 0o002) != 0 { 'w' } else { '-' });
    s.push(match (mode & 0o1000 != 0, mode & 0o001 != 0) {
        (true, true) => 't',
        (true, false) => 'T',
        (false, true) => 'x',
        (false, false) => '-',
    });
    s
}

fn month_index_ascii(mon: &str) -> Option<u32> {
    match mon.to_ascii_uppercase().as_str() {
        "JAN" => Some(1),
        "FEB" => Some(2),
        "MAR" => Some(3),
        "APR" => Some(4),
        "MAY" => Some(5),
        "JUN" => Some(6),
        "JUL" => Some(7),
        "AUG" => Some(8),
        "SEP" => Some(9),
        "OCT" => Some(10),
        "NOV" => Some(11),
        "DEC" => Some(12),
        _ => None,
    }
}

fn all_digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}

/// Parses GNU `ls --full-time` date/time/offset columns
/// (`2026-10-16`, `05:33:07.123456789`, `+0000`) into Unix epoch seconds.
pub fn parse_full_time_columns(date_text: &str, time_text: &str, offset_text: &str) -> Option<i64> {
    let mut dparts = date_text.split('-');
    let year: i32 = dparts.next()?.parse().ok()?;
    let month: u32 = dparts.next()?.parse().ok()?;
    let day: u32 = dparts.next()?.parse().ok()?;
    if dparts.next().is_some() {
        return None;
    }

    let hms_part = time_text.split('.').next()?;
    let mut tparts = hms_part.split(':');
    let hour: u32 = tparts.next()?.parse().ok()?;
    let minute: u32 = tparts.next()?.parse().ok()?;
    let second: u32 = tparts.next()?.parse().ok()?;
    if tparts.next().is_some() {
        return None;
    }

    let base = utc_ymdhms_to_unix(year, month, day, hour, minute, second)?;
    let off = offset_text.trim();
    if off == "Z" || off == "z" {
        return Some(base);
    }
    let (sign, digits) = if let Some(rest) = off.strip_prefix('+') {
        (1i64, rest)
    } else if let Some(rest) = off.strip_prefix('-') {
        (-1i64, rest)
    } else {
        return None;
    };
    let clean_digits: String = digits.chars().filter(|c| *c != ':').collect();
    if clean_digits.len() != 4 || !all_digits(&clean_digits) {
        return None;
    }
    let off_h: i64 = clean_digits[0..2].parse().ok()?;
    let off_m: i64 = clean_digits[2..4].parse().ok()?;
    if off_h > 23 || off_m > 59 {
        return None;
    }
    Some(base - sign * (off_h * 3600 + off_m * 60))
}

fn current_utc_year_month() -> (i32, u32) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(1_760_000_000);
    let (year, month, _) = civil_from_days(secs.div_euclid(86_400));
    (year, month)
}

fn parse_traditional_ls_date(mon_str: &str, day_str: &str, year_or_time: &str) -> Option<i64> {
    let month = month_index_ascii(mon_str)?;
    if !all_digits(day_str) {
        return None;
    }
    let day: u32 = day_str.parse().ok()?;

    if let Some((h_s, m_s)) = year_or_time.split_once(':') {
        if !all_digits(h_s) || !all_digits(m_s) {
            return None;
        }
        let hour: u32 = h_s.parse().ok()?;
        let minute: u32 = m_s.parse().ok()?;
        let (cur_year, cur_month) = current_utc_year_month();
        let year = if month > cur_month + 1 {
            cur_year - 1
        } else {
            cur_year
        };
        utc_ymdhms_to_unix(year, month, day, hour, minute, 0)
    } else if all_digits(year_or_time) && year_or_time.len() == 4 {
        let year: i32 = year_or_time.parse().ok()?;
        utc_ymdhms_to_unix(year, month, day, 0, 0, 0)
    } else {
        None
    }
}

pub fn parse_unix_listing_line(line: &str) -> Option<ParsedListingEntry> {
    let trimmed = line.trim_end_matches(['\r', '\n']);
    let fields = split_long_listing_into(trimmed, 9)?;
    if !looks_like_permissions(fields[0]) {
        return None;
    }

    let perms = permissions_from_string(fields[0]);
    let file_type = perms & S_IFMT;
    let is_symlink = file_type == S_IFLNK;

    let mut entry = ParsedListingEntry {
        longname: trimmed.to_string(),
        type_known: true,
        is_dir: file_type == S_IFDIR,
        is_symlink,
        permissions: perms,
        owner: Some(fields[2].to_string()),
        group: Some(fields[3].to_string()),
        ..Default::default()
    };

    if file_type == S_IFCHR || file_type == S_IFBLK {
        // Device nodes carry `major, minor` in two columns instead of one size column.
        if let Some(dev_fields) = split_long_listing_into(trimmed, 10) {
            if let Some(ts) =
                parse_full_time_columns(dev_fields[6], dev_fields[7], dev_fields[8])
            {
                if let Some(full_dev) = split_long_listing_into(trimmed, 10) {
                    entry.name = full_dev[9].to_string();
                }
                entry.mtime = ts;
                entry.time_known = true;
            } else {
                entry.name = dev_fields[9].to_string();
                if let Some(ts) =
                    parse_traditional_ls_date(dev_fields[6], dev_fields[7], dev_fields[8])
                {
                    entry.mtime = ts;
                    entry.time_known = true;
                }
            }
        } else {
            entry.name = fields[8].to_string();
        }
        entry.size = 0;
    } else {
        entry.size = if all_digits(fields[4]) {
            fields[4].parse::<u64>().unwrap_or(0)
        } else {
            0
        };

        if let Some(ts) = parse_full_time_columns(fields[5], fields[6], fields[7]) {
            entry.name = fields[8].to_string();
            entry.mtime = ts;
            entry.time_known = true;
        } else {
            entry.name = fields[8].to_string();
            if let Some(ts) = parse_traditional_ls_date(fields[5], fields[6], fields[7]) {
                entry.mtime = ts;
                entry.time_known = true;
            }
        }
    }

    if is_symlink {
        if let Some((link_name, _target)) = entry.name.split_once(" -> ") {
            entry.name = link_name.to_string();
        }
        entry.is_dir = false;
    }

    if entry.name.is_empty() || entry.name == "." || entry.name == ".." {
        return None;
    }
    Some(entry)
}

pub fn looks_like_dos_listing(line: &str) -> bool {
    let trimmed = line.trim_start_matches([' ', '\t']);
    let b = trimmed.as_bytes();
    // Matches MM-DD-YY or MM-DD-YYYY or YYYY-MM-DD followed by whitespace and HH:MM
    if b.len() < 17 {
        return false;
    }
    let date_token = trimmed.split_whitespace().next().unwrap_or("");
    let parts: Vec<&str> = date_token.split('-').collect();
    if parts.len() != 3 || !parts.iter().all(|p| all_digits(p)) {
        return false;
    }
    let time_token = trimmed.split_whitespace().nth(1).unwrap_or("");
    time_token.contains(':')
}

fn parse_dos_datetime(date_str: &str, time_str: &str) -> Option<i64> {
    let dparts: Vec<&str> = date_str.split('-').collect();
    if dparts.len() != 3 {
        return None;
    }
    let (year, month, day) = if dparts[0].len() == 4 {
        (
            dparts[0].parse::<i32>().ok()?,
            dparts[1].parse::<u32>().ok()?,
            dparts[2].parse::<u32>().ok()?,
        )
    } else {
        let yy: i32 = dparts[2].parse().ok()?;
        let full_year = if dparts[2].len() == 4 {
            yy
        } else if yy >= 70 {
            1900 + yy
        } else {
            2000 + yy
        };
        (
            full_year,
            dparts[0].parse::<u32>().ok()?,
            dparts[1].parse::<u32>().ok()?,
        )
    };

    let upper_time = time_str.trim().to_ascii_uppercase();
    let (clock, meridiem) = if let Some(c) = upper_time.strip_suffix("AM") {
        (c.trim(), Some(false))
    } else if let Some(c) = upper_time.strip_suffix("PM") {
        (c.trim(), Some(true))
    } else {
        (upper_time.as_str(), None)
    };
    let mut tparts = clock.split(':');
    let mut hour: u32 = tparts.next()?.parse().ok()?;
    let minute: u32 = tparts.next()?.parse().ok()?;
    let second: u32 = tparts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    if let Some(is_pm) = meridiem {
        if hour == 0 || hour > 12 {
            return None;
        }
        if is_pm && hour < 12 {
            hour += 12;
        } else if !is_pm && hour == 12 {
            hour = 0;
        }
    }
    utc_ymdhms_to_unix(year, month, day, hour, minute, second)
}

pub fn parse_dos_listing_line(line: &str) -> Option<ParsedListingEntry> {
    let trimmed = line.trim_end_matches(['\r', '\n']);
    if !looks_like_dos_listing(trimmed) {
        return None;
    }

    let bytes = trimmed.as_bytes();
    let len = bytes.len();
    let mut idx = 0usize;
    let mut next_tok = || -> Option<&str> {
        while idx < len && (bytes[idx] == b' ' || bytes[idx] == b'\t') {
            idx += 1;
        }
        if idx >= len {
            return None;
        }
        let s = idx;
        while idx < len && bytes[idx] != b' ' && bytes[idx] != b'\t' {
            idx += 1;
        }
        Some(&trimmed[s..idx])
    };

    let date_str = next_tok()?;
    let mut time_str = next_tok()?.to_string();
    let mut dir_or_size = next_tok()?;
    if dir_or_size.eq_ignore_ascii_case("AM") || dir_or_size.eq_ignore_ascii_case("PM") {
        time_str.push(' ');
        time_str.push_str(&dir_or_size.to_ascii_uppercase());
        dir_or_size = next_tok()?;
    }

    while idx < len && (bytes[idx] == b' ' || bytes[idx] == b'\t') {
        idx += 1;
    }
    let name = trimmed[idx..].trim_end_matches([' ', '\t']);
    if name.is_empty() || name == "." || name == ".." {
        return None;
    }

    let is_dir = dir_or_size.eq_ignore_ascii_case("<DIR>");
    let size = if is_dir {
        0
    } else if all_digits(dir_or_size) {
        dir_or_size.parse::<u64>().unwrap_or(0)
    } else {
        return None;
    };

    let mtime_opt = parse_dos_datetime(date_str, &time_str);
    Some(ParsedListingEntry {
        name: name.to_string(),
        longname: trimmed.to_string(),
        type_known: true,
        is_dir,
        is_symlink: false,
        permissions: if is_dir {
            S_IFDIR | 0o755
        } else {
            S_IFREG | 0o644
        },
        size,
        time_known: mtime_opt.is_some(),
        mtime: mtime_opt.unwrap_or(0),
        owner: None,
        group: None,
    })
}

pub fn looks_like_vms_listing(line: &str) -> bool {
    let trimmed = line.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() || trimmed.starts_with(' ') {
        return false;
    }
    let Some(semi) = trimmed.find(';') else {
        return false;
    };
    if semi < 2 {
        return false;
    }
    let Some(rel_dash) = trimmed[semi + 1..].find('-') else {
        return false;
    };
    let dash = semi + 1 + rel_dash;
    if dash + 9 > trimmed.len() {
        return false;
    }
    let Some(_) = month_index_ascii(&trimmed[dash + 1..dash + 4]) else {
        return false;
    };
    trimmed.contains('[') && trimmed.contains(']')
}

fn parse_vms_permissions(prot: &str, is_dir: bool) -> u32 {
    let base = if is_dir { S_IFDIR } else { S_IFREG };
    let Some(inner) = prot.strip_prefix('(').and_then(|s| s.strip_suffix(')')) else {
        return base | if is_dir { 0o755 } else { 0o644 };
    };
    let classes: Vec<&str> = inner.split(',').collect();
    if classes.len() != 4 {
        return base | if is_dir { 0o755 } else { 0o644 };
    }
    // VMS classes: (System, Owner, Group, World) -> map Owner, Group, World.
    let class_bits = |spec: &str, shift: u32| -> u32 {
        let mut bits = 0u32;
        for b in spec.bytes() {
            match b.to_ascii_uppercase() {
                b'R' => bits |= 4,
                b'W' | b'D' => bits |= 2,
                b'E' => bits |= 1,
                _ => {}
            }
        }
        bits << shift
    };
    base | class_bits(classes[1], 6) | class_bits(classes[2], 3) | class_bits(classes[3], 0)
}

pub fn parse_vms_listing_line(line: &str) -> Option<ParsedListingEntry> {
    let trimmed = line.trim_end_matches(['\r', '\n']);
    if !looks_like_vms_listing(trimmed) {
        return None;
    }
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.len() < 4 {
        return None;
    }
    let (raw_name, ver_str) = tokens[0].split_once(';')?;
    if raw_name.is_empty() || !all_digits(ver_str) {
        return None;
    }
    // Size column in VMS may be `blocks` or `used/allocated`
    let blocks_str = tokens[1].split('/').next().unwrap_or(tokens[1]);
    if !all_digits(blocks_str) {
        return None;
    }
    let blocks: u64 = blocks_str.parse().ok()?;

    // Date `DD-MON-YYYY` and optional `HH:MM[:SS[.cc]]`
    let dparts: Vec<&str> = tokens[2].split('-').collect();
    if dparts.len() != 3 || !all_digits(dparts[0]) || !all_digits(dparts[2]) {
        return None;
    }
    let day: u32 = dparts[0].parse().ok()?;
    let month = month_index_ascii(dparts[1])?;
    let year: i32 = dparts[2].parse().ok()?;

    let mut idx = 3usize;
    let (hour, minute, second) = if tokens.get(idx).is_some_and(|t| t.contains(':')) {
        let hms = tokens[idx].split('.').next().unwrap_or(tokens[idx]);
        let mut tp = hms.split(':');
        let h: u32 = tp.next()?.parse().ok()?;
        let m: u32 = tp.next()?.parse().ok()?;
        let s: u32 = tp.next().and_then(|v| v.parse().ok()).unwrap_or(0);
        idx += 1;
        (h, m, s)
    } else {
        (0, 0, 0)
    };
    let mtime_opt = utc_ymdhms_to_unix(year, month, day, hour, minute, second);

    let owner = tokens
        .get(idx)
        .and_then(|t| t.strip_prefix('[').and_then(|s| s.strip_suffix(']')))
        .map(str::to_string);
    if owner.is_some() {
        idx += 1;
    }

    let is_dir = raw_name.len() > 4 && raw_name[raw_name.len() - 4..].eq_ignore_ascii_case(".DIR");
    let display_name = if is_dir {
        raw_name[..raw_name.len() - 4].to_string()
    } else {
        raw_name.to_string()
    };
    if display_name.is_empty() {
        return None;
    }

    let perms = tokens
        .get(idx)
        .map(|p| parse_vms_permissions(p, is_dir))
        .unwrap_or(if is_dir {
            S_IFDIR | 0o755
        } else {
            S_IFREG | 0o644
        });

    Some(ParsedListingEntry {
        name: display_name,
        longname: trimmed.to_string(),
        type_known: true,
        is_dir,
        is_symlink: false,
        permissions: perms,
        size: if is_dir { 0 } else { blocks.saturating_mul(512) },
        time_known: mtime_opt.is_some(),
        mtime: mtime_opt.unwrap_or(0),
        owner,
        group: None,
    })
}

/// Parses an RFC 3659 `YYYYMMDDHHMMSS[.sss]` UTC timestamp (used by `MLSD`,
/// `MLST`, and `MDTM`).
pub fn parse_ftp_compact_utc(text: &str) -> Option<i64> {
    let base = text.trim().split('.').next()?;
    if base.len() != 14 || !all_digits(base) {
        return None;
    }
    let year: i32 = base[0..4].parse().ok()?;
    let month: u32 = base[4..6].parse().ok()?;
    let day: u32 = base[6..8].parse().ok()?;
    let hour: u32 = base[8..10].parse().ok()?;
    let minute: u32 = base[10..12].parse().ok()?;
    let second: u32 = base[12..14].parse().ok()?;
    utc_ymdhms_to_unix(year, month, day, hour, minute, second)
}

/// Parses one RFC 3659 `MLSD` / `MLST` entry line:
/// `type=file;size=42;modify=20260115103000;unix.mode=0644; report.csv`.
/// Returns `Ok(None)` for `cdir` / `pdir` (`.` and `..`) entries so directory
/// listings exclude self/parent markers cleanly.
pub fn parse_mlsx_line(line: &str) -> Result<Option<ParsedListingEntry>, String> {
    let trimmed = line.trim_end_matches(['\r', '\n']).trim_start_matches(' ');
    if trimmed.is_empty() {
        return Ok(None);
    }
    let Some((facts_str, raw_name)) = trimmed.split_once(' ') else {
        return Err(format!("Malformed MLSx line (missing space separator): {trimmed}"));
    };
    let name = if let Some(leaf) = raw_name.rsplit('/').find(|s| !s.is_empty()) {
        if raw_name.contains('/') {
            leaf
        } else {
            raw_name
        }
    } else {
        raw_name
    };
    if name.is_empty() || name == "." || name == ".." {
        return Ok(None);
    }

    let mut is_dir = false;
    let mut is_symlink = false;
    let mut skip_entry = false;
    let mut size = 0u64;
    let mut mtime = 0i64;
    let mut time_known = false;
    let mut unix_mode: Option<u32> = None;
    let mut owner: Option<String> = None;
    let mut group: Option<String> = None;

    for fact in facts_str.split(';').filter(|f| !f.is_empty()) {
        let Some((k, v)) = fact.split_once('=') else {
            continue;
        };
        match k.to_ascii_lowercase().as_str() {
            "type" => {
                let lv = v.to_ascii_lowercase();
                if lv == "cdir" || lv == "pdir" {
                    skip_entry = true;
                } else if lv == "dir" {
                    is_dir = true;
                } else if lv.starts_with("os.unix=slink") || lv.starts_with("os.unix=symlink") {
                    is_symlink = true;
                }
            }
            "size" | "sizd" => {
                if all_digits(v) {
                    size = v.parse::<u64>().unwrap_or(0);
                }
            }
            "modify" => {
                if let Some(ts) = parse_ftp_compact_utc(v) {
                    mtime = ts;
                    time_known = true;
                }
            }
            "unix.mode" => {
                if let Ok(m) = u32::from_str_radix(v.trim_start_matches("0o"), 8) {
                    unix_mode = Some(m & 0o7777);
                }
            }
            "unix.owner" | "unix.uid" => {
                if !v.is_empty() && owner.is_none() {
                    owner = Some(v.to_string());
                }
            }
            "unix.group" | "unix.gid" => {
                if !v.is_empty() && group.is_none() {
                    group = Some(v.to_string());
                }
            }
            _ => {}
        }
    }

    if skip_entry {
        return Ok(None);
    }

    let type_bits = if is_symlink {
        S_IFLNK
    } else if is_dir {
        S_IFDIR
    } else {
        S_IFREG
    };
    let mode_bits = unix_mode.unwrap_or(if is_dir { 0o755 } else { 0o644 });

    Ok(Some(ParsedListingEntry {
        name: name.to_string(),
        longname: trimmed.to_string(),
        type_known: true,
        is_dir,
        is_symlink,
        permissions: type_bits | mode_bits,
        size: if is_dir { 0 } else { size },
        time_known,
        mtime,
        owner,
        group,
    }))
}

pub fn parse_any_listing_line(line: &str) -> Option<ParsedListingEntry> {
    parse_unix_listing_line(line)
        .or_else(|| parse_dos_listing_line(line))
        .or_else(|| parse_vms_listing_line(line))
}

/// Parses a complete multi-line `LIST` payload (Unix, DOS/IIS, or OpenVMS)
/// into sorted `FileEntry` records, ignoring `total N` headers and VMS
/// directory header/footer banners.
pub fn parse_list_output(text: &str) -> Vec<FileEntry> {
    let mut out = Vec::new();
    for raw_line in text.lines() {
        let trimmed = raw_line.trim_end_matches('\r');
        if trimmed.trim().is_empty() {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("total ") {
            if all_digits(rest.trim()) {
                continue;
            }
        }
        if let Some(parsed) = parse_any_listing_line(trimmed) {
            out.push(parsed.into_file_entry());
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permissions_round_trip_preserves_special_bits_and_types() {
        for mode_str in [
            "-rw-r--r--",
            "drwxr-xr-x",
            "lrwxrwxrwx",
            "-rwsr-xr-x",
            "-rwSr--r--",
            "drwxr-sr-x",
            "drwxrwxrwt",
            "drwxrwxrwT",
            "crw-rw-rw-",
            "brw-rw----",
        ] {
            let bits = permissions_from_string(mode_str);
            assert_eq!(permissions_string(bits), mode_str);
        }
    }

    #[test]
    fn parses_unix_full_time_symlinks_and_devices() {
        let file = parse_unix_listing_line(
            "-rw-r----- 1 alice staff 4096 2026-03-15 12:30:45.000000000 +0000 report final.txt",
        )
        .unwrap();
        assert_eq!(file.name, "report final.txt");
        assert_eq!(file.size, 4096);
        assert!(!file.is_dir);
        assert!(file.time_known);
        assert_eq!(format_utc_timestamp(file.mtime), "2026-03-15 12:30:45");

        let link =
            parse_unix_listing_line("lrwxrwxrwx 1 root root 11 Oct 25 20:00 latest -> release-v2")
                .unwrap();
        assert_eq!(link.name, "latest");
        assert!(link.is_symlink);
        assert!(!link.is_dir);

        // Regular file containing ` -> ` in its filename keeps its whole name!
        let arrow_file =
            parse_unix_listing_line("-rw-r--r-- 1 root root 12 Oct 25 20:00 odd -> name.txt")
                .unwrap();
        assert_eq!(arrow_file.name, "odd -> name.txt");

        let dev =
            parse_unix_listing_line("crw-rw-rw- 1 root root 1, 3 Oct 25 20:00 null").unwrap();
        assert_eq!(dev.name, "null");
        assert_eq!(dev.size, 0);
    }

    #[test]
    fn parses_dos_and_vms_and_mlsx_dialects() {
        let dos_dir =
            parse_dos_listing_line("03-25-26  11:22AM       <DIR>          Invoices 2026").unwrap();
        assert!(dos_dir.is_dir);
        assert_eq!(dos_dir.name, "Invoices 2026");

        let dos_file =
            parse_dos_listing_line("07-14-25  04:00 PM             12345   summary.pdf").unwrap();
        assert!(!dos_file.is_dir);
        assert_eq!(dos_file.size, 12345);
        assert_eq!(dos_file.name, "summary.pdf");

        let vms_file = parse_vms_listing_line(
            " readme.txt;3   10  25-jun-2025 11:22:33 [SYSTEM] (rwed,rwed,re,r)",
        );
        assert!(vms_file.is_none(), "leading space is rejected per VMS spec");
        let vms_valid = parse_vms_listing_line(
            "readme.txt;3   10  25-jun-2025 11:22:33 [SYSTEM] (rwed,rwed,re,r)",
        )
        .unwrap();
        assert_eq!(vms_valid.name, "readme.txt");
        assert_eq!(vms_valid.size, 5120);
        assert_eq!(permissions_string(vms_valid.permissions), "-rwxr-xr--");

        let vms_dir = parse_vms_listing_line(
            "ARCHIVE.DIR;1   3  25-JUN-2025 11:22:33 [OWNER] (RWED,RWED,RE,RE)",
        )
        .unwrap();
        assert!(vms_dir.is_dir);
        assert_eq!(vms_dir.name, "ARCHIVE");

        let mlsd = parse_mlsx_line(
            "type=file;size=9876;modify=20260201091530;unix.mode=0640; backup.tar.gz",
        )
        .unwrap()
        .unwrap();
        assert_eq!(mlsd.name, "backup.tar.gz");
        assert_eq!(mlsd.size, 9876);
        assert_eq!(permissions_string(mlsd.permissions), "-rw-r-----");

        assert!(
            parse_mlsx_line("type=cdir;modify=20260201091530; .")
                .unwrap()
                .is_none()
        );
    }
}
