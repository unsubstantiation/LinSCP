//! Script command tokenization, unambiguous prefix matching, `%TIMESTAMP%` /
//! `%1%..%9%` / `%ENV%` parameter expansion, and secret-redacting log censoring.

use linscp_platform::terminal::{local_ymdhms_wday, mktime_local_ymdhms};

const MONTH_NAMES: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

const DAY_NAMES: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrefixMatch<'a> {
    ExactOrUnique(&'a str),
    Ambiguous(String),
    None,
}

/// Resolves `text` against `names` case-insensitively, accepting an exact match
/// or an unambiguous prefix match.
pub fn resolve_prefixed_name<'a>(names: &[&'a str], text: &str) -> PrefixMatch<'a> {
    let wanted = text.trim().to_ascii_lowercase();
    if wanted.is_empty() {
        return PrefixMatch::None;
    }
    for &n in names {
        if n.eq_ignore_ascii_case(&wanted) {
            return PrefixMatch::ExactOrUnique(n);
        }
    }
    let mut matched: Vec<&'a str> = Vec::new();
    for &n in names {
        if n.to_ascii_lowercase().starts_with(&wanted) {
            matched.push(n);
        }
    }
    match matched.len() {
        0 => PrefixMatch::None,
        1 => PrefixMatch::ExactOrUnique(matched[0]),
        _ => PrefixMatch::Ambiguous(matched.join(", ")),
    }
}

fn days_in_month(year: i32, month: i32) -> i32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
            if leap { 29 } else { 28 }
        }
        _ => 31,
    }
}

/// Formats `epoch_secs` (local time) according to Delphi `FormatDateTime` tokens
/// (`yyyy`, `yy`, `mmmm`, `mmm`, `mm`, `m`, `dddd`, `ddd`, `dd`, `d`, `hh`, `h`,
/// `nn`, `n`, `ss`, `s`, `am/pm`, `a/p`, `c`, and single/double-quoted literals).
pub fn format_timestamp(epoch_secs: i64, format: &str) -> String {
    let (year, month, day, hour, min, sec, wday) = local_ymdhms_wday(epoch_secs);
    let lowered = format.to_ascii_lowercase();
    let fmt_bytes = format.as_bytes();
    let low_bytes = lowered.as_bytes();

    // Detect unquoted AM/PM marker
    let mut has_ampm = false;
    let mut scan = 0usize;
    while scan < fmt_bytes.len() {
        let q = fmt_bytes[scan];
        if q == b'"' || q == b'\'' {
            scan += 1;
            while scan < fmt_bytes.len() && fmt_bytes[scan] != q {
                scan += 1;
            }
            scan += 1;
            continue;
        }
        if lowered[scan..].starts_with("am/pm") || lowered[scan..].starts_with("a/p") {
            has_ampm = true;
            break;
        }
        scan += 1;
    }

    const TOKENS: [&str; 19] = [
        "yyyy", "mmmm", "dddd", "am/pm", "a/p", "mmm", "ddd", "yy", "mm", "dd", "hh", "nn", "ss",
        "c", "m", "d", "h", "n", "s",
    ];

    let mut out = String::new();
    let mut i = 0usize;
    while i < fmt_bytes.len() {
        let c = fmt_bytes[i];
        if c == b'"' || c == b'\'' {
            let quote = c;
            i += 1;
            while i < fmt_bytes.len() {
                if fmt_bytes[i] == quote {
                    if i + 1 < fmt_bytes.len() && fmt_bytes[i + 1] == quote {
                        out.push(quote as char);
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                let ch = format[i..].chars().next().unwrap_or(' ');
                out.push(ch);
                i += ch.len_utf8();
            }
            continue;
        }

        let mut matched_tok: Option<&str> = None;
        for &tok in &TOKENS {
            if low_bytes[i..].starts_with(tok.as_bytes()) {
                matched_tok = Some(tok);
                break;
            }
        }
        let Some(tok) = matched_tok else {
            let ch = format[i..].chars().next().unwrap_or(' ');
            out.push(ch);
            i += ch.len_utf8();
            continue;
        };
        i += tok.len();
        let display_hour = if has_ampm {
            let h12 = hour % 12;
            if h12 == 0 { 12 } else { h12 }
        } else {
            hour
        };
        match tok {
            "yyyy" => out.push_str(&format!("{year:04}")),
            "yy" => out.push_str(&format!("{:02}", year.rem_euclid(100))),
            "mmmm" => out.push_str(MONTH_NAMES[(month.saturating_sub(1) as usize) % 12]),
            "mmm" => out.push_str(&MONTH_NAMES[(month.saturating_sub(1) as usize) % 12][..3]),
            "mm" => out.push_str(&format!("{month:02}")),
            "m" => out.push_str(&format!("{month}")),
            "dddd" => out.push_str(DAY_NAMES[(wday as usize) % 7]),
            "ddd" => out.push_str(&DAY_NAMES[(wday as usize) % 7][..3]),
            "dd" => out.push_str(&format!("{day:02}")),
            "d" => out.push_str(&format!("{day}")),
            "hh" => out.push_str(&format!("{display_hour:02}")),
            "h" => out.push_str(&format!("{display_hour}")),
            "nn" => out.push_str(&format!("{min:02}")),
            "n" => out.push_str(&format!("{min}")),
            "ss" => out.push_str(&format!("{sec:02}")),
            "s" => out.push_str(&format!("{sec}")),
            "am/pm" => out.push_str(if hour >= 12 { "PM" } else { "AM" }),
            "a/p" => out.push_str(if hour >= 12 { "P" } else { "A" }),
            "c" => out.push_str(&format!(
                "{year:04}-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02}"
            )),
            _ => {}
        }
    }
    out
}

pub fn try_relative_time(spec: &str, base_epoch: i64, add: bool) -> Result<i64, String> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Err(
            "a relative time needs an amount and a unit (for example '-1D', '+2H', 'today' or 'yesterday')"
                .to_string(),
        );
    }
    let (mut amount, unit, start_of_unit) = if trimmed.eq_ignore_ascii_case("today") {
        (0i32, 'D', true)
    } else if trimmed.eq_ignore_ascii_case("yesterday") {
        (1i32, 'D', true)
    } else {
        let digits = trimmed
            .bytes()
            .take_while(|b| b.is_ascii_digit())
            .count();
        if digits == 0 || digits >= trimmed.len() {
            return Err(format!(
                "'{trimmed}' is not a relative time (expected for example '1D', '2H' or '30N')"
            ));
        }
        let amt: i32 = trimmed[..digits]
            .parse()
            .map_err(|_| format!("'{trimmed}' is outside the representable time range"))?;
        let mut rest = trimmed[digits..].trim();
        let mut snap = false;
        if rest.len() == 2 && rest.as_bytes()[1].eq_ignore_ascii_case(&b's') {
            snap = true;
            rest = &rest[..1];
        }
        if rest.len() != 1 {
            return Err(format!(
                "'{trimmed}' has no single time unit after the number"
            ));
        }
        (amt, rest.as_bytes()[0].to_ascii_uppercase() as char, snap)
    };

    if !add {
        amount = -amount;
    }

    let (y0, m0, d0, h0, n0, s0, _) = local_ymdhms_wday(base_epoch);
    let mut year = y0;
    let mut month = m0 as i32;
    let mut day = d0 as i32;
    let mut hour = h0 as i32;
    let mut min = n0 as i32;
    let mut sec = s0 as i32;

    match unit {
        'S' => sec += amount,
        'N' => {
            if start_of_unit {
                sec = 0;
            }
            min += amount;
        }
        'H' => {
            if start_of_unit {
                sec = 0;
                min = 0;
            }
            hour += amount;
        }
        'D' => {
            if start_of_unit {
                sec = 0;
                min = 0;
                hour = 0;
            }
            day += amount;
        }
        'Y' => {
            if start_of_unit {
                sec = 0;
                min = 0;
                hour = 0;
                month = 1;
                day = 1;
            }
            year += amount;
            let max_d = days_in_month(year, month);
            day = day.clamp(1, max_d);
        }
        _ => {
            return Err(format!(
                "'{unit}' is not a time unit of this build (S seconds, N minutes, H hours, D days, Y years)"
            ));
        }
    }

    mktime_local_ymdhms(year, month, day, hour, min, sec)
        .ok_or_else(|| format!("'{trimmed}' is outside the representable time range"))
}

fn replace_all_icase(text: &str, needle: &str, replacement: &str) -> String {
    if needle.is_empty() {
        return text.to_string();
    }
    let lower = text.to_ascii_lowercase();
    let wanted = needle.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut pos = 0usize;
    while let Some(rel) = lower[pos..].find(&wanted) {
        let hit = pos + rel;
        out.push_str(&text[pos..hit]);
        out.push_str(replacement);
        pos = hit + wanted.len();
    }
    out.push_str(&text[pos..]);
    out
}

/// Expands `%1%..%9%`, `%TIMESTAMP%`, `%TIMESTAMP[+-offset]#format%`, and `%ENV%` placeholders.
pub fn expand_script_parameters(line: &str, parameters: &[String]) -> Result<String, String> {
    if !line.contains('%') {
        return Ok(line.to_string());
    }
    let mut expanded = line.to_string();
    for (idx, param) in parameters.iter().take(9).enumerate() {
        let token = format!("%{}%", idx + 1);
        expanded = expanded.replace(&token, param);
    }

    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    if std::env::var_os("TIMESTAMP").is_none_or(|v| v.is_empty()) {
        let stamp = format_timestamp(now_epoch, "yyyymmddhhnnss");
        expanded = replace_all_icase(&expanded, "%TIMESTAMP%", &stamp);
    }

    let mut offset = 0usize;
    while offset < expanded.len() {
        let lower = expanded.to_ascii_lowercase();
        let Some(rel_start) = lower[offset..].find("%timestamp") else {
            break;
        };
        let start = offset + rel_start;
        let after_name = start + "%timestamp".len();
        let Some(rel_close) = expanded[after_name..].find('%') else {
            break;
        };
        let close = after_name + rel_close;
        let after_ch = expanded.as_bytes().get(after_name).copied().unwrap_or(0);
        if after_ch != b'+' && after_ch != b'-' && after_ch != b'#' {
            offset = after_name;
            continue;
        }
        let Some(rel_hash) = expanded[after_name..=close].find('#') else {
            let bad = &expanded[start..=close];
            return Err(format!(
                "'{bad}' is not a valid timestamp placeholder; use %TIMESTAMP%, %TIMESTAMP+1D#yyyymmdd% or %TIMESTAMP-2H#yyyy-mm-dd%."
            ));
        };
        let hash = after_name + rel_hash;
        let mut moment = now_epoch;
        if hash > after_name {
            let add = after_ch == b'+';
            let spec = &expanded[after_name + 1..hash];
            let full_tok = &expanded[start..=close];
            moment = try_relative_time(spec, moment, add).map_err(|e| {
                format!("The time offset '{spec}' in '{full_tok}' is not valid: {e}.")
            })?;
        }
        let fmt = &expanded[hash + 1..close];
        let val = format_timestamp(moment, fmt);
        expanded.replace_range(start..=close, &val);
        offset = start + val.len();
    }

    let mut pos = 0usize;
    while pos < expanded.len() {
        let Some(rel_start) = expanded[pos..].find('%') else {
            break;
        };
        let start = pos + rel_start;
        let Some(rel_close) = expanded[start + 1..].find('%') else {
            break;
        };
        let close = start + 1 + rel_close;
        let name = &expanded[start + 1..close];
        if name.is_empty() {
            // `%%` collapses to `%` or advances past empty pair
            pos = start + 1;
            continue;
        }
        if let Ok(val) = std::env::var(name) {
            expanded.replace_range(start..=close, &val);
            pos = start + val.len();
        } else {
            pos = close + 1;
        }
    }
    Ok(expanded)
}

/// Returns `true` when `token` begins with a Windows drive prefix (`C:\...`, `D:/...`)
/// or a CLI/script switch whose value starts with a Windows drive prefix (`-keyfile=D:\...`).
fn looks_like_windows_drive_token(token: &str) -> bool {
    let val = match token.split_once('=') {
        Some((lhs, rhs)) if lhs.starts_with('-') || lhs.starts_with('/') => rhs,
        _ => token,
    };
    let bytes = val.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

/// Splits a script command line into tokens matching `PathUtil::SplitCommandLine`:
/// `'...'` is literal; `"..."` keeps whitespace while treating `\"` and `\\` as escapes
/// and preserving any other `\` literally; `""` is an empty argument; outside quotes `\`
/// escapes the next character (except inside unquoted `<Drive>:\...` Windows paths where
/// `\` not followed by whitespace or quotes is preserved as a path separator).
pub fn tokenize_script_line(line: &str) -> Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_token = false;
    let mut in_double = false;
    let mut in_single = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        if in_single {
            if c == '\'' {
                in_single = false;
            } else {
                current.push(c);
            }
        } else if in_double {
            if c == '\\' {
                if matches!(chars.peek(), Some('"' | '\\')) {
                    current.push(chars.next().unwrap());
                } else {
                    current.push('\\');
                }
            } else if c == '"' {
                in_double = false;
            } else {
                current.push(c);
            }
        } else if c == '\'' {
            in_single = true;
            in_token = true;
        } else if c == '"' {
            in_double = true;
            in_token = true;
        } else if c == '\\' {
            in_token = true;
            if looks_like_windows_drive_token(&current)
                && chars
                    .peek()
                    .is_some_and(|nc| !nc.is_ascii_whitespace() && *nc != '"' && *nc != '\'')
            {
                current.push('\\');
            } else if let Some(next_c) = chars.next() {
                current.push(next_c);
            } else {
                current.push('\\');
            }
        } else if c.is_ascii_whitespace() {
            if in_token {
                tokens.push(std::mem::take(&mut current));
                in_token = false;
            }
        } else {
            current.push(c);
            in_token = true;
        }
    }
    if in_token {
        tokens.push(current);
    }
    Ok(tokens)
}

/// Redacts inline URL passwords (`scheme://user:secret@host`) and secret switches/rawsettings
/// (`-password=...`, `-passphrase=...`, `ProxyPassword=...`, `TunnelPassword=...`, `TunnelPassphrase=...`,
/// `S3SessionToken=...`) before writing to action or diagnostic logs.
pub fn censored_for_log(line: &str) -> String {
    let Ok(tokens) = tokenize_script_line(line) else {
        return mask_url_credentials_inline(line);
    };
    let mut out = Vec::with_capacity(tokens.len());
    for tok in tokens {
        out.push(censor_single_token(&tok));
    }
    out.join(" ")
}

fn censor_single_token(tok: &str) -> String {
    let lower = tok.to_ascii_lowercase();
    for prefix in [
        "-password=",
        "/password=",
        "-password:",
        "/password:",
        "-passphrase=",
        "/passphrase=",
        "-passphrase:",
        "/passphrase:",
        "proxypassword=",
        "tunnelpassword=",
        "tunnelpasswordplain=",
        "tunnelpassphrase=",
        "tunnelpassphraseplain=",
        "s3sessiontoken=",
    ] {
        if lower.starts_with(prefix) {
            return format!("{}***", &tok[..prefix.len()]);
        }
    }
    let masked = mask_url_credentials_inline(tok);
    if masked.contains(' ') {
        format!("\"{}\"", masked.replace('"', "\"\""))
    } else {
        masked
    }
}

pub fn mask_url_credentials_inline(text: &str) -> String {
    let Some(scheme_pos) = text.find("://") else {
        return text.to_string();
    };
    let after_scheme = scheme_pos + 3;
    let authority_end = text[after_scheme..]
        .find('/')
        .map(|i| after_scheme + i)
        .unwrap_or(text.len());
    let authority = &text[after_scheme..authority_end];
    let Some(at_rel) = authority.rfind('@') else {
        return text.to_string();
    };
    let userinfo = &authority[..at_rel];
    let Some(colon_rel) = userinfo.find(':') else {
        return text.to_string();
    };
    format!(
        "{}:***@{}",
        &text[..after_scheme + colon_rel],
        &authority[at_rel + 1..]
    ) + &text[authority_end..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameter_expansion_and_log_censoring_match_script_rules() {
        let got = expand_script_parameters("put %1% %UNSET_VAR_XYZ%", &["report.csv".into()])
            .unwrap();
        assert_eq!(got, "put report.csv %UNSET_VAR_XYZ%");
        assert!(expand_script_parameters("%TIMESTAMP+1D%", &[]).is_err());
        assert_eq!(
            censored_for_log("open sftp://alice:s3cr3t@example.com/ -passphrase=mykey"),
            "open sftp://alice:***@example.com/ -passphrase=***"
        );
    }
}
