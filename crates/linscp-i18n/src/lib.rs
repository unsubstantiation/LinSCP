//! Unified localization lookup and single-pass placeholder interpolation for
//! CLI and GUI messages (`locales/{de,en,es,fr}.json`).

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogDomain {
    Cli,
    Gui,
}

#[derive(Debug, Deserialize)]
struct UnifiedCatalogFile {
    cli: BTreeMap<String, String>,
    gui: BTreeMap<String, String>,
}

static CATALOGS: OnceLock<BTreeMap<&'static str, UnifiedCatalogFile>> = OnceLock::new();

fn catalogs() -> &'static BTreeMap<&'static str, UnifiedCatalogFile> {
    CATALOGS.get_or_init(|| {
        let mut map = BTreeMap::new();
        for (code, raw) in [
            ("de", include_str!("../../../locales/de.json")),
            ("en", include_str!("../../../locales/en.json")),
            ("es", include_str!("../../../locales/es.json")),
            ("fr", include_str!("../../../locales/fr.json")),
        ] {
            let parsed: UnifiedCatalogFile =
                serde_json::from_str(raw).expect("embedded unified locale JSON must be valid");
            map.insert(code, parsed);
        }
        map
    })
}

/// Available shipped locale codes in sorted order.
pub fn supported_locales() -> Vec<&'static str> {
    catalogs().keys().copied().collect()
}

/// Normalizes BCP-47 or POSIX locale strings (`"es-MX"`, `"fr_CA.UTF-8"`) to
/// a shipped catalog code, falling back to `"en"`.
pub fn normalize_locale(raw: &str) -> &'static str {
    let trimmed = raw
        .split(['.', '@'])
        .next()
        .unwrap_or("")
        .trim()
        .replace('-', "_");
    if trimmed.is_empty() {
        return "en";
    }
    let map = catalogs();
    for &code in map.keys() {
        if code.eq_ignore_ascii_case(&trimmed) {
            return code;
        }
    }
    let base = trimmed.split('_').next().unwrap_or("").to_ascii_lowercase();
    for &code in map.keys() {
        if code == base {
            return code;
        }
    }
    "en"
}

/// Looks up `message` in `domain` for `locale`, returning the English source
/// string verbatim when untranslated or unknown.
pub fn translate<'a>(domain: CatalogDomain, locale: &str, message: &'a str) -> &'a str {
    let normalized = normalize_locale(locale);
    let Some(bundle) = catalogs().get(normalized) else {
        return message;
    };
    let table = match domain {
        CatalogDomain::Cli => &bundle.cli,
        CatalogDomain::Gui => &bundle.gui,
    };
    table.get(message).map(String::as_str).unwrap_or(message)
}

/// Single-pass `{placeholder}` interpolation. Replacement values are treated
/// strictly as literal text and are never rescanned for `{...}` tokens.
pub fn interpolate(template: &str, values: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len());
    let bytes = template.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'{' {
            if let Some(rel_end) = bytes[index + 1..].iter().position(|&b| b == b'}') {
                let end = index + 1 + rel_end;
                let key = &template[index + 1..end];
                if !key.is_empty() && key.bytes().all(|b| b.is_ascii_lowercase()) {
                    if let Some((_, value)) = values.iter().find(|(k, _)| *k == key) {
                        out.push_str(value);
                    } else {
                        out.push_str(&template[index..=end]);
                    }
                    index = end + 1;
                    continue;
                }
            }
        }
        let ch = template[index..].chars().next().expect("valid UTF-8 slice");
        out.push(ch);
        index += ch.len_utf8();
    }
    out
}

/// Translates `message` and applies single-pass named interpolation.
pub fn translate_with(
    domain: CatalogDomain,
    locale: &str,
    message: &str,
    values: &[(&str, &str)],
) -> String {
    interpolate(translate(domain, locale, message), values)
}

/// CLDR cardinal plural selection for the shipped languages (`fr` treats `0`
/// and `1` as singular `"one"`; `en`, `es`, and `de` treat only `1` as `"one"`).
pub fn is_singular(locale: &str, count: u64) -> bool {
    match normalize_locale(locale) {
        "fr" => count == 0 || count == 1,
        _ => count == 1,
    }
}

/// Translates a singular/plural pair and substitutes `{count}` alongside `values`.
pub fn translate_plural(
    domain: CatalogDomain,
    locale: &str,
    singular: &str,
    plural: &str,
    count: u64,
    extra_values: &[(&str, &str)],
) -> String {
    let chosen = if is_singular(locale, count) {
        singular
    } else {
        plural
    };
    let count_str = count.to_string();
    let mut combined = Vec::with_capacity(extra_values.len() + 1);
    combined.push(("count", count_str.as_str()));
    combined.extend_from_slice(extra_values);
    translate_with(domain, locale, chosen, &combined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locale_normalization_handles_bcp47_and_posix_variants() {
        assert_eq!(normalize_locale("es-MX"), "es");
        assert_eq!(normalize_locale("fr_CA.UTF-8"), "fr");
        assert_eq!(normalize_locale("de_DE@euro"), "de");
        assert_eq!(normalize_locale("eo"), "en");
    }

    #[test]
    fn domain_separation_preserves_cli_and_gui_wording() {
        assert_eq!(translate(CatalogDomain::Cli, "es", "upload"), "subida");
        assert_eq!(translate(CatalogDomain::Gui, "es", "upload"), "subir");
    }

    #[test]
    fn french_zero_uses_singular_plural_rule() {
        let fr_zero = translate_plural(
            CatalogDomain::Gui,
            "fr",
            "{count} match",
            "{count} matches",
            0,
            &[],
        );
        let es_zero = translate_plural(
            CatalogDomain::Gui,
            "es",
            "{count} match",
            "{count} matches",
            0,
            &[],
        );
        assert_eq!(fr_zero, "0 r\u{00e9}sultat");
        assert_eq!(es_zero, "0 coincidencias");
    }

    #[test]
    fn single_pass_interpolation_never_reexpands_user_data() {
        let rendered = translate_with(
            CatalogDomain::Gui,
            "es",
            "Line {line}: {snippet}",
            &[("line", "1"), ("snippet", "{line} $& %n <img>")],
        );
        assert_eq!(rendered, "L\u{00ed}nea 1: {line} $& %n <img>");
    }
}
