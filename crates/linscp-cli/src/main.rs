//! Cross-platform Rust CLI entrypoint (`linscp-rs` during parallel migration,
//! replacing `linscp` at Phase 6 cutover).

use std::sync::Arc;

use linscp_http::{serve, HttpAppState, HttpServerConfig};
use linscp_i18n::{supported_locales, translate, CatalogDomain};
use linscp_service::CommanderService;

/// Normalizes `/option=value` and `/option:value` command-line switches to
/// `-option=value` without touching POSIX paths (`/home/user`, `/var/log/a`).
pub fn normalize_cli_switch(arg: &str) -> String {
    let Some(rest) = arg.strip_prefix('/') else {
        return arg.to_string();
    };
    if rest.is_empty() {
        return arg.to_string();
    }
    let switch_name_end = rest.find(['=', ':']).unwrap_or(rest.len());
    let name = &rest[..switch_name_end];
    if name.is_empty() || name.contains('/') || name.contains('\\') {
        return arg.to_string();
    }
    const KNOWN_SLASH_SWITCHES: &[&str] = &[
        "help",
        "version",
        "command",
        "script",
        "log",
        "loglevel",
        "xmlgroups",
        "xmllog",
        "ini",
        "rawsettings",
        "passive",
        "implicit",
        "explicit",
        "timeout",
        "hostkey",
        "privatekey",
        "passphrase",
        "defaults",
        "batchsettings",
    ];
    if !KNOWN_SLASH_SWITCHES
        .iter()
        .any(|known| known.eq_ignore_ascii_case(name))
    {
        return arg.to_string();
    }
    if switch_name_end < rest.len() {
        let value = &rest[switch_name_end + 1..];
        format!("-{}={value}", name.to_ascii_lowercase())
    } else {
        format!("-{}", name.to_ascii_lowercase())
    }
}

fn print_help(locale: &str) {
    let header = translate(CatalogDomain::Cli, locale, "LinSCP — secure file transfer client");
    println!("{header}");
    println!("  -version              Print version and supported locales");
    println!("  -help                 Show command-line usage");
    println!("  --serve-http [PORT]   Run standalone browser Commander server");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args()
        .skip(1)
        .map(|a| normalize_cli_switch(&a))
        .collect();
    let locale = std::env::var("LINSCP_LANG")
        .or_else(|_| std::env::var("LC_ALL"))
        .or_else(|_| std::env::var("LANG"))
        .unwrap_or_else(|_| "en".to_string());

    if args.iter().any(|a| a == "-version" || a == "--version") {
        println!(
            "linscp-rs {} (locales: {})",
            env!("CARGO_PKG_VERSION"),
            supported_locales().join(", ")
        );
        return Ok(());
    }

    if args.is_empty() || args.iter().any(|a| a == "-help" || a == "--help") {
        print_help(&locale);
        return Ok(());
    }

    if let Some(pos) = args.iter().position(|a| a == "--serve-http") {
        let port = args
            .get(pos + 1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);
        let cfg = HttpServerConfig::loopback(port);
        let token = cfg.bearer_token.clone();
        let listener = tokio::net::TcpListener::bind(cfg.bind_addr).await?;
        let local_addr = listener.local_addr()?;
        let state = Arc::new(HttpAppState {
            service: CommanderService::default(),
            config: cfg,
        });
        println!("LinSCP HTTP server listening on http://{local_addr}/ (X-LSCP-Token: {token})");
        serve(listener, state).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slash_switch_normalization_preserves_posix_paths() {
        assert_eq!(normalize_cli_switch("/command"), "-command");
        assert_eq!(normalize_cli_switch("/log:/tmp/out.log"), "-log=/tmp/out.log");
        assert_eq!(normalize_cli_switch("/script=run.txt"), "-script=run.txt");
        assert_eq!(normalize_cli_switch("/home/user/file.txt"), "/home/user/file.txt");
        assert_eq!(normalize_cli_switch("/tmp"), "/tmp");
    }
}
