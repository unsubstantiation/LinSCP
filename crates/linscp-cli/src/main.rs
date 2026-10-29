//! Cross-platform Rust CLI entrypoint (`linscp`) for batch/interactive scripts,
//! `-server` automation, `-shell` interactive SSH PTYs, `-convertkey` PPK->OpenSSH
//! conversion, `-gui` desktop launcher, and `--serve-http` standalone browser mode.

use std::io::{BufReader, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use linscp_crypto::ppk::ppk_to_pkcs8_pem;
use linscp_engine::script::{
    BatchMode, CliSessionDefaults, ScriptInterpreter, ScriptRunConfig, run_pty_shell_session,
    select_cli_locale_from_env,
};
use linscp_engine::session_store::SessionStore;
use linscp_engine::url_and_raw::{
    DefaultOsVault, ParsedSiteSpec, apply_env_credential_fallbacks, apply_raw_settings,
    connect_ssh_for_shell, is_ssh_scheme, parse_site_url, site_spec_from_stored,
};
use linscp_engine::xml_log::{LogRotationPolicy, SessionLogger};
use linscp_http::{HttpAppState, HttpServerConfig, serve};
use linscp_i18n::{CatalogDomain, supported_locales, translate, translate_with};
use linscp_platform::gui_os::{install_shell_integration, open_url_in_browser, uninstall_shell_integration};
use linscp_platform::terminal::{
    ensure_default_sigint, expand_tilde, launch_gui_application, read_password_no_echo,
    stdin_is_terminal,
};
use linscp_platform::{default_config_dir, write_exclusive_private_file};
use linscp_service::CommanderService;
use linscp_types::ProtocolScheme;

const PRODUCT_VERSION: &str = "1.0";

const USAGE_TEMPLATE: &str = "\
LinSCP {version} - secure file transfer client

  linscp [options] [sftp://[user[:password]@]host[:port]/[path]]

Options:
  -script=FILE      execute commands from FILE ('-' reads stdin)
  -command=CMD      execute commands (separate several with ';')
  -literal          with -command, treat %...% in paths as literal text
  -rawsettings[=N]  session defaults as N NAME=VALUE arguments (also -shell)
  -hostkey=KEY      pin the host key (fingerprint or '*' for this connection)
  -password=PWD     password to use (prefer the LINSCP_PASSWORD variable)
  -privatekey=FILE  OpenSSH/PEM or PPK v2/v3 private key for authentication
  -passphrase=PWD   private-key passphrase (avoid exposing it in process lists)
  -convertkey=FILE  convert a PPK v2/v3 key (requires -output=FILE)
  -output=FILE      destination PEM file for -convertkey (no overwrite)
  -username=NAME    user name to authenticate with
  -port=NUMBER      port to connect to (default 22)
  -timeout=SECS     connection timeout in seconds (default 15)
  -clientcert=FILE  TLS client certificate for FTPS and WebDAVS
  -implicit[=on|off] / -explicit[=ON|OFF]  the TLS mode of an FTP session
  -passive[=on|off] choose the FTP data connection policy
  -log=FILE         log the session to FILE
  -loglevel=LEVEL   logging level: -1 reduced, 0 normal, 1 debug, 2 debug2
  -logsize=[N*]SIZE rotate the log at SIZE bytes, keeping N older files
  -xmllog=FILE      write an XML log of every command and operation to
                    FILE (upstream session format; passwords masked)
  -batch            never ask, abort instead
  -parameter VAL..  script parameters, for %1% .. %9%, %TIMESTAMP% and
                    %ENVIRONMENT% expansion in the commands
  -gui              launch the graphical Commander desktop interface
  -shell            open an interactive shell on the site given as
                    the argument; stdin and stdout are the raw byte
                    pipe of the shell, as the graphical client's
                    embedded terminal uses it
  -server           command server of the graphical client: one command
                    per line on stdin, 'LSCP-RESULT <code>' after each
  -verbose          print SSH event log messages
  -version          print the version and exit
  -help             print this help and exit

Commands:
  open SITE         connect to a site (sftp://user@host:port/path)
  close [INDEX]     disconnect the open session, or session INDEX
  cd DIR            change the remote directory
  pwd               print the remote directory
  ls [-al1] [DIR]   list remote files
  versions [OBJECT] list S3 object versions and delete markers
  lcd DIR           change the local directory
  lpwd              print the local directory
  lls [DIR[/MASK]]  list local files with date, time and size
  get [opts] REMOTE [LOCAL]  download file(s) or directories
  put [opts] LOCAL [REMOTE]  upload file(s) or directories
                    both: -r -delete -neweronly -resume -append -preservetime
                    -speed=KB -transfer=binary|ascii|automatic -filemask=MASK
                    -resumesupport=on|off|KB -rawtransfersettings[=N]
                    -permissions[=OCTAL] -nopermissions
                    -versionid=ID (S3 get/rm; versions lists history)
  synchronize local|remote|both [LOCAL [REMOTE]] [switches]
                    synchronize directories: -delete -preview
                    -nonrecursive -filemask=MASK
                    -criteria=time|size|checksum|either|both|none
  keepuptodate [LOCAL [REMOTE]] [switches]
                    reflect local changes on the remote side; the local
                    tree is watched, -interval=SECS polls instead
                    (-count=N bounds the passes; Ctrl-C stops watching)
  edit FILE         edit a remote file in an external editor
                    (-force, -keep, -editor=COMMAND)
  session [INDEX]   list the open sessions, or switch to INDEX
  sessions [NAME]   list stored sites; NAME opens one, and
                    (also: sessions export FILE, sessions import FILE)
  savesession NAME  store the current connection as a named session
                    (-preset=NAME stores its transfer preset)
  rmsession NAME    forget a stored session
  presets           list the transfer presets; savepreset NAME K=V...
                    stores one, rmspreset NAME removes one
  rm FILE           remove remote file(s)
  rmdir DIR         remove a remote directory
  mkdir [-parents] DIR  create a remote directory (parents if requested)
  mv FROM TO        move/rename a remote file
  chmod MODE FILE [FILE...] [-recursive]
                    change remote permissions; MODE is octal (644) or
                    symbolic (u+x, a=r,go-w)
  copyid [KEYFILE]  add the public key of KEYFILE, or of the session key,
                    to the server's ~/.ssh/authorized_keys
  stat FILE         print the listing line of a remote path
  attr FILE         print remote file attributes, key/value
  terminal          open an interactive shell on the server
  echo [MESSAGE]    display text message
  option confirm|batch|resume|editor|editmaxsize|transfer|preset VALUE
                    configure session options (preset NAME makes a
                    transfer preset the default, 'option preset off' clears)
  binary / ascii    select the transfer mode of the following commands
  help              list the commands (alias: man)
  exit              end the session
";

fn is_option_name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'?' || b == b'_'
}

/// Normalizes `/option=value`, `/option:value`, and `-option:value` command-line
/// switches to `-option=value` without touching POSIX paths (`/home/user`, `/var/log/a`).
pub fn normalize_cli_switch(arg: &str) -> String {
    let mut dummy = false;
    normalize_option_token(arg, &mut dummy)
}

fn normalize_option_token(raw: &str, no_more_options: &mut bool) -> String {
    if *no_more_options || raw.is_empty() {
        return raw.to_string();
    }
    if raw == "--" {
        *no_more_options = true;
        return String::new();
    }
    if raw == "--serve-http" {
        return raw.to_string();
    }
    let bytes = raw.as_bytes();
    if bytes[0] != b'-' && bytes[0] != b'/' {
        return raw.to_string();
    }
    let prefix_len = if raw.starts_with("--") { 2 } else { 1 };
    let mut idx = prefix_len;
    while idx < bytes.len() && is_option_name_char(bytes[idx]) {
        idx += 1;
    }
    let name = &raw[prefix_len..idx];
    if name.is_empty() {
        return raw.to_string();
    }
    let lower_name = name.to_ascii_lowercase();
    if idx < bytes.len() && (bytes[idx] == b'=' || bytes[idx] == b':') {
        let val = &raw[idx + 1..];
        return format!("-{lower_name}={val}");
    }
    if idx < bytes.len() {
        // Contains `/` or other path characters (e.g., `/home/user`)
        return raw.to_string();
    }
    if bytes[0] == b'-' {
        return format!("-{lower_name}");
    }
    // Slash-prefixed valueless switch: only accept known valueless switches so `/site` stays positional
    const VALUELESS_SLASH: &[&str] = &[
        "batch",
        "gui",
        "h",
        "help",
        "?",
        "literal",
        "server",
        "shell",
        "verbose",
        "version",
        "xmlgroups",
        "implicit",
        "explicit",
        "passive",
        "parameter",
        "parameters",
        "rawsettings",
        "defaults",
        "batchsettings",
    ];
    if VALUELESS_SLASH.contains(&lower_name.as_str()) {
        if lower_name == "?" {
            "-help".to_string()
        } else {
            format!("-{lower_name}")
        }
    } else {
        raw.to_string()
    }
}

fn parse_on_off_switch(val: Option<&str>) -> Option<bool> {
    let Some(text) = val else {
        return Some(true);
    };
    if text.is_empty() || text.eq_ignore_ascii_case("on") {
        return Some(true);
    }
    if text.eq_ignore_ascii_case("off") {
        return Some(false);
    }
    if let Ok(n) = text.parse::<i64>() {
        return Some(n != 0);
    }
    None
}

fn parse_loglevel(raw: &str) -> Option<(i32, bool)> {
    let (num_part, sensitive) = if let Some(stripped) = raw.strip_suffix('*') {
        (stripped, true)
    } else {
        (raw, false)
    };
    let lvl: i32 = num_part.parse().ok()?;
    if (-1..=2).contains(&lvl) {
        Some((lvl, sensitive))
    } else {
        None
    }
}

fn format_usage(locale: &str) -> String {
    translate_with(
        CatalogDomain::Cli,
        locale,
        USAGE_TEMPLATE,
        &[("version", PRODUCT_VERSION)],
    )
}

fn print_err(msg: &str) {
    let _ = writeln!(std::io::stderr(), "{msg}");
    let _ = std::io::stderr().flush();
}

#[tokio::main]
async fn main() -> ExitCode {
    // Debug for window test
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open("/tmp/linscp-gui-debug2.log") {
        use std::io::Write as _;
        let _ = writeln!(f, "main start exe={:?} args={:?}", std::env::current_exe().unwrap_or_default().display(), std::env::args().collect::<Vec<_>>());
    }
    ensure_default_sigint();
    let code = run_cli().await;
    if code == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from((code.clamp(1, 255)) as u8)
    }
}

async fn run_cli() -> i32 {
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    // Debug for window test
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open("/tmp/linscp-gui-debug2.log") {
        use std::io::Write as _;
        let _ = writeln!(f, "run_cli raw_args={:?} exe={:?}", raw_args, std::env::current_exe().unwrap_or_default().display());
    }
    let locale = select_cli_locale_from_env();
    let bin_name = std::env::args().next().unwrap_or_default();
    let is_gui_bin = bin_name.contains("linscp-gui");

    // File-manager integration standalone actions (do not start server)
    if raw_args.iter().any(|a| a == "--install-shell-integration") {
        let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("linscp-gui"));
        match install_shell_integration(&exe) {
            Ok(results) => {
                for (mgr, path, outcome) in results {
                    println!("{mgr}: {path} ({outcome})");
                }
                return 0;
            }
            Err(e) => {
                print_err(&format!("Cannot change the file-manager integration: {e}"));
                return 1;
            }
        }
    }
    if raw_args.iter().any(|a| a == "--uninstall-shell-integration") {
        match uninstall_shell_integration() {
            Ok(results) => {
                for (mgr, path, outcome) in results {
                    println!("{mgr}: {path} ({outcome})");
                }
                return 0;
            }
            Err(e) => {
                print_err(&format!("Cannot change the file-manager integration: {e}"));
                return 1;
            }
        }
    }
    // Shell upload staging: `linscp-gui --shell-upload FILES...`
    if let Some(pos) = raw_args.iter().position(|a| a == "--shell-upload") {
        let files: Vec<PathBuf> = raw_args[pos + 1..].iter().map(PathBuf::from).collect();
        if files.is_empty() {
            print_err("--shell-upload was given no files.");
            return 2;
        }
        let cfg_dir = std::env::var("LINSCP_CONFIG_DIR")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(default_config_dir);
        match linscp_service::ops::record_shell_upload_manifest(&cfg_dir, &files) {
            Ok(manifest) => {
                let count = manifest.get("items").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(files.len());
                println!("{count} file(s) from the file manager held for LinSCP; the GUI will offer to upload them.");
                // After staging, continue to start the GUI server and open browser (like Python)
                // Fall through to serve-http handling below
            }
            Err(e) => {
                print_err(&format!("Cannot accept those files: {e}"));
                return 2;
            }
        }
    }

    // Standalone HTTP server mode (`linscp --serve-http` or `linscp-gui` binary)
    let serve_http_requested = raw_args.iter().any(|a| a == "--serve-http") || is_gui_bin;
    if serve_http_requested {
        // Parse serve-http options
        let mut host = "127.0.0.1".to_string();
        let mut port: u16 = 0;
        let mut allow_hosts: Vec<String> = Vec::new();
        let mut allow_any = false;
        let mut print_token = false;
        let mut open_browser = is_gui_bin;
        let mut explicit_port = false;
        for a in &raw_args {
            if let Some(v) = a.strip_prefix("--host=") {
                host = v.to_string();
            } else if let Some(v) = a.strip_prefix("--port=") {
                if let Ok(p) = v.parse::<u16>() {
                    port = p;
                    explicit_port = true;
                }
            } else if a == "--allow-any-host" {
                allow_any = true;
            } else if let Some(v) = a.strip_prefix("--allow-host=") {
                allow_hosts.push(v.to_ascii_lowercase());
            } else if a == "--print-token" {
                print_token = true;
            } else if a == "--open-browser" {
                open_browser = true;
            } else if a == "--serve-http" {
                // bare flag: port may be next arg if numeric and not already parsed
            }
        }
        // Handle `linscp --serve-http 8080` (port as separate arg)
        if !explicit_port {
            if let Some(pos) = raw_args.iter().position(|a| a == "--serve-http") {
                if let Some(next) = raw_args.get(pos + 1) {
                    if let Ok(p) = next.parse::<u16>() {
                        // Ensure next is not another option
                        if !next.starts_with('-') {
                            port = p;
                        }
                    }
                }
            }
        }
        let mut cfg = HttpServerConfig::loopback(port);
        // Override host if requested
        if host != "127.0.0.1" {
            if let Ok(addr) = format!("{host}:{port}").parse::<SocketAddr>() {
                cfg.bind_addr = addr;
            } else if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                cfg.bind_addr = SocketAddr::new(ip, port);
            }
        }
        if allow_any {
            cfg.allowed_hosts.insert("*".to_string());
        }
        for h in allow_hosts {
            cfg.allowed_hosts.insert(h);
        }
        // Also allow the bind host itself (like Python does)
        if host != "0.0.0.0" && host != "::" && host != "::0" {
            cfg.allowed_hosts.insert(host.to_ascii_lowercase());
        }
        let token = cfg.bearer_token.clone();
        let listener = match tokio::net::TcpListener::bind(cfg.bind_addr).await {
            Ok(l) => l,
            Err(e) => {
                print_err(&format!("Failed to bind HTTP server: {e}"));
                return 1;
            }
        };
        let local_addr = match listener.local_addr() {
            Ok(a) => a,
            Err(e) => {
                print_err(&format!("Failed to query local address: {e}"));
                return 1;
            }
        };
        // Python-compatible output
        println!("LinSCP Commander GUI running at http://{local_addr}/");
        if let Some(dist) = cfg.ui_dist.as_ref() {
            println!("Serving web client from: {}", dist.display());
        }
        println!("LinSCP core binary: {}", std::env::current_exe().unwrap_or_else(|_| PathBuf::from("linscp")).display());
        if print_token || is_gui_bin {
            println!("Token: {token}");
        }
        println!("LINSCP_HTTP_URL=http://{local_addr}");
        println!("LINSCP_HTTP_TOKEN={token}");
        let _ = std::io::stdout().flush();
        if open_browser {
            let url = format!("http://{local_addr}/");
            if let Err(e) = open_url_in_browser(&url) {
                print_err(&format!("Not opening a browser: {e}."));
                println!("Open {url} in a browser of your own.");
            }
        }
        let state = Arc::new(HttpAppState {
            service: CommanderService::default(),
            config: cfg,
        });
        if let Err(e) = serve(listener, state).await {
            print_err(&format!("HTTP server error: {e}"));
            return 1;
        }
        return 0;
    }

    let mut config_dir = std::env::var("LINSCP_CONFIG_DIR")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(linscp_platform::default_config_dir);

    let mut defaults_hostkey = String::new();
    let mut defaults_password: Option<String> = None;
    let mut defaults_privatekey: Option<String> = None;
    let mut defaults_passphrase: Option<String> = None;
    let mut defaults_username: Option<String> = None;
    let mut defaults_port: Option<u16> = None;
    let mut defaults_timeout: Option<u64> = None;
    let mut defaults_clientcert: Option<String> = None;
    let mut defaults_sessionname: Option<String> = None;
    let mut defaults_ftps_mode: Option<u8> = None;
    let mut defaults_ftp_pasv_mode: Option<bool> = None;
    let mut defaults_raw_pairs: Vec<String> = Vec::new();

    let mut script_specified = false;
    let mut script_file = String::new();
    let mut command_specified = false;
    let mut command_text = String::new();
    let mut literal_command = false;
    let mut convert_key_specified = false;
    let mut convert_key_input = String::new();
    let mut convert_output_specified = false;
    let mut convert_key_output = String::new();

    let mut log_file: Option<PathBuf> = None;
    let mut xml_log_file: Option<PathBuf> = None;
    let mut log_level: i32 = 0;
    let mut log_level_given = false;
    let mut log_sensitive = false;
    let mut verbose = false;
    let mut log_rotation: Option<LogRotationPolicy> = None;

    let mut batch: Option<bool> = None;
    let mut launch_gui = false;
    let mut server_mode = false;
    let mut shell_mode = false;
    let mut show_help = false;
    let mut show_version = false;

    let mut parameters: Vec<String> = Vec::new();
    let mut collecting_parameters = false;
    let mut no_more_options = false;
    let mut url = String::new();

    let mut i = 0usize;
    while i < raw_args.len() {
        if collecting_parameters {
            parameters.push(raw_args[i].clone());
            i += 1;
            continue;
        }
        let normalized = normalize_option_token(&raw_args[i], &mut no_more_options);
        if normalized.is_empty() {
            // `--` sentinel
            i += 1;
            continue;
        }
        if no_more_options {
            if url.is_empty() {
                url = normalized;
            } else {
                print_err(&translate_with(
                    CatalogDomain::Cli,
                    &locale,
                    "Unexpected argument '{argument}'.",
                    &[("argument", &normalized)],
                ));
                return 1;
            }
            i += 1;
            continue;
        }

        let arg = normalized.as_str();
        if arg == "-parameter" || arg == "-parameters" {
            collecting_parameters = true;
        } else if let Some(val) = arg.strip_prefix("-parameter=") {
            parameters.push(val.to_string());
        } else if let Some(val) = arg.strip_prefix("-script=") {
            script_specified = true;
            script_file = if val == "-" {
                "-".to_string()
            } else {
                expand_tilde(val)
            };
        } else if let Some(val) = arg.strip_prefix("-command=") {
            command_specified = true;
            command_text = val.to_string();
        } else if arg == "-literal" {
            literal_command = true;
        } else if arg == "-rawsettings" || arg.starts_with("-rawsettings=") {
            let explicit_count: Option<usize> = if let Some(c_str) = arg.strip_prefix("-rawsettings=")
            {
                let Ok(cnt) = c_str.parse::<usize>() else {
                    print_err(translate(
                        CatalogDomain::Cli,
                        &locale,
                        "-rawsettings requires a positive setting count.",
                    ));
                    return 1;
                };
                if cnt == 0 || cnt > raw_args.len() {
                    print_err(translate(
                        CatalogDomain::Cli,
                        &locale,
                        "-rawsettings requires a positive setting count.",
                    ));
                    return 1;
                }
                Some(cnt)
            } else {
                None
            };

            let mut taken = 0usize;
            while i + 1 < raw_args.len() && explicit_count.is_none_or(|c| taken < c) {
                let next_s = &raw_args[i + 1];
                if next_s.is_empty() || next_s.starts_with('-') || !next_s.contains('=') {
                    break;
                }
                // Validate immediately across protocol families so unknown keys or bad values
                // fail right away while protocol-specific settings (e.g. Ftps=1) remain usable
                // with `open ftp://...` inside `-command`/`-script`.
                let mut valid_on_any = false;
                let mut first_err = String::new();
                for proto in [
                    ProtocolScheme::Sftp,
                    ProtocolScheme::Ftp,
                    ProtocolScheme::Dav,
                    ProtocolScheme::S3,
                ] {
                    let mut probe = ParsedSiteSpec::default();
                    probe.session.protocol = proto;
                    match apply_raw_settings(&mut probe, std::slice::from_ref(next_s)) {
                        Ok(()) => {
                            valid_on_any = true;
                            break;
                        }
                        Err(err) if first_err.is_empty() => first_err = err,
                        Err(_) => {}
                    }
                }
                if !valid_on_any {
                    print_err(&first_err);
                    return 1;
                }
                defaults_raw_pairs.push(next_s.clone());
                i += 1;
                taken += 1;
            }
            if taken == 0 || explicit_count.is_some_and(|c| taken != c) {
                print_err(translate(
                    CatalogDomain::Cli,
                    &locale,
                    "-rawsettings requires NAME=VALUE arguments matching its count.",
                ));
                return 1;
            }
        } else if let Some(val) = arg.strip_prefix("-ini=") {
            if !val.eq_ignore_ascii_case("nul") && !val.is_empty() {
                let p = PathBuf::from(expand_tilde(val));
                config_dir = if p.extension().is_some() {
                    p.parent().map(Path::to_path_buf).unwrap_or(p)
                } else {
                    p
                };
            }
        } else if let Some(val) = arg.strip_prefix("-hostkey=") {
            defaults_hostkey = val.to_string();
        } else if let Some(val) = arg.strip_prefix("-password=") {
            defaults_password = Some(val.to_string());
        } else if let Some(val) = arg.strip_prefix("-privatekey=") {
            defaults_privatekey = Some(expand_tilde(val));
        } else if let Some(val) = arg.strip_prefix("-passphrase=") {
            defaults_passphrase = Some(val.to_string());
        } else if let Some(val) = arg.strip_prefix("-convertkey=") {
            convert_key_specified = true;
            convert_key_input = val.to_string();
        } else if let Some(val) = arg.strip_prefix("-output=") {
            convert_output_specified = true;
            convert_key_output = val.to_string();
        } else if let Some(val) = arg.strip_prefix("-username=") {
            defaults_username = Some(val.to_string());
        } else if let Some(val) = arg.strip_prefix("-port=") {
            let Ok(p) = val.parse::<u16>() else {
                print_err(&translate_with(
                    CatalogDomain::Cli,
                    &locale,
                    "Invalid port number '{value}' (expected 1 through 65535).",
                    &[("value", val)],
                ));
                return 1;
            };
            if p == 0 {
                print_err(&translate_with(
                    CatalogDomain::Cli,
                    &locale,
                    "Invalid port number '{value}' (expected 1 through 65535).",
                    &[("value", val)],
                ));
                return 1;
            }
            defaults_port = Some(p);
        } else if let Some(val) = arg.strip_prefix("-timeout=") {
            let max_secs = (i32::MAX / 1000) as u64;
            let Ok(secs) = val.parse::<u64>() else {
                print_err(&translate_with(
                    CatalogDomain::Cli,
                    &locale,
                    "Invalid timeout '{value}' (expected a positive number of seconds).",
                    &[("value", val)],
                ));
                return 1;
            };
            if secs == 0 || secs > max_secs {
                print_err(&translate_with(
                    CatalogDomain::Cli,
                    &locale,
                    "Invalid timeout '{value}' (expected a positive number of seconds).",
                    &[("value", val)],
                ));
                return 1;
            }
            defaults_timeout = Some(secs);
        } else if let Some(val) = arg.strip_prefix("-log=") {
            log_file = Some(PathBuf::from(expand_tilde(val)));
        } else if let Some(val) = arg.strip_prefix("-clientcert=") {
            defaults_clientcert = Some(expand_tilde(val));
        } else if let Some(val) = arg.strip_prefix("-sessionname=") {
            defaults_sessionname = Some(val.to_string());
        } else if arg == "-implicit" || arg.starts_with("-implicit=") {
            let val = arg.strip_prefix("-implicit=");
            let Some(enabled) = parse_on_off_switch(val) else {
                print_err(translate(
                    CatalogDomain::Cli,
                    &locale,
                    "The value of '-implicit' must be on or off (a number other than zero means on).",
                ));
                return 1;
            };
            defaults_ftps_mode = Some(if enabled { 1 } else { 0 });
        } else if arg == "-explicit"
            || arg.starts_with("-explicit=")
            || arg == "-explicittls"
            || arg.starts_with("-explicittls=")
        {
            let val = arg
                .strip_prefix("-explicit=")
                .or_else(|| arg.strip_prefix("-explicittls="));
            let Some(enabled) = parse_on_off_switch(val) else {
                print_err(translate(
                    CatalogDomain::Cli,
                    &locale,
                    "The value of '-explicit' must be on or off (a number other than zero means on).",
                ));
                return 1;
            };
            defaults_ftps_mode = Some(if enabled { 3 } else { 0 });
        } else if arg == "-passive" || arg.starts_with("-passive=") {
            let val = arg.strip_prefix("-passive=");
            let Some(enabled) = parse_on_off_switch(val) else {
                print_err(translate(
                    CatalogDomain::Cli,
                    &locale,
                    "The value of '-passive' must be on or off (a number other than zero means on).",
                ));
                return 1;
            };
            defaults_ftp_pasv_mode = Some(enabled);
        } else if let Some(val) = arg.strip_prefix("-loglevel=") {
            let Some((lvl, sens)) = parse_loglevel(val) else {
                print_err(&translate_with(
                    CatalogDomain::Cli,
                    &locale,
                    "Invalid log level '{value}' (expected -1, 0, 1 or 2).",
                    &[("value", val)],
                ));
                return 1;
            };
            log_level = lvl;
            log_level_given = true;
            log_sensitive = sens;
        } else if let Some(val) = arg.strip_prefix("-logsize=") {
            match LogRotationPolicy::parse(val) {
                Ok(pol) => log_rotation = Some(pol),
                Err(err) => {
                    print_err(translate(CatalogDomain::Cli, &locale, &err));
                    return 1;
                }
            }
        } else if let Some(val) = arg.strip_prefix("-xmllog=") {
            xml_log_file = Some(PathBuf::from(expand_tilde(val)));
        } else if arg == "-xmlgroups" || arg == "-defaults" || arg.starts_with("-batchsettings=") {
            // Accepted compatibility switches
        } else if arg == "-batch" || arg == "-batch=on" {
            batch = Some(true);
        } else if arg == "-batch=off" {
            batch = Some(false);
        } else if arg == "-gui" {
            launch_gui = true;
        } else if arg == "-server" {
            server_mode = true;
        } else if arg == "-shell" {
            shell_mode = true;
        } else if arg == "-verbose" || arg == "-v" {
            verbose = true;
        } else if arg == "-version" {
            show_version = true;
        } else if arg == "-help" || arg == "-h" {
            show_help = true;
        } else if arg.starts_with('-') && arg.len() > 1 {
            // Preserve the user's raw option text in the error message
            print_err(&translate_with(
                CatalogDomain::Cli,
                &locale,
                "Unknown option '{argument}'.",
                &[("argument", &raw_args[i])],
            ));
            print_err(&format_usage(&locale));
            return 1;
        } else if url.is_empty() {
            url = raw_args[i].clone();
        } else {
            print_err(&translate_with(
                CatalogDomain::Cli,
                &locale,
                "Unexpected argument '{argument}'.",
                &[("argument", &raw_args[i])],
            ));
            return 1;
        }
        i += 1;
    }

    if launch_gui && (convert_key_specified || convert_output_specified) {
        print_err(translate(
            CatalogDomain::Cli,
            &locale,
            "Key conversion syntax: linscp -convertkey=INPUT.ppk -output=OUTPUT.pem [-passphrase=PASSPHRASE].",
        ));
        return 1;
    }
    // Debug for window test
    if launch_gui {
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open("/tmp/linscp-gui-debug2.log") {
            use std::io::Write as _;
            let _ = writeln!(f, "main launch_gui true exe={:?} args={:?}", std::env::current_exe().unwrap_or_default().display(), std::env::args().collect::<Vec<_>>());
        }
        if let Err(err) = launch_gui_application() {
            print_err(&err);
            return 1;
        }
        return 0;
    }

    if show_version {
        println!(
            "LinSCP {PRODUCT_VERSION} (russh 0.65.0; locales: {})",
            supported_locales().join(", ")
        );
        return 0;
    }
    if show_help {
        println!("{}", format_usage(&locale));
        return 0;
    }

    if convert_key_specified {
        if convert_key_input.is_empty()
            || convert_key_output.is_empty()
            || !url.is_empty()
            || script_specified
            || command_specified
            || server_mode
            || shell_mode
        {
            print_err(translate(
                CatalogDomain::Cli,
                &locale,
                "Key conversion syntax: linscp -convertkey=INPUT.ppk -output=OUTPUT.pem [-passphrase=PASSPHRASE].",
            ));
            return 1;
        }
        return run_convert_key(
            &expand_tilde(&convert_key_input),
            &expand_tilde(&convert_key_output),
            defaults_passphrase.as_deref(),
            batch.unwrap_or(false),
            &locale,
        );
    }
    if convert_output_specified {
        print_err(translate(
            CatalogDomain::Cli,
            &locale,
            "-output is only valid with -convertkey.",
        ));
        return 1;
    }

    if server_mode && (script_specified || command_specified) {
        print_err(translate(
            CatalogDomain::Cli,
            &locale,
            "-server reads commands from standard input and cannot be combined with -script or -command.",
        ));
        return 1;
    }
    if shell_mode && (script_specified || command_specified || server_mode) {
        print_err(translate(
            CatalogDomain::Cli,
            &locale,
            "-shell opens an interactive shell on the site given as the argument and cannot be combined with -script, -command or -server.",
        ));
        return 1;
    }
    if shell_mode && url.is_empty() {
        print_err(translate(
            CatalogDomain::Cli,
            &locale,
            "-shell requires a site URL, for example sftp://user@example.com/.",
        ));
        return 1;
    }
    if script_specified && command_specified {
        print_err(translate(
            CatalogDomain::Cli,
            &locale,
            "Choose either -script or -command, not both.",
        ));
        return 1;
    }
    if literal_command && !command_specified {
        print_err(translate(
            CatalogDomain::Cli,
            &locale,
            "-literal requires -command; scripts and interactive commands still expand parameters.",
        ));
        return 1;
    }
    if script_specified && script_file.is_empty() {
        print_err(translate(
            CatalogDomain::Cli,
            &locale,
            "-script requires a file name (use -script=- for standard input).",
        ));
        return 1;
    }
    if command_specified && command_text.is_empty() {
        print_err(translate(
            CatalogDomain::Cli,
            &locale,
            "-command requires at least one command.",
        ));
        return 1;
    }
    if (script_specified || command_specified) && !url.is_empty() {
        print_err(translate(
            CatalogDomain::Cli,
            &locale,
            "A site URL cannot be combined with -script or -command; put an 'open' command in the script instead.",
        ));
        return 1;
    }

    let effective_log_level = if log_level_given {
        log_level
    } else if verbose {
        1
    } else {
        0
    };

    let mut logger = match SessionLogger::open(
        log_file.as_deref(),
        effective_log_level,
        log_sensitive,
        log_rotation,
        xml_log_file.as_deref(),
        true,
        &url,
    ) {
        Ok(l) => l,
        Err(reason) => {
            if reason.contains("XML") {
                let p_str = xml_log_file
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default();
                print_err(&translate_with(
                    CatalogDomain::Cli,
                    &locale,
                    "Cannot open the XML log file '{path}': {reason}",
                    &[("path", &p_str), ("reason", &reason)],
                ));
            } else {
                let p_str = log_file
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default();
                print_err(&translate_with(
                    CatalogDomain::Cli,
                    &locale,
                    "Cannot open the log file '{path}': {reason}",
                    &[("path", &p_str), ("reason", &reason)],
                ));
            }
            return 1;
        }
    };

    let apply_cli_defaults = |spec: &mut ParsedSiteSpec| -> Result<(), String> {
        if !defaults_hostkey.is_empty() && spec.session.hostkey.is_empty() {
            spec.session.hostkey = defaults_hostkey.clone();
        }
        if let Some(ref pw) = defaults_password {
            spec.session.password = Some(pw.clone());
        }
        if let Some(ref pk) = defaults_privatekey {
            spec.session.keyfile = Some(pk.clone());
        }
        if let Some(ref pp) = defaults_passphrase {
            spec.passphrase = Some(pp.clone());
        }
        if let Some(ref u) = defaults_username {
            spec.session.username = u.clone();
        }
        if let Some(p) = defaults_port {
            spec.session.port = p;
        }
        if let Some(t) = defaults_timeout {
            spec.timeout_secs = t;
        }
        if let Some(ref cc) = defaults_clientcert {
            spec.raw_fields
                .insert("tls_certificate_file".to_string(), cc.clone());
        }
        if let Some(ref sn) = defaults_sessionname {
            if !sn.is_empty() {
                spec.session_label = sn.clone();
                spec.explicit_session_name = Some(sn.clone());
            }
        }
        if let Some(ftps) = defaults_ftps_mode {
            spec.raw_fields
                .insert("ftps".to_string(), ftps.to_string());
        }
        if let Some(pasv) = defaults_ftp_pasv_mode {
            spec.raw_fields.insert(
                "ftp_pasv_mode".to_string(),
                (if pasv { "1" } else { "0" }).to_string(),
            );
        }
        if !defaults_raw_pairs.is_empty() {
            apply_raw_settings(spec, &defaults_raw_pairs)?;
        }
        apply_env_credential_fallbacks(spec);
        Ok(())
    };

    if shell_mode {
        let mut spec = match resolve_site_arg(&url, &config_dir) {
            Ok(s) => s,
            Err(e) => {
                print_err(&e);
                return 1;
            }
        };
        if !is_ssh_scheme(spec.session.protocol) {
            let proto = spec.session.protocol.as_str();
            print_err(&translate_with(
                CatalogDomain::Cli,
                &locale,
                "A shell is only available for SSH (sftp:// or scp://) sessions, not for '{protocol}'.",
                &[("protocol", proto)],
            ));
            return 1;
        }
        if let Err(e) = apply_cli_defaults(&mut spec) {
            print_err(&e);
            return 1;
        }
        let is_batch = batch.unwrap_or(false);
        let interactive = !is_batch && stdin_is_terminal();
        let collected_events: Arc<std::sync::Mutex<Vec<String>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink_events = Arc::clone(&collected_events);
        let ssh_sink: linscp_proto::ssh::SshEventLogger = Arc::new(move |msg: &str| {
            sink_events
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(msg.to_string());
        });
        let connect_res = connect_ssh_for_shell(
            &spec,
            &config_dir,
            interactive,
            interactive,
            &locale,
            effective_log_level,
            Some(ssh_sink),
        )
        .await;
        for ev in collected_events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
        {
            logger.log_event(&ev);
        }
        let (conn, jump) = match connect_res {
            Ok(pair) => pair,
            Err(e) => {
                logger.finish();
                print_err(&e);
                return 1;
            }
        };
        let res = run_pty_shell_session(&conn).await;
        let _ = conn.disconnect().await;
        if let Some(j) = jump {
            let _ = j.close().await;
        }
        logger.finish();
        return match res {
            Ok(code) => code,
            Err(e) => {
                print_err(&e);
                1
            }
        };
    }

    let initial_batch_mode = if server_mode {
        BatchMode::Continue
    } else if let Some(explicit_batch) = batch {
        if explicit_batch {
            BatchMode::Abort
        } else {
            BatchMode::Off
        }
    } else if script_specified || command_specified {
        BatchMode::Abort
    } else {
        BatchMode::Off
    };

    let cli_defaults = CliSessionDefaults {
        hostkey: (!defaults_hostkey.is_empty()).then_some(defaults_hostkey.clone()),
        password: defaults_password.clone(),
        privatekey: defaults_privatekey.clone(),
        passphrase: defaults_passphrase.clone(),
        username: defaults_username.clone(),
        port: defaults_port,
        timeout_secs: defaults_timeout,
        clientcert: defaults_clientcert.clone(),
        sessionname: defaults_sessionname.clone(),
        ftps_mode: defaults_ftps_mode,
        ftp_pasv_mode: defaults_ftp_pasv_mode,
        raw_pairs: defaults_raw_pairs.clone(),
    };

    let run_cfg = ScriptRunConfig {
        config_dir: config_dir.clone(),
        locale: locale.clone(),
        batch_mode: initial_batch_mode,
        confirm: !server_mode,
        echo: false,
        log_level: effective_log_level,
        server_mode,
        parameters,
        cli_defaults,
    };

    let mut interp = ScriptInterpreter::new(run_cfg, logger);

    if !url.is_empty() && !server_mode {
        match resolve_site_arg(&url, &config_dir) {
            Ok(mut spec) => {
                if let Err(e) = apply_cli_defaults(&mut spec) {
                    print_err(&e);
                    interp.shutdown().await;
                    return 1;
                }
                if interp.connect_initial_site(spec).await.is_err()
                    && initial_batch_mode.aborts_script()
                {
                    interp.shutdown().await;
                    return 1;
                }
            }
            Err(e) => {
                print_err(&e);
                interp.shutdown().await;
                return 1;
            }
        }
    }

    let exit_code = if server_mode {
        interp.run_server_loop().await
    } else if script_specified {
        if script_file == "-" {
            interp.run_reader(BufReader::new(std::io::stdin())).await
        } else {
            let file = match std::fs::File::open(&script_file) {
                Ok(f) => f,
                Err(e) => {
                    let reason = e.to_string();
                    print_err(&translate_with(
                        CatalogDomain::Cli,
                        &locale,
                        "Cannot open the script file '{path}': {reason}",
                        &[("path", &script_file), ("reason", &reason)],
                    ));
                    interp.shutdown().await;
                    return 1;
                }
            };
            interp.run_reader(BufReader::new(file)).await
        }
    } else if command_specified {
        interp.run_command_string(&command_text, literal_command).await
    } else if !stdin_is_terminal() && url.is_empty() {
        print_err(translate(
            CatalogDomain::Cli,
            &locale,
            "No input. Pass -script, -command or a site URL, or run interactively from a terminal.",
        ));
        print_err(&format_usage(&locale));
        1
    } else {
        interp.run_interactive_repl().await
    };

    interp.shutdown().await;
    exit_code
}

fn resolve_site_arg(target: &str, config_dir: &Path) -> Result<ParsedSiteSpec, String> {
    if target.contains("://") {
        parse_site_url(target)
    } else {
        let vault = DefaultOsVault;
        let store = SessionStore::load_from_dir(config_dir, &vault)?;
        let Some(site) = store.find(target) else {
            return Err(format!(
                "'{target}' is neither a session URL (scheme://host) nor a stored session."
            ));
        };
        site_spec_from_stored(site)
    }
}

fn run_convert_key(
    input_path: &str,
    output_path: &str,
    initial_passphrase: Option<&str>,
    is_batch: bool,
    locale: &str,
) -> i32 {
    let out_p = Path::new(output_path);
    if out_p.exists() {
        print_err(&format!(
            "Refusing to overwrite existing output file '{output_path}'."
        ));
        return 1;
    }
    let raw = match std::fs::read(input_path) {
        Ok(b) => b,
        Err(e) => {
            print_err(&format!("Cannot read private key '{input_path}': {e}"));
            return 1;
        }
    };
    let Ok(raw_text) = std::str::from_utf8(&raw) else {
        print_err(&format!(
            "Invalid PPK key file '{input_path}': not valid UTF-8 text."
        ));
        return 1;
    };
    let source_is_encrypted = raw_text
        .lines()
        .any(|l| l.trim_end_matches('\r') == "Encryption: aes256-cbc");

    let mut pass = initial_passphrase.unwrap_or("").to_string();
    let mut last_err = String::new();
    for attempt in 0..3 {
        let out_pass = if source_is_encrypted && !pass.is_empty() {
            Some(pass.as_str())
        } else {
            None
        };
        match ppk_to_pkcs8_pem(raw_text, &pass, out_pass) {
            Ok(pkcs8_pem) => {
                if let Err(e) = write_exclusive_private_file(out_p, pkcs8_pem.as_bytes()) {
                    print_err(&format!("Cannot write '{output_path}': {e}"));
                    return 1;
                }
                println!(
                    "{}",
                    translate_with(
                        CatalogDomain::Cli,
                        locale,
                        "Converted key written to '{path}'.",
                        &[("path", output_path)],
                    )
                );
                return 0;
            }
            Err(e) => {
                last_err = e.to_string();
                let needs_pass = last_err.contains("passphrase")
                    || last_err.contains("encrypted")
                    || last_err.contains("MAC")
                    || last_err.contains("integrity");
                if !needs_pass
                    || initial_passphrase.is_some()
                    || is_batch
                    || !stdin_is_terminal()
                    || attempt == 2
                {
                    break;
                }
                let prompt = translate(CatalogDomain::Cli, locale, "PPK key passphrase: ");
                match read_password_no_echo(prompt).ok().flatten() {
                    Some(entered) => pass = entered,
                    None => break,
                }
            }
        }
    }
    print_err(&last_err);
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_slash_switches_without_mangling_posix_paths() {
        assert_eq!(normalize_cli_switch("/command=ls"), "-command=ls");
        assert_eq!(normalize_cli_switch("/log:session.log"), "-log=session.log");
        assert_eq!(normalize_cli_switch("/help"), "-help");
        assert_eq!(normalize_cli_switch("/home/user/file.txt"), "/home/user/file.txt");
        assert_eq!(normalize_cli_switch("/var"), "/var");
    }
}
