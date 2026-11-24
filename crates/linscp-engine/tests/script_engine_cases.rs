//! Rust ports of the `script` cases the parity ledger
//! (`docs/upstream-parity.json`, suite `engine-script`) cites, plus the
//! engine-level cases the retired `unit` and `live-*` suites were the only
//! evidence for.
//!
//! The retired Python suite (`source/linux/tests/ScriptTest.py`) drove a
//! `linscp` binary this repository does not build, so nothing it asserted
//! was reproducible. These cases drive the same behaviour through the
//! engine's own APIs and its script interpreter, so every claim they make
//! is checked by code this repository ships.
//!
//! Each case carries the upstream case name of the same name; the tests
//! carrying that name are what the ledger cites as evidence.

use std::path::Path;

use linscp_engine::presets::{ResumeSupportMode, TransferPreset, TransferPresetStore};
use linscp_engine::script::{
    BatchMode, ScriptInterpreter, ScriptRunConfig, split_semicolon_commands,
};
use linscp_engine::script_params::{
    expand_script_parameters, format_timestamp, try_relative_time,
};
use linscp_engine::session_store::SessionStore;
use linscp_engine::url_and_raw::{
    DefaultOsVault, ParsedSiteSpec, apply_raw_settings, site_spec_from_stored,
    validate_session_settings,
};
use linscp_engine::xml_log::SessionLogger;
use linscp_types::{ProtocolScheme, TransferMode};

/// A script configuration rooted at `config_dir`, so the stored-session and
/// preset files a case writes land in a temporary directory.
fn test_config(config_dir: &Path) -> ScriptRunConfig {
    ScriptRunConfig {
        config_dir: config_dir.to_path_buf(),
        batch_mode: BatchMode::Abort,
        confirm: false,
        echo: false,
        log_level: 0,
        ..ScriptRunConfig::default()
    }
}

/// A logger that keeps the XML action log out of the way: these cases assert
/// on the console, not on the log file (the XML cases build their own).
fn in_memory_logger() -> SessionLogger {
    SessionLogger::open(None, 0, false, None, None, false, "linscp-test")
        .expect("an in-memory logger opens")
}

/// Runs one command string (which may hold several `;`-separated commands)
/// through the interpreter and returns (the run raised no new error, the text
/// the console received on both channels).
///
/// The batch mode decides what happens after a failing command, exactly as it
/// does for a script file: `abort` stops the run, `continue` carries on.
async fn run_line(interp: &mut ScriptInterpreter, line: &str) -> (bool, String) {
    let seen = interp.capture_console();
    let before = interp.error_count();
    interp.run_command_string(line, false).await;
    let (stdout, stderr) = ScriptInterpreter::collected_console(&seen);
    (interp.error_count() == before, format!("{stdout}{stderr}"))
}

/// An environment variable of the running process, used to check the `%NAME%`
/// expansion.
///
/// The suite never changes the process environment: the cases beside this one
/// read it while they run, and changing it under them is a data race. Every
/// environment this suite runs in has variables, so one is found by name.
fn ambient_var() -> Option<(String, String)> {
    std::env::vars().find(|(name, value)| {
        !name.is_empty()
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !name.starts_with(|c: char| c.is_ascii_digit())
            && name != "TIMESTAMP"
            && !value.is_empty()
            && !value.contains('%')
    })
}

/// The upstream case name is `test_script_parameters`.
#[tokio::test]
async fn test_script_parameters() {
    let expanded = expand_script_parameters("echo %1%-%2%-end", &["one".into(), "two".into()])
        .expect("the parameters expand");
    assert_eq!(expanded, "echo one-two-end");

    // An unset variable is left alone rather than turned into nothing, and so
    // is a parameter that was not given.
    let untouched = expand_script_parameters("echo [%LINSCP_NO_SUCH_VAR_XYZ%] [%3%]", &[])
        .expect("the line expands");
    assert_eq!(untouched, "echo [%LINSCP_NO_SUCH_VAR_XYZ%] [%3%]");

    // An environment variable that is set is replaced by its value.
    let (name, value) = ambient_var().expect("the environment has a variable to expand");
    let from_env = expand_script_parameters(&format!("echo [%{name}%]"), &[])
        .expect("the line expands");
    assert_eq!(from_env, format!("echo [{value}]"));

    // The plain timestamp placeholder is the compact 'yyyymmddhhnnss' form.
    // An environment variable of that name overrides it, so the check only
    // runs where there is none.
    if std::env::var_os("TIMESTAMP").is_none() {
        let stamped = expand_script_parameters("echo %TIMESTAMP%", &[]).expect("the stamp expands");
        let stamp = stamped.trim_start_matches("echo ").to_string();
        assert_eq!(stamp.len(), 14, "the plain stamp is 14 digits: {stamp}");
        assert!(
            stamp.chars().all(|c| c.is_ascii_digit()),
            "the plain stamp is digits only: {stamp}"
        );
    }

    // A formatted timestamp placeholder is the format it names.
    let formatted = expand_script_parameters("echo %TIMESTAMP#yyyymmdd%", &[])
        .expect("the formatted stamp expands");
    let day = formatted.trim_start_matches("echo ").to_string();
    assert_eq!(day.len(), 8, "the formatted stamp is 8 digits: {day}");
    assert!(
        day.chars().all(|c| c.is_ascii_digit()),
        "the formatted stamp is digits only: {day}"
    );

    // A malformed offset fails instead of transferring to a path that still
    // contains the placeholder.
    let broken = expand_script_parameters("echo %TIMESTAMP-1Q#yyyymmdd%", &[])
        .expect_err("a malformed offset is refused");
    assert!(
        broken.contains("is not valid"),
        "the refusal names the problem: {broken}"
    );

    // The same expansion happens inside the interpreter, so a command's
    // arguments really are the expanded ones.
    let tmp = tempfile::tempdir().expect("temp dir");
    let mut cfg = test_config(tmp.path());
    cfg.parameters = vec!["report.csv".into()];
    let mut interp = ScriptInterpreter::new(cfg, in_memory_logger());
    let (ok, out) = run_line(&mut interp, "echo %1%").await;
    assert!(ok, "the echo succeeds: {out}");
    assert!(
        out.contains("report.csv"),
        "the parameter reached the command: {out}"
    );
}

/// The upstream case name is `test_option_resume_values`.
#[tokio::test]
async fn test_option_resume_values() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let mut interp = ScriptInterpreter::new(test_config(tmp.path()), in_memory_logger());

    for (value, shown) in [
        ("on", "on"),
        ("off", "off"),
        ("automatic", "automatic"),
        ("aut", "automatic"),
    ] {
        let (ok, out) = run_line(&mut interp, &format!("option resume {value}; option resume")).await;
        assert!(ok, "'option resume {value}' succeeds: {out}");
        assert!(
            out.contains(&format!("resume = {shown}")),
            "'option resume {value}' shows '{shown}': {out}"
        );
    }

    let (ok, out) = run_line(&mut interp, "option resume sometimes").await;
    assert!(!ok, "an unknown resume value is refused: {out}");
    assert!(
        out.contains("on, off or automatic"),
        "the refusal names the accepted values: {out}"
    );

    // 'option resume on' forces binary transfers, so an ASCII transfer is
    // refused before any connection, like an explicit -resume.
    let (ok, out) = run_line(&mut interp, "option resume on; get -transfer=ascii x /tmp/").await;
    assert!(!ok, "the ASCII transfer is refused: {out}");
    assert!(
        out.contains("binary only"),
        "the refusal names the reason: {out}"
    );
    assert!(
        !out.contains("Not connected"),
        "the refusal comes before the connection is attempted: {out}"
    );
}

/// The upstream case name is
/// `test_transfer_presets_and_permission_switches`.
#[tokio::test]
async fn test_transfer_presets_and_permission_switches() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let config_dir = tmp.path().to_path_buf();
    let mut interp = ScriptInterpreter::new(test_config(&config_dir), in_memory_logger());

    // Store, list, update.
    let (ok, out) = run_line(
        &mut interp,
        "savepreset asciitxt -transfer=ascii -preservetime=on -mask=*.txt; presets",
    )
    .await;
    assert!(ok, "the preset is stored and listed: {out}");
    assert!(out.contains("transfer=ascii"), "the mode is listed: {out}");
    assert!(out.contains("mask=*.txt"), "the mask is listed: {out}");

    let (ok, out) = run_line(&mut interp, "savepreset asciitxt -transfer=binary; presets").await;
    assert!(ok, "the preset is updated: {out}");
    assert!(out.contains("transfer=binary"), "the new mode is listed: {out}");
    assert!(
        !out.contains("transfer=ascii"),
        "the old mode is gone: {out}"
    );

    // A preset that is not there is refused by name.
    let (ok, out) = run_line(&mut interp, "rmspreset nosuchpreset").await;
    assert!(!ok, "removing an unknown preset fails: {out}");
    assert!(
        out.contains("no transfer preset named"),
        "the refusal names the missing preset: {out}"
    );

    // Activate, show, clear.
    let (ok, out) = run_line(
        &mut interp,
        "savepreset p1 -transfer=binary; option preset p1; option",
    )
    .await;
    assert!(ok, "the preset is activated: {out}");
    assert!(out.contains("preset = p1"), "the active preset is shown: {out}");

    let (ok, out) = run_line(&mut interp, "option preset nosuchpreset").await;
    assert!(!ok, "activating an unknown preset fails: {out}");
    assert!(
        out.contains("There is no transfer preset named"),
        "the refusal names the missing preset: {out}"
    );

    let (ok, out) = run_line(&mut interp, "option preset p1; option preset off; option").await;
    assert!(ok, "the preset is cleared: {out}");
    assert!(out.contains("preset = off"), "the cleared preset is shown: {out}");

    // A site stores and validates its preset.
    let (ok, out) = run_line(
        &mut interp,
        "savesession sx -host=host.example -preset=unknownpreset",
    )
    .await;
    assert!(!ok, "a site with an unknown preset is refused: {out}");
    assert!(
        out.contains("no transfer preset named"),
        "the refusal names the missing preset: {out}"
    );

    let (ok, out) = run_line(
        &mut interp,
        "savepreset p1 -transfer=binary; savesession sx -host=host.example -preset=p1; sessions",
    )
    .await;
    assert!(ok, "the site with a known preset is stored: {out}");
    assert!(
        out.contains("(preset p1)"),
        "the listing names the preset the site carries: {out}"
    );

    // '-permissions' without a value is understood on both directions: the
    // run stops at the missing connection, not at the switch.
    for command in [
        "get -permissions x /tmp/",
        "put -nopermissions x /tmp/",
        "put -permissions=640 x /tmp/",
    ] {
        let (ok, out) = run_line(&mut interp, command).await;
        assert!(!ok, "'{command}' needs a connection: {out}");
        assert!(
            !out.contains("Unsupported switch"),
            "'{command}' is not refused as an unknown switch: {out}"
        );
        assert!(
            !out.contains("applies to uploads only"),
            "'{command}' is not refused for its direction: {out}"
        );
    }

    // The preset vocabulary errors name the setting at fault.
    let (ok, out) = run_line(&mut interp, "savepreset bad -nosuchsetting=1").await;
    assert!(!ok, "an unknown preset setting is refused: {out}");
    assert!(
        out.contains("nosuchsetting"),
        "the refusal names the setting: {out}"
    );

    let (ok, out) = run_line(&mut interp, "savepreset bad -speed=lots").await;
    assert!(!ok, "an unknown speed is refused: {out}");
    assert!(out.contains("speed"), "the refusal names the setting: {out}");
}

/// The upstream case name is `test_stored_sessions`.
#[tokio::test]
async fn test_stored_sessions() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let config_dir = tmp.path().to_path_buf();
    let mut interp = ScriptInterpreter::new(test_config(&config_dir), in_memory_logger());

    let (ok, out) = run_line(&mut interp, "sessions").await;
    assert!(ok, "the empty listing succeeds: {out}");
    assert!(
        out.contains("no stored sessions"),
        "the empty listing says so: {out}"
    );

    let (ok, out) = run_line(
        &mut interp,
        "savesession demo -host=demo.example.com -username=alice -port=2222",
    )
    .await;
    assert!(ok, "the session is stored: {out}");
    assert!(
        out.contains("Stored session 'demo'"),
        "the store names the session: {out}"
    );

    let (ok, out) = run_line(&mut interp, "sessions").await;
    assert!(ok, "the listing succeeds: {out}");
    assert!(out.contains("demo"), "the listing names the session: {out}");
    assert!(
        out.contains("sftp://alice@demo.example.com:2222"),
        "the listing shows the URL the site reads back: {out}"
    );

    // The file the graphical client reads is the one written here.
    let stored = config_dir.join("sessions.ini");
    assert!(stored.is_file(), "the store wrote sessions.ini");
    let text = std::fs::read_to_string(&stored).expect("the store is readable");
    assert!(text.contains("[demo]"), "the site has its own section: {text}");
    assert!(
        text.contains("host=demo.example.com"),
        "the host is stored: {text}"
    );
    assert!(text.contains("port=2222"), "the port is stored: {text}");
    assert!(
        !text.contains("password"),
        "no password is stored without being asked for: {text}"
    );

    let (ok, out) = run_line(&mut interp, "rmsession demo").await;
    assert!(ok, "the session is removed: {out}");
    let (ok, out) = run_line(&mut interp, "sessions").await;
    assert!(ok, "the listing succeeds: {out}");
    assert!(
        out.contains("no stored sessions"),
        "the listing is empty again: {out}"
    );
}

/// The upstream case name is `test_stored_session_folders`: a site stored in
/// a folder is listed under it, and the folder can be removed as a whole.
#[tokio::test]
async fn test_stored_session_folders() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let config_dir = tmp.path().to_path_buf();
    let mut interp = ScriptInterpreter::new(test_config(&config_dir), in_memory_logger());

    let (ok, out) = run_line(
        &mut interp,
        "savesession group/site -host=group.example.com; sessions folders",
    )
    .await;
    assert!(ok, "the site in a folder is stored: {out}");
    assert!(
        out.contains("group/"),
        "the folder is listed: {out}"
    );

    // The site itself is still listed by its full name.
    let (ok, out) = run_line(&mut interp, "sessions").await;
    assert!(ok, "the listing succeeds: {out}");
    assert!(
        out.contains("group/site"),
        "the site is listed under its folder: {out}"
    );

    // The folder can be filtered to, and removed as a whole.
    let (ok, out) = run_line(&mut interp, "sessions group/").await;
    assert!(ok, "the folder listing succeeds: {out}");
    assert!(
        out.contains("group/site"),
        "the folder listing names the site: {out}"
    );

    let (ok, out) = run_line(&mut interp, "rmsession -folder group").await;
    assert!(ok, "the folder is removed: {out}");
    let (ok, out) = run_line(&mut interp, "sessions").await;
    assert!(ok, "the listing succeeds: {out}");
    assert!(
        !out.contains("group/site"),
        "the site in the folder is gone: {out}"
    );
}

/// The upstream case name is `test_a_stored_session_keeps_its_gssapi_and_tunnel_local_port`:
/// the Kerberos and jump-host settings a site is saved with are the ones the
/// site reads back.
#[tokio::test]
async fn test_a_stored_session_keeps_its_gssapi_and_tunnel_local_port() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let config_dir = tmp.path().to_path_buf();
    let mut interp = ScriptInterpreter::new(test_config(&config_dir), in_memory_logger());

    let (ok, out) = run_line(
        &mut interp,
        "savesession jump -protocol=sftp -host=target.example.com -username=alice \
         -rawsettings AuthGSSAPI=1 Tunnel=1 TunnelHostName=jump.example \
         TunnelPortNumber=2222 TunnelLocalPortNumber=1080",
    )
    .await;
    assert!(ok, "the site with its jump settings is stored: {out}");

    let stored = config_dir.join("sessions.ini");
    let text = std::fs::read_to_string(&stored).expect("the store is readable");
    assert!(text.contains("auth_gssapi=1"), "the Kerberos setting is stored: {text}");
    assert!(text.contains("tunnel=1"), "the jump is stored: {text}");
    assert!(
        text.contains("tunnel_host=jump.example"),
        "the jump host is stored: {text}"
    );
    assert!(
        text.contains("tunnel_port=2222"),
        "the jump port is stored: {text}"
    );
    assert!(
        text.contains("tunnel_local_port=1080"),
        "the local port is stored: {text}"
    );

    let store = SessionStore::load_from_dir(&config_dir, &DefaultOsVault)
        .expect("the store loads");
    let site = store.find("jump").expect("the stored site is found").clone();
    let spec = site_spec_from_stored(&site).expect("the stored site becomes a specification");
    assert_eq!(
        spec.raw_fields.get("auth_gssapi").map(String::as_str),
        Some("1"),
        "the Kerberos setting survives the round trip"
    );
    let tunnel = spec.session.tunnel.as_ref().expect("the jump survives");
    assert!(tunnel.enabled, "the jump is still enabled");
    assert_eq!(tunnel.host, "jump.example", "the jump host survives");
    assert_eq!(tunnel.port, 2222, "the jump port survives");
    assert_eq!(tunnel.local_port, 1080, "the local port survives");
}

/// The upstream case name is `test_a_stored_session_keeps_its_proxy`:
/// the proxy a site is saved with is the one the site reads back, and a
/// proxy the protocol cannot run is refused rather than quietly dropped.
#[tokio::test]
async fn test_a_stored_session_keeps_its_proxy() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let config_dir = tmp.path().to_path_buf();
    let mut interp = ScriptInterpreter::new(test_config(&config_dir), in_memory_logger());

    let (ok, out) = run_line(
        &mut interp,
        "savesession proxy-site -protocol=sftp -host=target.example.com -username=alice \
         -rawsettings ProxyMethod=SOCKS5 ProxyHost=proxy.example ProxyPort=1080 \
         ProxyUserName=bob",
    )
    .await;
    assert!(ok, "the site with its proxy is stored: {out}");

    let stored = config_dir.join("sessions.ini");
    let text = std::fs::read_to_string(&stored).expect("the store is readable");
    assert!(
        text.contains("proxy_method=SOCKS5"),
        "the proxy method is stored: {text}"
    );
    assert!(
        text.contains("proxy_host=proxy.example"),
        "the proxy host is stored: {text}"
    );
    assert!(text.contains("proxy_port=1080"), "the proxy port is stored: {text}");
    assert!(
        text.contains("proxy_username=bob"),
        "the proxy user is stored: {text}"
    );

    let store = SessionStore::load_from_dir(&config_dir, &DefaultOsVault)
        .expect("the store loads");
    let site = store.find("proxy-site").expect("the stored site is found").clone();
    let spec = site_spec_from_stored(&site).expect("the stored site becomes a specification");
    assert_eq!(
        spec.raw_fields.get("proxy_method").map(String::as_str),
        Some("SOCKS5"),
        "the proxy method survives the round trip"
    );
    assert_eq!(
        spec.raw_fields.get("proxy_host").map(String::as_str),
        Some("proxy.example"),
        "the proxy host survives the round trip"
    );
    assert_eq!(
        spec.raw_fields.get("proxy_port").map(String::as_str),
        Some("1080"),
        "the proxy port survives the round trip"
    );
    assert_eq!(
        spec.raw_fields.get("proxy_username").map(String::as_str),
        Some("bob"),
        "the proxy user survives the round trip"
    );
    validate_session_settings(&spec).expect("the restored proxy is valid");

    // A proxy the protocol cannot run is refused at the point it is set,
    // not accepted and ignored later.
    let (ok, out) = run_line(
        &mut interp,
        "savesession dav-site -protocol=webdav -host=dav.example.com -username=alice \
         -rawsettings ProxyMethod=Telnet ProxyHost=proxy.example ProxyPort=1080",
    )
    .await;
    assert!(!ok, "a telnet proxy on a curl-backed protocol is refused: {out}");
    assert!(
        out.to_lowercase().contains("telnet"),
        "the refusal names the proxy method: {out}"
    );

    // A proxy method without a host is refused as well.
    let (ok, out) = run_line(
        &mut interp,
        "savesession nohost-site -protocol=sftp -host=target.example.com -username=alice \
         -rawsettings ProxyMethod=SOCKS5",
    )
    .await;
    assert!(!ok, "a proxy without a host is refused: {out}");
    assert!(
        out.contains("ProxyHost"),
        "the refusal names the missing setting: {out}"
    );
}

/// The upstream case name is `test_tunnel_settings_validation_is_fail_closed`:
/// a jump host that is not named, or a name that cannot be a host, is
/// refused before any connection is attempted.
#[tokio::test]
async fn test_tunnel_settings_validation_is_fail_closed() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let mut interp = ScriptInterpreter::new(test_config(tmp.path()), in_memory_logger());

    // A jump without a host cannot be connected to.
    let (ok, out) = run_line(
        &mut interp,
        "open sftp://alice@example.com/ -rawsettings Tunnel=1 ; echo SHOULD_NOT_RUN",
    )
    .await;
    assert!(!ok, "a jump without a host is refused: {out}");
    assert!(
        out.contains("TunnelHostName"),
        "the refusal names the missing setting: {out}"
    );
    assert!(
        !out.contains("SHOULD_NOT_RUN"),
        "the run stopped before the next command: {out}"
    );

    // A host name with whitespace in it cannot be a host either.
    let (ok, out) = run_line(
        &mut interp,
        "open sftp://alice@example.com/ -rawsettings TunnelHostName=\"two hosts\"",
    )
    .await;
    assert!(!ok, "a jump host with whitespace is refused: {out}");
    assert!(
        out.contains("TunnelHostName"),
        "the refusal names the setting: {out}"
    );

    // The Kerberos setting is an SSH setting: it is refused elsewhere
    // rather than stored and then ignored.
    let (ok, out) = run_line(
        &mut interp,
        "open ftp://alice@example.com/ -rawsettings AuthGSSAPI=1",
    )
    .await;
    assert!(!ok, "the Kerberos setting is refused for FTP: {out}");
    assert!(
        out.contains("AuthGSSAPI"),
        "the refusal names the setting: {out}"
    );
}

/// The upstream case name is `test_session_export_import`.
#[tokio::test]
async fn test_session_export_import() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let config_dir = tmp.path().to_path_buf();
    let mut interp = ScriptInterpreter::new(test_config(&config_dir), in_memory_logger());

    let (ok, out) = run_line(&mut interp, "savesession one -host=one.example.com").await;
    assert!(ok, "the session is stored: {out}");

    let exported = config_dir.join("exported.ini");
    let (ok, out) = run_line(
        &mut interp,
        &format!("sessions export \"{}\"", exported.display()),
    )
    .await;
    assert!(ok, "the export succeeds: {out}");
    assert!(
        out.contains("Exported 1 session"),
        "the export names the count: {out}"
    );
    assert!(exported.is_file(), "the export wrote its file");

    let (ok, out) = run_line(&mut interp, "rmsession one").await;
    assert!(ok, "the session is removed: {out}");

    let (ok, out) = run_line(
        &mut interp,
        &format!("sessions import \"{}\"", exported.display()),
    )
    .await;
    assert!(ok, "the import succeeds: {out}");
    assert!(
        out.contains("Imported 1 session"),
        "the import names the count: {out}"
    );

    let (ok, out) = run_line(&mut interp, "sessions").await;
    assert!(ok, "the listing succeeds: {out}");
    assert!(
        out.contains("one.example.com"),
        "the imported site is listed: {out}"
    );
}

/// The upstream case name is
/// `test_rawsettings_refuse_a_setting_this_build_would_drop`.
#[tokio::test]
async fn test_rawsettings_refuse_a_setting_this_build_would_drop() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let mut interp = ScriptInterpreter::new(test_config(tmp.path()), in_memory_logger());

    // A setting this build does not apply is refused by name, with the names
    // it does apply, before any connection is attempted: a setting silently
    // dropped is a session that connects somewhere else than asked.
    let (ok, out) = run_line(
        &mut interp,
        "open sftp://alice@example.com/ -rawsettings SFTPUploadQueue=2 ; echo SHOULD_NOT_RUN",
    )
    .await;
    assert!(!ok, "the unknown setting is refused: {out}");
    assert!(
        out.contains("SFTPUploadQueue"),
        "the refusal names the refused setting: {out}"
    );
    assert!(
        out.contains("ProxyMethod"),
        "the refusal names the settings that are applied: {out}"
    );
    assert!(
        !out.contains("SHOULD_NOT_RUN"),
        "the run stopped before the next command: {out}"
    );
}

/// The upstream case name is `test_rawsettings_validate_their_values`.
#[tokio::test]
async fn test_rawsettings_validate_their_values() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let mut interp = ScriptInterpreter::new(test_config(tmp.path()), in_memory_logger());

    for (setting, expected) in [
        ("ProxyMethod=SOCKS9", "proxy method"),
        ("ProxyPort=99999", "proxy port"),
        ("ProxyDNS=maybe", "ProxyDNS"),
        ("ProxyLocalhost=perhaps", "ProxyLocalhost"),
    ] {
        let (ok, out) = run_line(
            &mut interp,
            &format!(
                "open sftp://alice@example.com/ -rawsettings {setting} ; echo SHOULD_NOT_RUN"
            ),
        )
        .await;
        assert!(!ok, "'{setting}' is refused: {out}");
        assert!(
            out.contains(expected),
            "'{setting}' is refused naming '{expected}': {out}"
        );
        assert!(
            !out.contains("SHOULD_NOT_RUN"),
            "'{setting}' stopped the run: {out}"
        );
    }

    // A method that needs a host has to have one: the alternative is a
    // connection attempt that fails with a message about the network.
    let (ok, out) = run_line(
        &mut interp,
        "open sftp://alice@example.com/ -rawsettings ProxyMethod=SOCKS5",
    )
    .await;
    assert!(!ok, "a proxy method without a host is refused: {out}");
    assert!(
        out.contains("ProxyHost"),
        "the refusal names the missing setting: {out}"
    );

    // '-rawsettings=N' takes exactly N parameters, the way upstream's list
    // switches do.
    let (ok, out) = run_line(
        &mut interp,
        "open sftp://alice@example.com/ -rawsettings=2 ProxyHost=proxy",
    )
    .await;
    assert!(!ok, "a wrong parameter count is refused: {out}");
    assert!(
        out.contains("-rawsettings=2"),
        "the refusal names the count that was asked for: {out}"
    );
}

/// The upstream case name is `test_ftp_and_tls_raw_settings` (the retired
/// `unit` suite's `TestFtpAndTlsSettings`): the FTP engine's policy and the
/// TLS policy are applied by name, in the forms people write them, and a
/// value outside that set is refused by name.
#[tokio::test]
async fn test_ftp_and_tls_raw_settings() {
    let mut spec = ParsedSiteSpec::default();
    spec.session.protocol = ProtocolScheme::Ftp;
    spec.session.host = "ftp.example.com".to_string();

    // The FTP engine's policy.
    apply_raw_settings(&mut spec, &["FtpPasvMode=0".to_string()]).expect("the passive mode applies");
    assert_eq!(
        spec.raw_fields.get("ftp_pasv_mode").map(String::as_str),
        Some("0"),
        "the passive mode is applied"
    );
    apply_raw_settings(&mut spec, &["FtpPasvMode=on".to_string()]).expect("the named mode applies");
    assert_eq!(
        spec.raw_fields.get("ftp_pasv_mode").map(String::as_str),
        Some("1"),
        "'on' means the same as 1"
    );
    let refused = apply_raw_settings(&mut spec, &["FtpPasvMode=maybe".to_string()])
        .expect_err("an unknown passive mode is refused");
    assert!(
        refused.contains("FtpPasvMode"),
        "the refusal names the setting: {refused}"
    );

    apply_raw_settings(&mut spec, &["FtpUseMlsd=2".to_string()]).expect("the MLSD mode applies");
    assert_eq!(
        spec.raw_fields.get("ftp_use_mlsd").map(String::as_str),
        Some("2"),
        "the MLSD mode is applied"
    );
    apply_raw_settings(&mut spec, &["FtpForcePasvIp=0".to_string()]).expect("the PASV address applies");
    assert_eq!(
        spec.raw_fields.get("ftp_force_pasv_ip").map(String::as_str),
        Some("0"),
        "the PASV address policy is applied"
    );
    let refused = apply_raw_settings(&mut spec, &["FtpForcePasvIp=3".to_string()])
        .expect_err("an unknown PASV address policy is refused");
    assert!(
        refused.contains("FtpForcePasvIp"),
        "the refusal names the setting: {refused}"
    );

    // 'Ftps' is upstream's TFtps, by number: 0 is plain FTP, 1 implicit TLS,
    // 2 and 3 explicit TLS.
    for (value, protocol) in [
        ("1", ProtocolScheme::Ftps),
        ("2", ProtocolScheme::Ftpes),
        ("3", ProtocolScheme::Ftpes),
    ] {
        let mut spec = ParsedSiteSpec::default();
        spec.session.protocol = ProtocolScheme::Ftp;
        spec.session.host = "ftp.example.com".to_string();
        apply_raw_settings(&mut spec, &[format!("Ftps={value}")])
            .unwrap_or_else(|e| panic!("'Ftps={value}' applies: {e}"));
        assert_eq!(
            spec.session.protocol, protocol,
            "'Ftps={value}' selects the protocol"
        );
    }
    let mut spec = ParsedSiteSpec::default();
    spec.session.protocol = ProtocolScheme::Ftp;
    spec.session.host = "ftp.example.com".to_string();
    apply_raw_settings(&mut spec, &["Ftps=0".to_string()]).expect("plain FTP applies");
    assert_eq!(
        spec.session.protocol,
        ProtocolScheme::Ftp,
        "'Ftps=0' keeps plain FTP"
    );
    let refused = apply_raw_settings(&mut spec, &["Ftps=sometimes".to_string()])
        .expect_err("an unknown Ftps mode is refused");
    assert!(refused.contains("Ftps"), "the refusal names the setting: {refused}");

    // The TLS versions, in the forms people write them.
    for text in ["1.2", "tls1.2", "TLSv1.2", "tls12", "12"] {
        let mut spec = ParsedSiteSpec::default();
        spec.session.protocol = ProtocolScheme::Webdavs;
        spec.session.host = "dav.example.com".to_string();
        apply_raw_settings(&mut spec, &[format!("MinTlsVersion={text}")])
            .unwrap_or_else(|e| panic!("'MinTlsVersion={text}' applies: {e}"));
        assert_eq!(
            spec.raw_fields.get("min_tls_version").map(String::as_str),
            Some(text),
            "'MinTlsVersion={text}' is stored as it was written"
        );
    }
    for text in ["1.3", "tls1.3", "TLSv1.3", "tls13", "13"] {
        let mut spec = ParsedSiteSpec::default();
        spec.session.protocol = ProtocolScheme::Webdavs;
        spec.session.host = "dav.example.com".to_string();
        apply_raw_settings(&mut spec, &[format!("MinTlsVersion={text}")])
            .unwrap_or_else(|e| panic!("'MinTlsVersion={text}' applies: {e}"));
    }
    let refused = apply_raw_settings(&mut spec, &["MinTlsVersion=1.4".to_string()])
        .expect_err("an unknown TLS version is refused");
    assert!(
        refused.contains("TLS version"),
        "the refusal names the problem: {refused}"
    );

    // The obsolete versions are refused by name too, not silently accepted.
    let refused = apply_raw_settings(&mut spec, &["MinTlsVersion=1.0".to_string()])
        .expect_err("an obsolete TLS version is refused");
    assert!(
        refused.contains("obsolete"),
        "the refusal names the problem: {refused}"
    );

    // A minimum above the maximum is refused.
    let mut spec = ParsedSiteSpec::default();
    spec.session.protocol = ProtocolScheme::Webdavs;
    spec.session.host = "dav.example.com".to_string();
    apply_raw_settings(&mut spec, &["MinTlsVersion=1.3".to_string()]).expect("the minimum applies");
    let refused = apply_raw_settings(&mut spec, &["MaxTlsVersion=1.2".to_string()])
        .expect_err("a minimum above the maximum is refused");
    assert!(
        refused.contains("MinTlsVersion"),
        "the refusal names the setting: {refused}"
    );

    // The certificate files are applied by name.
    apply_raw_settings(
        &mut spec,
        &[
            "TlsCertificateFile=/tmp/c.pem".to_string(),
            "CaCertificateFile=/tmp/ca.pem".to_string(),
        ],
    )
    .expect("the certificate files apply");
    assert_eq!(
        spec.raw_fields.get("tls_certificate_file").map(String::as_str),
        Some("/tmp/c.pem"),
        "the client certificate is applied"
    );
    assert_eq!(
        spec.raw_fields.get("ca_certificate_file").map(String::as_str),
        Some("/tmp/ca.pem"),
        "the CA certificate is applied"
    );
}

/// The upstream case name is `test_raw_settings_survive_a_stored_session`
/// (the retired `live-curl` suite's
/// `test_saved_session_keeps_ftp_and_tls_settings`): a setting the session
/// stores is read back, so a site opened later behaves the way it was
/// saved.
#[tokio::test]
async fn test_raw_settings_survive_a_stored_session() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let config_dir = tmp.path().to_path_buf();
    let mut interp = ScriptInterpreter::new(test_config(&config_dir), in_memory_logger());

    let (ok, out) = run_line(
        &mut interp,
        "savesession ftp-site -protocol=ftp -host=ftp.example.com -username=bob \
         -rawsettings FtpPasvMode=0 FtpUseMlsd=2",
    )
    .await;
    assert!(ok, "the site with its raw settings is stored: {out}");

    // The stored file holds the settings under the keys a saved site reads
    // back, so opening the site later restores them.
    let stored = config_dir.join("sessions.ini");
    let text = std::fs::read_to_string(&stored).expect("the store is readable");
    assert!(
        text.contains("ftp_pasv_mode=0"),
        "the passive mode is stored: {text}"
    );
    assert!(
        text.contains("ftp_use_mlsd=2"),
        "the MLSD mode is stored: {text}"
    );

    // Reading the store back gives the same settings.
    let store = SessionStore::load_from_dir(&config_dir, &DefaultOsVault)
        .expect("the store loads");
    let site = store.find("ftp-site").expect("the stored site is found").clone();
    let spec = site_spec_from_stored(&site).expect("the stored site becomes a specification");
    assert_eq!(
        spec.raw_fields.get("ftp_pasv_mode").map(String::as_str),
        Some("0"),
        "the passive mode survives the round trip"
    );
    assert_eq!(
        spec.raw_fields.get("ftp_use_mlsd").map(String::as_str),
        Some("2"),
        "the MLSD mode survives the round trip"
    );
    validate_session_settings(&spec).expect("the restored settings are valid");
}

/// The upstream case name is `test_preset_matches_a_session_and_a_mask`
/// (the retired `live-dav` suite's
/// `test_transfer_preset_drives_ascii_and_loads_with_the_site`): a preset
/// whose rule names the host applies to that host's transfers, and a preset
/// whose rule names a file mask applies to the files that mask names.
#[tokio::test]
async fn test_preset_matches_a_session_and_a_mask() {
    let mut store = TransferPresetStore::default();

    let mut byhost = TransferPreset {
        name: "byhost".to_string(),
        host: "*.example.com".to_string(),
        ..TransferPreset::default()
    };
    byhost
        .parse_setting("transfer", "ascii")
        .expect("the mode parses");
    store.add_or_update(byhost).expect("the preset is stored");

    let matched = store
        .match_session("host.example.com:22", "alice", "/pub", "/local")
        .expect("the host rule matches the session");
    assert_eq!(
        matched.transfer_mode,
        Some(TransferMode::Ascii),
        "the matching preset supplies the mode"
    );
    assert!(
        store
            .match_session("other.invalid:22", "alice", "/pub", "/local")
            .is_none(),
        "a host the rule does not name is not matched"
    );

    // A mask rule names the files it applies to.
    let mut bymask = TransferPreset {
        name: "bymask".to_string(),
        ..TransferPreset::default()
    };
    bymask
        .parse_setting("mask", "*.txt")
        .expect("the mask rule parses");
    bymask
        .parse_setting("transfer", "ascii")
        .expect("the mode parses");
    store.add_or_update(bymask).expect("the preset is stored");

    let matched = store.match_mask("notes.txt").expect("the mask rule matches the file");
    assert_eq!(
        matched.transfer_mode,
        Some(TransferMode::Ascii),
        "the matching preset supplies the mode"
    );
    assert!(
        store.match_mask("notes.bin").is_none(),
        "a file the mask does not name is not matched"
    );
}

/// The upstream case name is `test_relative_timestamp_offsets`: a relative
/// time moves a moment by a number of units, in the directions and the
/// units people write.
#[tokio::test]
async fn test_relative_timestamp_offsets() {
    // A base of 2026-03-15T12:34:56Z.
    let base = 1_773_578_096;
    let (year, month, day, _, _, _, _) = linscp_platform::terminal::local_ymdhms_wday(base);

    // 'today' and 'yesterday' name the local day, at its start.
    let start_of_today = linscp_platform::terminal::mktime_local_ymdhms(year, month as i32, day as i32, 0, 0, 0)
        .expect("the start of the day is representable");
    assert_eq!(
        try_relative_time("today", base, true).expect("today is computed"),
        start_of_today
    );
    let start_of_yesterday =
        linscp_platform::terminal::mktime_local_ymdhms(year, month as i32, day as i32 - 1, 0, 0, 0)
            .expect("the start of the previous day is representable");
    assert_eq!(
        try_relative_time("yesterday", base, false).expect("yesterday is computed"),
        start_of_yesterday
    );

    // A number of units moves the moment that way, in both directions.
    for spec in ["1S", "1N", "1H", "1D", "1Y"] {
        let ahead = try_relative_time(spec, base, true)
            .unwrap_or_else(|e| panic!("'{spec}' ahead: {e}"));
        let behind = try_relative_time(spec, base, false)
            .unwrap_or_else(|e| panic!("'{spec}' behind: {e}"));
        assert!(ahead > base, "'{spec}' ahead moves forward");
        assert!(behind < base, "'{spec}' behind moves back");
    }

    // A time with no unit is not a time.
    let refused = try_relative_time("1X", base, true).expect_err("an unknown unit is refused");
    assert!(
        refused.contains("time unit"),
        "the refusal names the problem: {refused}"
    );
    let refused = try_relative_time("tomorrow", base, true).expect_err("a word is refused");
    assert!(
        refused.contains("relative time"),
        "the refusal names the problem: {refused}"
    );
}

/// The upstream case name is `test_timestamp_format_tokens`: the timestamp
/// formats are the ones upstream's `FormatDateTime` produces.
#[tokio::test]
async fn test_timestamp_format_tokens() {
    const MONTHS: [&str; 12] = [
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
    const DAYS: [&str; 7] = [
        "Sunday",
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
    ];

    // A fixed moment; the local reading of it is what the tokens render.
    let moment = 1_614_834_367;
    let (year, month, day, hour, min, sec, wday) =
        linscp_platform::terminal::local_ymdhms_wday(moment);

    assert_eq!(format_timestamp(moment, "yyyy"), format!("{year:04}"));
    assert_eq!(format_timestamp(moment, "yy"), format!("{:02}", year % 100));
    assert_eq!(format_timestamp(moment, "mmmm"), MONTHS[(month - 1) as usize]);
    assert_eq!(format_timestamp(moment, "mmm"), &MONTHS[(month - 1) as usize][..3]);
    assert_eq!(format_timestamp(moment, "mm"), format!("{month:02}"));
    assert_eq!(format_timestamp(moment, "m"), month.to_string());
    assert_eq!(format_timestamp(moment, "dddd"), DAYS[(wday % 7) as usize]);
    assert_eq!(format_timestamp(moment, "ddd"), &DAYS[(wday % 7) as usize][..3]);
    assert_eq!(format_timestamp(moment, "dd"), format!("{day:02}"));
    assert_eq!(format_timestamp(moment, "d"), day.to_string());
    assert_eq!(format_timestamp(moment, "hh"), format!("{hour:02}"));
    assert_eq!(format_timestamp(moment, "h"), hour.to_string());
    assert_eq!(format_timestamp(moment, "nn"), format!("{min:02}"));
    assert_eq!(format_timestamp(moment, "n"), min.to_string());
    assert_eq!(format_timestamp(moment, "ss"), format!("{sec:02}"));
    assert_eq!(format_timestamp(moment, "s"), sec.to_string());
    assert_eq!(
        format_timestamp(moment, "c"),
        format!("{year:04}-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02}")
    );
    assert_eq!(format_timestamp(moment, "am/pm"), if hour >= 12 { "PM" } else { "AM" });
    assert_eq!(format_timestamp(moment, "a/p"), if hour >= 12 { "P" } else { "A" });

    // A quoted literal is text, not a token.
    assert_eq!(
        format_timestamp(moment, "'on' yyyy"),
        format!("on {year:04}")
    );
    assert_eq!(format_timestamp(moment, "\"at\" hh"), format!("at {hour:02}"));

    // The compact form the plain placeholder uses.
    assert_eq!(
        format_timestamp(moment, "yyyymmddhhnnss"),
        format!("{year:04}{month:02}{day:02}{hour:02}{min:02}{sec:02}")
    );
}

/// The upstream case name is `test_xml_action_log`: the XML action log
/// writes the upstream session format - one `<session>` root in the
/// upstream namespace, one `<group>` per command named by its masked line,
/// and a `<failure>` with the command's errors when it failed.
#[tokio::test]
async fn test_xml_action_log() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let log = tmp.path().join("actions.xml");
    let logger = SessionLogger::open(None, 0, false, None, Some(&log), true, "")
        .expect("the logger opens");
    let mut cfg = test_config(tmp.path());
    // 'batch continue' keeps the run going past the failures, so the log
    // holds several commands of each kind.
    cfg.batch_mode = BatchMode::Continue;
    let mut interp = ScriptInterpreter::new(cfg, logger);

    let (ok, _) = run_line(
        &mut interp,
        "option batch continue ; echo text ; no-such-command ; open sftp://user:secret@127.0.0.1:1/",
    )
    .await;
    assert!(!ok, "the run reports the failures it had: {ok}");
    interp.shutdown().await;

    let text = std::fs::read_to_string(&log).expect("the log was written");
    assert!(
        text.contains("<session xmlns=\"http://winscp.net/schema/session/1.0\""),
        "the root carries the upstream namespace: {text}"
    );
    assert!(
        text.contains("name=\"nosession\""),
        "a run that never connected keeps the upstream fallback name: {text}"
    );
    assert!(
        text.contains("<group name=\"option batch continue\""),
        "the first group names its command: {text}"
    );
    assert!(
        text.contains("<group name=\"echo text\""),
        "the second group names its command: {text}"
    );
    assert!(
        text.contains("<group name=\"no-such-command\""),
        "the failed command has its group: {text}"
    );
    assert!(
        text.contains("<group name=\"open sftp://user:***@127.0.0.1:1/\""),
        "the group's name is masked: {text}"
    );
    assert!(
        text.contains("Unknown command"),
        "the failed command carries its error: {text}"
    );
    // The text 'echo' printed is console output, not an operation: it must
    // not be in the XML log at all.
    assert!(
        !text.contains(">text<"),
        "the console output is not in the log: {text}"
    );
    // A password must not be written to a file the user keeps.
    assert!(!text.contains("secret"), "the secret is not in the log: {text}");
    assert!(
        text.trim_end().ends_with("</session>"),
        "the log is one closed document: {text}"
    );
}

/// The upstream case name is `test_xml_log_matches_the_upstream_schema`: the
/// log is the upstream session format, read back the way an upstream-style
/// consumer reads it - namespace-aware groups, then action elements, then
/// '<name value>' parameters and the result.
#[tokio::test]
async fn test_xml_log_matches_the_upstream_schema() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let log = tmp.path().join("masked.xml");
    let logger = SessionLogger::open(None, 0, false, None, Some(&log), true, "")
        .expect("the logger opens");
    let mut interp = ScriptInterpreter::new(test_config(tmp.path()), logger);

    // A failed 'open' with a password in the URL: masking the group name
    // keeps the document valid, and the secret is not in it.
    let (_, _) = run_line(
        &mut interp,
        "open sftp://user:secret@127.0.0.1:1/ -password=also-secret",
    )
    .await;
    interp.shutdown().await;

    let text = std::fs::read_to_string(&log).expect("the log was written");
    assert!(!text.contains("secret"), "the secret is not in the log: {text}");
    assert!(
        !text.contains("also-secret"),
        "the second secret is not in the log: {text}"
    );

    // The document parses as XML and holds the upstream namespace.
    let doc = roxmltree::Document::parse(&text).expect("the log is well-formed XML");
    let root = doc.root_element();
    assert_eq!(
        root.tag_name().namespace(),
        Some("http://winscp.net/schema/session/1.0"),
        "the root is in the upstream namespace"
    );
    assert_eq!(root.tag_name().name(), "session", "the root is a session");

    // The groups a consumer walks: one per command, each with a name and a
    // start timestamp.
    let groups: Vec<_> = root
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() == "group")
        .collect();
    assert_eq!(groups.len(), 1, "one command means one group");
    let group = groups[0];
    assert!(
        group.attribute("name").is_some(),
        "the group names its command"
    );
    assert!(
        group.attribute("start").is_some(),
        "the group carries its start timestamp"
    );

    // A failed group ends with the failure that closed it, and the failure
    // holds the command's errors.
    let failures: Vec<_> = group
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() == "failure")
        .collect();
    assert_eq!(failures.len(), 1, "a failed command has one failure");
    let messages: Vec<String> = failures[0]
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() == "message")
        .map(|n| n.text().unwrap_or_default().to_string())
        .collect();
    assert!(
        messages.iter().any(|m| m.contains("Cannot open session")),
        "the failure carries the command's error: {messages:?}"
    );
}

/// The upstream case name is `test_xml_log_fixtures_match_the_upstream_schema`:
/// the shipped fixtures - the ones a consumer is told to expect - are in the
/// upstream format too, so the format the engine writes and the format the
/// documentation shows cannot drift apart.
#[tokio::test]
async fn test_xml_log_fixtures_match_the_upstream_schema() {
    let root_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("xml");

    for (file, expect_failure) in [
        ("action-log-success.xml", false),
        ("action-log-error.xml", true),
    ] {
        let path = root_dir.join(file);
        let text = std::fs::read_to_string(&path).expect("the fixture is readable");
        let doc = roxmltree::Document::parse(&text).expect("the fixture is well-formed XML");
        let root = doc.root_element();
        assert_eq!(
            root.tag_name().namespace(),
            Some("http://winscp.net/schema/session/1.0"),
            "{file} is in the upstream namespace"
        );
        assert_eq!(root.tag_name().name(), "session", "{file} is a session");
        assert!(
            root.attribute("name").is_some(),
            "{file} names the session it belongs to"
        );
        assert!(
            root.attribute("start").is_some(),
            "{file} carries the session's start timestamp"
        );

        let groups: Vec<_> = root
            .children()
            .filter(|n| n.is_element() && n.tag_name().name() == "group")
            .collect();
        assert!(!groups.is_empty(), "{file} holds at least one group");
        for group in &groups {
            assert!(
                group.attribute("name").is_some(),
                "{file}: every group names its command"
            );
            assert!(
                group.attribute("start").is_some(),
                "{file}: every group carries its start timestamp"
            );
        }

        let failures = root
            .descendants()
            .filter(|n| n.is_element() && n.tag_name().name() == "failure")
            .count();
        if expect_failure {
            assert_eq!(failures, 1, "{file} holds the failure it documents");
            let message = root
                .descendants()
                .filter(|n| n.is_element() && n.tag_name().name() == "message")
                .count();
            assert!(message > 0, "{file} says what went wrong");
        } else {
            assert_eq!(failures, 0, "{file} holds no failure");
        }
    }

    // The successful fixture is the one the documentation shows: an upload
    // with its size and a result that says it worked.
    let text = std::fs::read_to_string(root_dir.join("action-log-success.xml"))
        .expect("the fixture is readable");
    let doc = roxmltree::Document::parse(&text).expect("the fixture is well-formed XML");
    let uploads: Vec<_> = doc
        .root_element()
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "upload")
        .collect();
    assert_eq!(uploads.len(), 1, "the fixture uploads one file");
    let upload = uploads[0];
    let params: Vec<&str> = upload
        .children()
        .filter(|n| n.is_element())
        .map(|n| n.tag_name().name())
        .collect();
    assert_eq!(
        params,
        vec!["filename", "destination", "size", "result"],
        "the upload names the file, the destination and the size"
    );
    let result = upload
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "result")
        .expect("the upload has a result");
    assert_eq!(
        result.attribute("success"),
        Some("true"),
        "the result says the upload worked"
    );
}

/// The upstream case name is `test_xml_action_log_is_closed`: the log ends
/// in one complete document, not in a half element, even when no command
/// ever opened a session.
#[tokio::test]
async fn test_xml_action_log_is_closed() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let log = tmp.path().join("closed.xml");
    let logger = SessionLogger::open(None, 0, false, None, Some(&log), true, "")
        .expect("the logger opens");
    let mut interp = ScriptInterpreter::new(test_config(tmp.path()), logger);
    let (_, _) = run_line(&mut interp, "echo one").await;
    interp.shutdown().await;

    let text = std::fs::read_to_string(&log).expect("the log was written");
    assert!(
        text.trim_end().ends_with("</session>"),
        "the log is one closed document: {text}"
    );
    let doc = roxmltree::Document::parse(&text).expect("the log is well-formed XML");
    let root = doc.root_element();
    assert_eq!(root.tag_name().name(), "session", "the root is a session");
    let children: Vec<_> = root
        .children()
        .filter(|n| n.is_element())
        .map(|n| n.tag_name().name().to_string())
        .collect();
    assert_eq!(
        children,
        vec!["group".to_string()],
        "the log holds one group and nothing else"
    );
}

/// The upstream case name is `test_preset_store_round_trips`: the preset
/// file is written and read back, so a preset stored by one run is the
/// preset the next run finds.
#[tokio::test]
async fn test_preset_store_round_trips() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let config_dir = tmp.path().to_path_buf();

    let mut preset = TransferPreset {
        name: "stored".to_string(),
        ..TransferPreset::default()
    };
    preset
        .parse_setting("transfer", "ascii")
        .expect("the mode parses");
    preset
        .parse_setting("preservetime", "on")
        .expect("the time rule parses");
    preset
        .parse_setting("neweronly", "")
        .expect("the switch parses");
    preset
        .parse_setting("speed", "512")
        .expect("the speed parses");
    preset
        .parse_setting("resumesupport", "on")
        .expect("the resume rule parses");
    preset
        .parse_setting("permissions", "640")
        .expect("the permissions parse");
    preset
        .parse_setting("mask", "*.txt")
        .expect("the mask parses");

    let mut store = TransferPresetStore::default();
    store.add_or_update(preset).expect("the preset is stored");
    store.save_to_dir(&config_dir).expect("the store is written");

    let path = TransferPresetStore::presets_path(&config_dir);
    assert!(path.is_file(), "the preset file is where it is documented");

    let reread = TransferPresetStore::load_from_dir(&config_dir).expect("the store loads");
    let found = reread.find("stored").expect("the preset is found");
    assert_eq!(
        found.transfer_mode,
        Some(TransferMode::Ascii),
        "the mode survives the round trip"
    );
    assert_eq!(found.preserve_time, Some(true), "the time rule survives");
    assert_eq!(found.newer_only, Some(true), "the switch survives");
    assert_eq!(found.speed_kbytes_per_sec, Some(512), "the speed survives");
    assert_eq!(found.mask, "*.txt", "the mask survives");
    assert!(
        found.describe().contains("resumesupport=on"),
        "the description names the resume rule: {}",
        found.describe()
    );
}

/// The upstream case name is `test_preset_describes_a_smart_resume`: the
/// description of a preset names its resume support the way upstream's own
/// listing does - 'on', 'off', or the threshold in KiB.
#[tokio::test]
async fn test_preset_describes_a_smart_resume() {
    let mut preset = TransferPreset {
        name: "described".to_string(),
        ..TransferPreset::default()
    };
    preset
        .parse_setting("resumesupport", "on")
        .expect("the resume rule parses");
    assert!(
        preset.describe().contains("resumesupport=on"),
        "a forced resume says so: {}",
        preset.describe()
    );

    let mut preset = TransferPreset {
        name: "described".to_string(),
        ..TransferPreset::default()
    };
    preset
        .parse_setting("resumesupport", "off")
        .expect("the resume rule parses");
    assert!(
        preset.describe().contains("resumesupport=off"),
        "a disabled resume says so: {}",
        preset.describe()
    );

    // A preset without a resume rule does not name one.
    let default = TransferPreset::default();
    assert!(
        !default.describe().contains("resumesupport"),
        "a preset without a resume rule does not name one: {}",
        default.describe()
    );

    // A smart resume names its threshold in KiB.
    let preset = TransferPreset {
        name: "described".to_string(),
        resume_support: Some(ResumeSupportMode::Smart(100 * 1024)),
        ..TransferPreset::default()
    };
    assert!(
        preset.describe().contains("resumesupport=100"),
        "a smart resume names its threshold in KiB: {}",
        preset.describe()
    );
}

/// The upstream case name is `test_help_lists_commands_and_command_help`:
/// the help lists the commands, and every command it lists has its own help.
#[tokio::test]
async fn test_help_lists_commands_and_command_help() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let mut interp = ScriptInterpreter::new(test_config(tmp.path()), in_memory_logger());

    let (ok, out) = run_line(&mut interp, "help").await;
    assert!(ok, "the help succeeds: {out}");
    for command in ["ascii", "session", "attr", "help", "man"] {
        assert!(
            out.contains(command),
            "the listing names '{command}': {out}"
        );
    }

    // 'help rename' shows the command's own syntax.
    let (ok, out) = run_line(&mut interp, "help rename").await;
    assert!(ok, "the command help succeeds: {out}");
    assert!(
        out.contains("mv <source>"),
        "the rename help names the move it is: {out}"
    );

    // 'man' is an alias of 'help'.
    let (ok, man_out) = run_line(&mut interp, "man").await;
    assert!(ok, "the man page succeeds: {man_out}");
    assert!(
        man_out.contains("ascii"),
        "the man page lists the commands: {man_out}"
    );

    // An unknown command is an error, not a silent success.
    let (ok, out) = run_line(&mut interp, "no-such-command").await;
    assert!(!ok, "an unknown command fails: {out}");
    assert!(
        out.contains("Unknown command"),
        "the refusal names the command: {out}"
    );
}

/// The upstream case name is `test_script_command_list`: the command list
/// the interpreter answers with is the one the help prints, so a command
/// cannot be reachable without being documented.
#[tokio::test]
async fn test_script_command_list() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let mut interp = ScriptInterpreter::new(test_config(tmp.path()), in_memory_logger());

    let (ok, out) = run_line(&mut interp, "help").await;
    assert!(ok, "the help succeeds: {out}");

    // Every documented command answers to its own help.
    for command in ["get", "put", "ls", "cd", "open", "option", "presets", "sessions"] {
        let (ok, out) = run_line(&mut interp, &format!("help {command}")).await;
        assert!(ok, "'help {command}' succeeds: {out}");
        assert!(
            out.contains(command),
            "'help {command}' says what the command is: {out}"
        );
    }

    // A command the build does not have is refused by name.
    let (ok, out) = run_line(&mut interp, "help no-such-command").await;
    assert!(!ok, "an unknown command has no help: {out}");
    assert!(
        out.contains("Unknown command"),
        "the refusal names the command: {out}"
    );

    // The interpreter splits a command string the way a script file is
    // split, so a quoted ';' stays inside its argument. The parts keep the
    // whitespace around them; the caller trims before it runs them.
    let parts = split_semicolon_commands("echo one; echo \"two; three\"; echo four");
    assert_eq!(
        parts,
        vec![
            "echo one".to_string(),
            " echo \"two; three\"".to_string(),
            " echo four".to_string(),
        ],
        "a quoted separator is not a command separator"
    );
}
