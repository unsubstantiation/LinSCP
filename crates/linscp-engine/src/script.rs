//! Full LinSCP script interpreter, interactive REPL, `-server` automation loop
//! (`LSCP-SERVER 1 ready` / `LSCP-RESULT 0|1`), and interactive SSH PTY `-shell`
//! runner (`xterm-256color`, `SIGWINCH`, strict `EOF` + `exit-status` check).

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use linscp_i18n::{CatalogDomain, translate, translate_with};
use linscp_platform::terminal::{
    RawTerminalGuard, expand_tilde, launch_desktop_ssh_terminal, read_stdin_chunk, stat_local_path,
    stdin_is_terminal, take_window_resized, terminal_size,
};
use linscp_proto::RemoteSession;
use linscp_proto::ssh::{ChannelMsg, SshConnection, extract_openssh_public_key_line};
use linscp_proto::webdav::DavEtagPrecondition;
use linscp_types::{FileEntry, ProtocolScheme, TransferMode};

use crate::editor::{EditOptions, edit_remote_file};
use crate::filemask::{
    FileMask, format_file_clock, format_file_date, format_ls_time, format_permissions_10,
    has_wildcard, join_remote_path, matches_wildcard, mode_from_permissions_str,
    parse_permissions_expr, remote_parent_and_name, resolve_remote_path,
};
use crate::keepuptodate::{KeepUpToDateOptions, run_keep_up_to_date};
use crate::presets::{PresetPermissions, ResumeSupportMode, TransferPreset, TransferPresetStore};
use crate::script_params::{
    PrefixMatch, expand_script_parameters, resolve_prefixed_name, tokenize_script_line,
};
use crate::session_store::SessionStore;
use crate::sync_planner::{
    SyncConflictPolicy, SyncCriteria, SyncMode, SyncOptions, SyncState, apply_sync_plan,
    plan_synchronization,
};
use crate::text_mode::{EolStyle, parse_transfer_mode, transfer_mode_name};
use crate::transfer::{
    TransferFlags, download_directory_recursive, download_single_file, upload_directory_recursive,
    upload_single_file,
};
use crate::url_and_raw::{
    DefaultOsVault, ParsedSiteSpec, apply_env_credential_fallbacks, apply_raw_settings,
    connect_site_spec, connect_ssh_for_shell, is_ssh_scheme, is_webdav_scheme, parse_site_url,
    site_spec_from_stored, stored_site_from_spec,
};
use crate::xml_log::SessionLogger;

/// Resolves the active CLI locale from environment variables following
/// `LINSCP_LANGUAGE` > `LC_ALL` > `LC_MESSAGES` > `LANG` (empty values fall
/// through; `C`/`POSIX` keep English).
pub fn select_cli_locale_from_env() -> String {
    for var in ["LINSCP_LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(val) = std::env::var(var) {
            if !val.is_empty() {
                if val == "C" || val == "POSIX" {
                    return "en".to_string();
                }
                return val;
            }
        }
    }
    "en".to_string()
}

pub const COMMAND_NAMES: &[&str] = &[
    "!",
    "ascii",
    "attr",
    "binary",
    "bye",
    "call",
    "cd",
    "checksum",
    "chmod",
    "close",
    "copyid",
    "cp",
    "del",
    "delsession",
    "dir",
    "echo",
    "edit",
    "end",
    "etag",
    "exit",
    "get",
    "help",
    "keepuptodate",
    "lcd",
    "lls",
    "ln",
    "lock",
    "lpwd",
    "ls",
    "man",
    "md",
    "mkdir",
    "mget",
    "mput",
    "mv",
    "open",
    "option",
    "presets",
    "property",
    "pwd",
    "put",
    "quit",
    "recv",
    "rename",
    "rm",
    "rmdir",
    "rmsession",
    "rmspreset",
    "send",
    "session",
    "sessions",
    "stat",
    "savepreset",
    "savesession",
    "show",
    "symlink",
    "sync",
    "synchronize",
    "terminal",
    "unlock",
    "versions",
    "?",
];

/// Exact English help keys matching `locales/*.json` (`cli` catalog).
const SCRIPT_COMMAND_HELPS: &[(&str, &str)] = &[
    (
        "ascii",
        "ascii\n  Transfers files in ASCII mode: line endings are converted\n  (CRLF to LF when downloading, LF to CRLF when uploading).",
    ),
    (
        "attr",
        "attr <file>\n  Prints path, size, permissions, modification time and owner\n  of a remote file, one key/value line each.",
    ),
    (
        "binary",
        "binary\n  Transfers files in binary mode (no conversion).",
    ),
    ("bye", "bye\n  Ends the session and exits."),
    (
        "call",
        "call <command>\n  Executes a command on the server through the SSH 'exec'\n  channel and prints its output. '! <command>' is the same.",
    ),
    (
        "cd",
        "cd [ <directory> ]\n  Changes the remote working directory; without an argument\n  it goes to the home directory.",
    ),
    (
        "checksum",
        "checksum <algorithm> <file>\n  Calculates a checksum (sha-256, sha-1, md5 or crc32) of a\n  remote file, on the server when it can, locally otherwise.",
    ),
    (
        "chmod",
        "chmod <mode> <file> [ <file>... ] [ -recursive ]\n  Changes permissions of remote files. <mode> is octal\n  (644, 0700) or symbolic (u+x, go-w, a=r,go-w, u+s); with\n  -recursive everything below a directory is changed too,\n  symbolic links excepted.",
    ),
    (
        "close",
        "close [ <index> ]\n  Closes the open session, or the session at the 1-based\n  <index> (only one connection is open at a time).",
    ),
    (
        "copyid",
        "copyid [ <keyfile> ]\n  Installs the public key of the private key in use (or of\n  <keyfile>) into ~/.ssh/authorized_keys on the server, so\n  that later connections need no password. Requires a SFTP\n  or SCP session and a key this build can read.",
    ),
    (
        "cp",
        "cp <source> [ <source>... ] <target>\n  Copies files on the server, server-side when it can,\n  streamed through this client otherwise.",
    ),
    ("echo", "echo <message>\n  Prints the message."),
    (
        "edit",
        "edit <file>\n  Downloads the file, opens it in the configured editor and\n  uploads it back when it changed.",
    ),
    ("exit", "exit\n  Ends the session and exits."),
    (
        "get",
        "get [ <switches> ] <file> [ <file>... ] [ <target> ]\n  Downloads files. Switches: -delete, -resume, -append,\n  -resumesupport=on|off|<KB>, -speed=<KB/s>, -neweronly,\n  -noneweronly, -latest, -preservetime, -preservetime=all,\n  -nopreservetime, -r, -transfer=binary|ascii|automatic,\n  -permissions[=<mode>], -nopermissions, -versionid=<ID>,\n  -rawtransfersettings[=<count>], -filemask=<mask>.\n  -latest transfers only the newest file the command named,\n  by the source's modification time.\n  For S3, -versionid downloads that exact object version; it\n  stages separately per version so resumes never mix versions.\n  Without a value, -permissions gives the downloaded file\n  the permissions of the remote one.",
    ),
    (
        "help",
        "help [ <command> ]\n  Prints the list of commands, or the help of one command.",
    ),
    (
        "keepuptodate",
        "keepuptodate [ <localdir> [ <remotedir> ] ]\n  Reflects local changes on the remote side, watching the local\n  tree with inotify. -interval=<seconds>, -count=<passes>,\n  -delete, -continue, -filemask=, -transfer=.",
    ),
    (
        "lcd",
        "lcd <directory>\n  Changes the local working directory.",
    ),
    (
        "lls",
        "lls [ <directory>[/<mask>] ]\n  Lists the local working directory.",
    ),
    (
        "ln",
        "ln <target> <link>\n  Creates a symbolic link on the server.",
    ),
    ("lpwd", "lpwd\n  Prints the local working directory."),
    (
        "ls",
        "ls [ <directory>[/<mask>] ]\n  Lists the remote directory (switches: -l, -a, -1).",
    ),
    ("man", "man [ <command> ]\n  Same as 'help'."),
    (
        "mkdir",
        "mkdir [-parents] <directory>\n  Creates a remote directory. -parents creates missing parents\n  and accepts an existing directory (a LinSCP extension).",
    ),
    (
        "mv",
        "mv <source> [ <source>... ] <target>\n  Moves or renames remote files; with several sources the\n  target must be an existing directory.",
    ),
    (
        "open",
        "open <site> [-hostkey=KEY] [-password=PWD] [-username=NAME]\n        [-privatekey=FILE] [-passphrase=PHR] [-clientcert=FILE]\n        [-timeout=SEC] [-implicit[=on|off]] [-explicit[=on|off]]\n        [-passive[=on|off]] [-sessionname=NAME]\n        [-rawsettings NAME=VALUE...]\n  Connects to a site given as a URL or a stored session name;\n  the switches apply to a stored site as well as to a URL.\n  -timeout is the server response timeout in seconds.\n  -implicit and -explicit choose the TLS mode of an FTP\n  session (implicit TLS uses port 990 when the URL names no\n  port); -passive turns the FTP data connection policy on or\n  off; -clientcert is the TLS client certificate file;\n  -sessionname is the name this connection is logged under.\n  -rawsettings sets session settings by upstream's names. This\n  build applies the proxy ones (ProxyMethod=None|SOCKS4|SOCKS5|\n  HTTP|Telnet|Cmd, ProxyHost, ProxyPort, ProxyUsername,\n  ProxyPassword, ProxyTelnetCommand, ProxyLocalCommand,\n  ProxyDNS=0|1|2, ProxyLocalhost=0|1, ProxyExcludeList), the FTP\n  engine's policy (FtpPasvMode=0|1, FtpForcePasvIp=0|1|2,\n  FtpUseMlsd=0|1|2, FtpAccount) and the TLS policy (Ftps=0|1|2|3,\n  MinTlsVersion, MaxTlsVersion, TlsCertificateFile,\n  TlsCertificateKeyFile, CaCertificateFile, CaCertificateDir,\n  PinnedPublicKey); any other setting is refused rather than\n  dropped.",
    ),
    (
        "option",
        "option [ <name> [ <value> ] ]\n  Shows or changes a setting: echo, batch, confirm, resume,\n  transfer, include, exclude, failonnomatch, synchdelete,\n  reconnecttime, editor, editmaxsize, preset. Without a name it\n  prints every setting; a name or a value may be abbreviated\n  as long as the abbreviation is unambiguous.",
    ),
    (
        "presets",
        "presets\n  Lists the transfer presets from the user configuration.\n  A preset is stored with 'savepreset <name> <setting>...'\n  (transfer=binary|ascii|automatic, preservetime=on|off|all,\n  neweronly, speed=<KB/s>, resumesupport=on|off|<KB>,\n  permissions=<octal>|off|fromfile, host=, user=, remotedir=,\n  localdir=, mask=); 'rmspreset <name>' removes one.\n  'option preset <name>' makes a preset the default for the\n  following transfer commands, 'option preset off' disables\n  presets for this session (even matching rules); a stored\n  site loads its own when it is opened.",
    ),
    (
        "put",
        "put [ <switches> ] <file> [ <file>... ] [ <target> ]\n  Uploads files; the switches of 'get' (on uploads,\n  -permissions without a value keeps the local file's own\n  mode on the server); -append adds to the remote file\n  instead of replacing it (native SFTP only, and not\n  together with -resume); -latest uploads only the newest\n  local file the command named.",
    ),
    ("pwd", "pwd\n  Prints the remote working directory."),
    (
        "rm",
        "rm [ -onlyfile ] [ -versionid=ID ] <file> [ <file>... ]\n  Deletes remote files (masks allowed); -onlyfile skips\n  directories. On S3, -versionid deletes just that version\n  (including a delete marker) instead of the current object.",
    ),
    (
        "rmdir",
        "rmdir <directory> [ <directory>... ]\n  Deletes empty remote directories.",
    ),
    (
        "rmsession",
        "rmsession <name>\n  Removes the stored session <name>.",
    ),
    (
        "rmspreset",
        "rmspreset <name>\n  Removes the transfer preset <name>; if it was active,\n  transfers go back to their own settings.",
    ),
    (
        "savepreset",
        "savepreset <name> <setting>[=<value>]...\n  Stores or updates a transfer preset; settings without a\n  value (neweronly) are switches. See 'help presets'.",
    ),
    (
        "savesession",
        "savesession <name> [ options ]\n  Stores the current session, or the one the options\n  describe, under <name>; -preset=NAME also stores the\n  transfer preset the site should load (-preset= clears it),\n  and -rawsettings NAME=VALUE... stores session settings with\n  it (the ones 'open -rawsettings' applies: proxy, FTP engine\n  and TLS policy; a proxy password is encrypted like a session\n  password).",
    ),
    (
        "show",
        "show\n  Not available in this build: the connection runs the SFTP\n  subsystem, so remote shell commands cannot be shown.",
    ),
    (
        "session",
        "session [ <index> ]\n  Lists the open sessions and prints which one is active;\n  with a 1-based <index> it switches to that session.",
    ),
    (
        "sessions",
        "sessions [ NAME | list | export <file> | import <file> ]\n  Lists the stored sites, opens one by name, or exports and\n  imports the whole list.",
    ),
    (
        "etag",
        "etag <file> -match=ETAG | -nomatch=ETAG | -get | -clear\n  Records an ETag precondition for one WebDAV path with this\n  session: an upload, a delete or a move of that path then\n  sends it in the If header next to any lock token, so the\n  server refuses (412) a write over a version this client has\n  not seen instead of accepting it. '-get' prints the ETag the\n  server reports now and says so when the path is not there,\n  '-clear' forgets the precondition. Give exactly one of the\n  four. A protocol with no ETags is refused rather than left\n  believing a write is conditional.",
    ),
    (
        "lock",
        "lock <file> [-timeout=SECONDS]\n  Takes an exclusive WebDAV write lock on one file and\n  remembers its token: uploads, deletes and moves of that\n  path then carry it, so the server refuses a write the lock\n  should prevent instead of accepting it.",
    ),
    (
        "property",
        "property <file> -get=NAME | property <file> -set=NAME=VALUE\n  Reads or writes one WebDAV dead property of a file, in this\n  client's own namespace. '-get' prints 'NAME is not set' when\n  the server says the property does not exist.",
    ),
    (
        "stat",
        "stat <file>\n  Prints the listing line of a remote path, as ls -l shows\n  it. The key/value breakdown of attr stays available there.",
    ),
    (
        "synchronize",
        "synchronize local|remote|both [ <localdir> [ <remotedir> ] ]\n  [ -delete ] [-nodelete] [-mirror] [-preview]\n  [-criteria=time|size|checksum|either|both|none] [-filemask=<mask>]\n  [-transfer=binary|ascii|automatic] [-nonrecursive]\n  The criteria say what counts as a change: 'time' (the\n  default) copies a file the source has newer, 'size' one of\n  a different size, 'checksum' one whose contents differ and\n  'none' every file. 'either' and its synonym 'both' compare\n  the time and the size, and the three comparisons may also\n  be listed, as in -criteria=time,checksum. In the 'both'\n  direction the record of the previous synchronization\n  decides, so 'checksum' and 'none' are refused there.",
    ),
    (
        "symlink",
        "symlink <target> <link>\n  Same as 'ln'.",
    ),
    (
        "terminal",
        "terminal\n  Opens an interactive shell terminal on the server.",
    ),
    (
        "unlock",
        "unlock <file>\n  Releases the lock 'lock <file>' took in this session.",
    ),
    (
        "versions",
        "versions [ <object-or-prefix> ]\n  Lists S3 object versions and delete markers. An object path\n  lists that exact key; a bucket or trailing-slash prefix\n  lists every matching key. Results are paginated.",
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchMode {
    Off,
    On,
    Abort,
    Continue,
}

impl BatchMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::On => "on",
            Self::Abort => "abort",
            Self::Continue => "continue",
        }
    }

    pub fn aborts_script(self) -> bool {
        matches!(self, Self::On | Self::Abort)
    }

    pub fn is_non_interactive(self) -> bool {
        !matches!(self, Self::Off)
    }
}

struct ConnectedSlot {
    spec: ParsedSiteSpec,
    session: Box<dyn RemoteSession>,
    remote_cwd: String,
}

pub struct ScriptRunConfig {
    pub config_dir: PathBuf,
    pub locale: String,
    pub batch_mode: BatchMode,
    pub confirm: bool,
    pub echo: bool,
    pub log_level: i32,
    pub server_mode: bool,
    pub parameters: Vec<String>,
}

impl Default for ScriptRunConfig {
    fn default() -> Self {
        Self {
            config_dir: linscp_platform::default_config_dir(),
            locale: select_cli_locale_from_env(),
            batch_mode: BatchMode::Off,
            confirm: true,
            echo: false,
            log_level: 0,
            server_mode: false,
            parameters: Vec::new(),
        }
    }
}

pub struct ScriptInterpreter {
    cfg: ScriptRunConfig,
    logger: SessionLogger,
    local_cwd: PathBuf,
    slots: Vec<ConnectedSlot>,
    active_slot: usize,

    transfer_mode: TransferMode,
    resume_support: ResumeSupportMode,
    option_mask: FileMask,
    option_mask_used: bool,
    fail_on_nomatch: bool,
    synch_delete: bool,
    reconnect_time_secs: u64,
    editor_cmd: String,
    edit_max_size: u64,
    active_preset_name: Option<String>,
    presets_disabled: bool,

    errors: usize,
    should_exit: bool,
}

impl ScriptInterpreter {
    pub fn new(cfg: ScriptRunConfig, logger: SessionLogger) -> Self {
        let local_cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        Self {
            cfg,
            logger,
            local_cwd,
            slots: Vec::new(),
            active_slot: 0,
            transfer_mode: TransferMode::Binary,
            resume_support: ResumeSupportMode::Smart(100 * 1024),
            option_mask: FileMask::default(),
            option_mask_used: false,
            fail_on_nomatch: true,
            synch_delete: false,
            reconnect_time_secs: 120,
            editor_cmd: String::new(),
            edit_max_size: 16 * 1024 * 1024,
            active_preset_name: None,
            presets_disabled: false,
            errors: 0,
            should_exit: false,
        }
    }

    pub fn error_count(&self) -> usize {
        self.errors
    }

    pub fn should_exit(&self) -> bool {
        self.should_exit
    }

    fn tr<'a>(&self, msg: &'a str) -> &'a str {
        translate(CatalogDomain::Cli, &self.cfg.locale, msg)
    }

    fn trp(&self, msg: &str, values: &[(&str, &str)]) -> String {
        translate_with(CatalogDomain::Cli, &self.cfg.locale, msg, values)
    }

    fn wrong_args(&self, cmd: &str, hint: &str) -> String {
        self.trp(
            "Wrong arguments of '{command}' command. {hint}",
            &[("command", cmd), ("hint", hint)],
        )
    }

    pub async fn shutdown(&mut self) {
        for slot in self.slots.drain(..) {
            let _ = slot.session.close().await;
        }
        self.logger.finish();
    }

    fn emit_error(&mut self, msg: &str) {
        let _ = writeln!(std::io::stderr(), "{msg}");
        let _ = std::io::stderr().flush();
        self.logger.record_group_failure(msg);
        self.errors += 1;
    }

    fn emit_status(&self, msg: &str) {
        if self.cfg.log_level >= 0 {
            println!("{msg}");
            let _ = std::io::stdout().flush();
        }
    }

    fn is_interactive_confirm(&self) -> bool {
        !self.cfg.server_mode
            && !self.cfg.batch_mode.is_non_interactive()
            && self.cfg.confirm
            && stdin_is_terminal()
    }

    fn is_interactive_auth(&self) -> bool {
        !self.cfg.server_mode
            && !self.cfg.batch_mode.is_non_interactive()
            && stdin_is_terminal()
    }

    pub async fn connect_initial_site(&mut self, mut spec: ParsedSiteSpec) -> Result<(), String> {
        apply_env_credential_fallbacks(&mut spec);
        let log_res = self.open_slot_from_spec(spec).await;
        if let Err(ref e) = log_res {
            self.emit_error(e);
        }
        log_res
    }

    async fn open_slot_from_spec(&mut self, mut spec: ParsedSiteSpec) -> Result<(), String> {
        if !spec.session.local_dir.is_empty() {
            let expanded = PathBuf::from(expand_tilde(&spec.session.local_dir));
            if expanded.is_dir() {
                self.local_cwd = expanded;
            }
        }
        if !spec.preset_name.is_empty() {
            self.active_preset_name = Some(spec.preset_name.clone());
            self.presets_disabled = false;
        }

        let session = connect_site_spec(
            &spec,
            &self.cfg.config_dir,
            self.is_interactive_confirm(),
            self.is_interactive_auth(),
            &self.cfg.locale,
            self.cfg.log_level,
            None,
        )
        .await?;

        let remote_cwd = if !spec.session.initial_dir.is_empty() {
            let want = resolve_remote_path("/", &spec.session.initial_dir);
            session.realpath(&want).await.unwrap_or(want)
        } else {
            session.pwd().await.unwrap_or_else(|_| "/".to_string())
        };
        spec.timeout_secs = self.reconnect_time_secs.max(spec.timeout_secs);
        self.slots.push(ConnectedSlot {
            spec,
            session,
            remote_cwd,
        });
        self.active_slot = self.slots.len() - 1;
        Ok(())
    }

    fn active_slot(&self) -> Result<&ConnectedSlot, String> {
        self.slots.get(self.active_slot).ok_or_else(|| {
            self.tr("Not connected. Use 'open' to connect to a site first.")
                .to_string()
        })
    }

    /// Executes `-command=...` splitting unquoted `;` into individual commands.
    pub async fn run_command_string(&mut self, command_text: &str, literal: bool) -> i32 {
        let parts = split_semicolon_commands(command_text);
        for part in parts {
            let trimmed = part.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let ok = self.execute_line_with_mode(trimmed, literal).await;
            if self.should_exit {
                break;
            }
            if !ok && self.cfg.batch_mode.aborts_script() {
                break;
            }
        }
        if self.errors == 0 { 0 } else { 1 }
    }

    /// Executes a script file's lines (`-script=...`). Each line may also contain `;`-separated commands.
    pub async fn run_lines(&mut self, lines: &[String]) -> i32 {
        for raw in lines {
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                continue;
            }
            for sub in split_semicolon_commands(trimmed) {
                let s = sub.trim();
                if s.is_empty() || s.starts_with('#') {
                    continue;
                }
                let ok = self.execute_line_with_mode(s, false).await;
                if self.should_exit {
                    return if self.errors == 0 { 0 } else { 1 };
                }
                if !ok && self.cfg.batch_mode.aborts_script() {
                    return if self.errors == 0 { 0 } else { 1 };
                }
            }
        }
        if self.errors == 0 { 0 } else { 1 }
    }

    /// Runs the interactive `sftp> ` prompt loop on stdin.
    pub async fn run_interactive_repl(&mut self) -> i32 {
        let stdin = std::io::stdin();
        let mut reader = stdin.lock();
        let mut line = String::new();
        loop {
            if stdin_is_terminal() {
                print!("sftp> ");
                let _ = std::io::stdout().flush();
            }
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => break,
            }
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                continue;
            }
            let ok = self.execute_line_with_mode(trimmed, false).await;
            if self.should_exit {
                break;
            }
            if !ok && self.cfg.batch_mode.aborts_script() {
                break;
            }
        }
        if self.errors == 0 { 0 } else { 1 }
    }

    /// Runs the `-server` automation protocol (`LSCP-SERVER 1 ready` -> `LSCP-RESULT 0|1`).
    pub async fn run_server_loop(&mut self) -> i32 {
        println!("LSCP-SERVER 1 ready");
        let _ = std::io::stdout().flush();

        let stdin = std::io::stdin();
        let mut reader = stdin.lock();
        let mut line = String::new();
        let mut any_failed = self.errors > 0;

        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => break,
            }
            let trimmed = line.trim_end_matches(['\r', '\n']).trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                println!("LSCP-RESULT 0");
                let _ = std::io::stdout().flush();
                continue;
            }
            let errs_before = self.errors;
            let ok = self.execute_line_with_mode(trimmed, true).await;
            let cmd_failed = !ok || self.errors > errs_before;
            if cmd_failed {
                any_failed = true;
            }
            let _ = std::io::stderr().flush();
            println!("LSCP-RESULT {}", if cmd_failed { 1 } else { 0 });
            let _ = std::io::stdout().flush();
            if self.should_exit {
                break;
            }
        }
        if any_failed { 1 } else { 0 }
    }

    pub async fn execute_line(&mut self, raw_line: &str) -> bool {
        let literal = self.cfg.server_mode;
        self.execute_line_with_mode(raw_line, literal).await
    }

    async fn execute_line_with_mode(&mut self, raw_line: &str, literal: bool) -> bool {
        let effective_line = if literal || self.cfg.server_mode {
            raw_line.to_string()
        } else {
            match expand_script_parameters(raw_line, &self.cfg.parameters) {
                Ok(s) => s,
                Err(err) => {
                    self.logger.begin_command_group(raw_line);
                    self.emit_error(&err);
                    self.logger.end_command_group();
                    return false;
                }
            }
        };

        if self.cfg.echo && !self.cfg.server_mode {
            println!("{}", crate::script_params::censored_for_log(&effective_line));
            let _ = std::io::stdout().flush();
        }

        let tokens = if let Some(rest) = effective_line.trim_start().strip_prefix('!') {
            let cmd_body = rest.trim();
            if cmd_body.is_empty() {
                vec!["!".to_string()]
            } else {
                vec!["!".to_string(), cmd_body.to_string()]
            }
        } else {
            match tokenize_script_line(&effective_line) {
                Ok(t) => t,
                Err(err) => {
                    self.logger.begin_command_group(&effective_line);
                    self.emit_error(&err);
                    self.logger.end_command_group();
                    return false;
                }
            }
        };

        if tokens.is_empty() {
            return true;
        }

        self.logger.begin_command_group(&effective_line);
        let cmd_raw = &tokens[0];
        let args = &tokens[1..];

        let canonical = match resolve_prefixed_name(COMMAND_NAMES, cmd_raw) {
            PrefixMatch::ExactOrUnique(name) => canonical_alias(name),
            PrefixMatch::Ambiguous(candidates) => {
                let msg = format!("Ambiguous command '{cmd_raw}' (matches: {candidates}).");
                self.emit_error(&msg);
                self.logger.end_command_group();
                return false;
            }
            PrefixMatch::None => {
                let msg = self.trp(
                    "Unknown command '{command}'. Type 'help' for a list of commands.",
                    &[("command", cmd_raw)],
                );
                self.emit_error(&msg);
                self.logger.end_command_group();
                return false;
            }
        };

        let res = match canonical {
            "exit" => {
                self.should_exit = true;
                Ok(())
            }
            "help" => self.cmd_help(args),
            "echo" => {
                println!("{}", args.join(" "));
                let _ = std::io::stdout().flush();
                Ok(())
            }
            "ascii" => {
                self.transfer_mode = TransferMode::Ascii;
                println!("{}", self.trp("{name} = {value}", &[("name", "transfer"), ("value", "ascii")]));
                Ok(())
            }
            "binary" => {
                self.transfer_mode = TransferMode::Binary;
                println!(
                    "{}",
                    self.trp("{name} = {value}", &[("name", "transfer"), ("value", "binary")])
                );
                Ok(())
            }
            "option" => self.cmd_option(args),
            "lpwd" => {
                println!("{}", self.local_cwd.display());
                Ok(())
            }
            "lcd" => self.cmd_lcd(args),
            "lls" => self.cmd_lls(args),
            "presets" => self.cmd_presets(args),
            "savepreset" => self.cmd_savepreset(args),
            "rmspreset" => self.cmd_rmspreset(args),
            "sessions" => self.cmd_sessions(args).await,
            "savesession" => self.cmd_savesession(args),
            "rmsession" => self.cmd_rmsession(args),
            "session" => self.cmd_session(args),
            "open" => self.cmd_open(args).await,
            "close" => self.cmd_close(args).await,
            "pwd" => self.cmd_pwd(args),
            "cd" => self.cmd_cd(args).await,
            "ls" => self.cmd_ls(args).await,
            "stat" => self.cmd_stat(args).await,
            "attr" => self.cmd_attr(args).await,
            "mkdir" => self.cmd_mkdir(args).await,
            "rmdir" => self.cmd_rmdir(args).await,
            "rm" => self.cmd_rm(args).await,
            "mv" => self.cmd_mv_or_cp(args, false).await,
            "cp" => self.cmd_mv_or_cp(args, true).await,
            "chmod" => self.cmd_chmod(args).await,
            "ln" => self.cmd_ln(args).await,
            "checksum" => self.cmd_checksum(args).await,
            "call" => self.cmd_call(&effective_line, args).await,
            "copyid" => self.cmd_copyid(args).await,
            "get" => self.cmd_get(args).await,
            "put" => self.cmd_put(args).await,
            "synchronize" => self.cmd_synchronize(args).await,
            "keepuptodate" => self.cmd_keepuptodate(args).await,
            "edit" => self.cmd_edit(args).await,
            "etag" => self.cmd_etag(args).await,
            "lock" => self.cmd_lock(args).await,
            "unlock" => self.cmd_unlock(args).await,
            "property" => self.cmd_property(args).await,
            "versions" => self.cmd_versions(args).await,
            "terminal" => self.cmd_terminal(args).await,
            "show" => Err(self
                .tr("Not available in this build: the connection runs the SFTP subsystem, so remote shell commands cannot be shown.")
                .to_string()),
            _ => Err(format!("Unsupported command '{canonical}'.")),
        };

        let ok = match res {
            Ok(()) => true,
            Err(err) => {
                self.emit_error(&err);
                false
            }
        };
        self.logger.end_command_group();
        ok
    }

    fn cmd_help(&mut self, args: &[String]) -> Result<(), String> {
        if !args.is_empty() {
            let mut had_err = false;
            for name in args {
                let lower = name.to_ascii_lowercase();
                let target = SCRIPT_COMMAND_HELPS
                    .iter()
                    .find(|(k, _)| *k == lower)
                    .or_else(|| {
                        let c = canonical_alias(&lower);
                        SCRIPT_COMMAND_HELPS.iter().find(|(k, _)| *k == c)
                    });
                if let Some((_, help_key)) = target {
                    println!("{}", self.tr(help_key));
                } else {
                    let msg = self.trp(
                        "Unknown command '{command}'. Type 'help' for a list of commands.",
                        &[("command", name)],
                    );
                    self.emit_error(&msg);
                    had_err = true;
                }
            }
            if had_err {
                // Already recorded via emit_error; return Ok so we don't double-count
                return Ok(());
            }
            return Ok(());
        }

        let mut output = String::new();
        for (name, help_key) in SCRIPT_COMMAND_HELPS {
            let translated = self.tr(help_key);
            if let Some(nl) = translated.find('\n') {
                let summary = translated[nl + 1..].trim_start_matches([' ', '\t']);
                if !summary.is_empty() {
                    output.push_str(&format!("{name:<8} {summary}\n"));
                }
            }
        }
        println!("{output}");
        Ok(())
    }

    fn print_option_value(&self, name: &str) {
        let val = match name {
            "echo" => (if self.cfg.echo { "on" } else { "off" }).to_string(),
            "batch" => self.cfg.batch_mode.as_str().to_string(),
            "confirm" => (if self.cfg.confirm { "on" } else { "off" }).to_string(),
            "resume" => match self.resume_support {
                ResumeSupportMode::On => "on".to_string(),
                ResumeSupportMode::Off => "off".to_string(),
                ResumeSupportMode::Smart(_) => "automatic".to_string(),
            },
            "transfer" => transfer_mode_name(self.transfer_mode).to_string(),
            "preset" => self
                .active_preset_name
                .clone()
                .unwrap_or_else(|| "off".to_string()),
            "include" => {
                if self.option_mask.include.is_empty() {
                    "(none)".to_string()
                } else {
                    self.option_mask
                        .include
                        .iter()
                        .map(|r| r.text.as_str())
                        .collect::<Vec<_>>()
                        .join(";")
                }
            }
            "exclude" => {
                if self.option_mask.exclude.is_empty() {
                    "(none)".to_string()
                } else {
                    self.option_mask
                        .exclude
                        .iter()
                        .map(|r| r.text.as_str())
                        .collect::<Vec<_>>()
                        .join(";")
                }
            }
            "failonnomatch" => (if self.fail_on_nomatch { "on" } else { "off" }).to_string(),
            "synchdelete" => (if self.synch_delete { "on" } else { "off" }).to_string(),
            "reconnecttime" => {
                if self.reconnect_time_secs > 0 {
                    self.reconnect_time_secs.to_string()
                } else {
                    "off".to_string()
                }
            }
            "editor" => {
                if self.editor_cmd.is_empty() {
                    "(from LINSCP_EDITOR, VISUAL or EDITOR)".to_string()
                } else {
                    self.editor_cmd.clone()
                }
            }
            "editmaxsize" => self.edit_max_size.to_string(),
            _ => String::new(),
        };
        println!(
            "{}",
            self.trp("{name} = {value}", &[("name", name), ("value", &val)])
        );
    }

    fn cmd_option(&mut self, args: &[String]) -> Result<(), String> {
        const OPTIONS: &[&str] = &[
            "echo",
            "batch",
            "confirm",
            "resume",
            "transfer",
            "include",
            "exclude",
            "failonnomatch",
            "synchdelete",
            "reconnecttime",
            "editor",
            "editmaxsize",
            "preset",
        ];
        if args.is_empty() {
            for &opt in OPTIONS {
                self.print_option_value(opt);
            }
            return Ok(());
        }

        if args[0].starts_with('-') {
            let supported = self.tr("supported: echo, batch, confirm, resume, transfer, include, exclude, failonnomatch, synchdelete, reconnecttime, editor, editmaxsize, preset");
            let hint = self.trp(
                "Syntax: option [<name> [<value>]] ({options})",
                &[("options", supported)],
            );
            return Err(self.wrong_args("option", &hint));
        }

        let opt_name = match resolve_prefixed_name(OPTIONS, &args[0]) {
            PrefixMatch::ExactOrUnique(n) => n,
            PrefixMatch::Ambiguous(m) => {
                return Err(format!("Ambiguous option '{}' (matches: {m}).", args[0]));
            }
            PrefixMatch::None => {
                let hint = self.trp(
                    "The option '{name}' is not supported by this build.",
                    &[("name", &args[0])],
                );
                return Err(self.wrong_args("option", &hint));
            }
        };

        if args.len() == 1 {
            self.print_option_value(opt_name);
            return Ok(());
        }
        if args.len() > 2 && opt_name != "editor" {
            let supported = self.tr("supported: echo, batch, confirm, resume, transfer, include, exclude, failonnomatch, synchdelete, reconnecttime, editor, editmaxsize, preset");
            let hint = self.trp(
                "Syntax: option [<name> [<value>]] ({options})",
                &[("options", supported)],
            );
            return Err(self.wrong_args("option", &hint));
        }
        let val = &args[1];

        match opt_name {
            "echo" => {
                self.cfg.echo = parse_option_on_off(val, "echo")
                    .map_err(|h| self.wrong_args("option", &h))?;
            }
            "confirm" => {
                self.cfg.confirm = parse_option_on_off(val, "confirm")
                    .map_err(|h| self.wrong_args("option", &h))?;
            }
            "batch" => {
                const BATCH_VALS: &[&str] = &["on", "off", "abort", "continue"];
                match resolve_prefixed_name(BATCH_VALS, val) {
                    PrefixMatch::ExactOrUnique("on") => self.cfg.batch_mode = BatchMode::On,
                    PrefixMatch::ExactOrUnique("off") => self.cfg.batch_mode = BatchMode::Off,
                    PrefixMatch::ExactOrUnique("abort") => self.cfg.batch_mode = BatchMode::Abort,
                    PrefixMatch::ExactOrUnique("continue") => {
                        self.cfg.batch_mode = BatchMode::Continue;
                    }
                    _ => {
                        let hint =
                            self.tr("The value of 'batch' must be 'on', 'off', 'abort' or 'continue'.");
                        return Err(self.wrong_args("option", hint));
                    }
                }
            }
            "transfer" => {
                const TMODES: &[&str] = &["binary", "ascii", "automatic"];
                match resolve_prefixed_name(TMODES, val) {
                    PrefixMatch::ExactOrUnique(m) => {
                        self.transfer_mode = parse_transfer_mode(m).unwrap_or(TransferMode::Binary);
                    }
                    _ => {
                        let hint = self.tr("The value of 'transfer' must be binary, ascii or automatic.");
                        return Err(self.wrong_args("option", hint));
                    }
                }
            }
            "resume" => {
                const RMODES: &[&str] = &["on", "off", "automatic"];
                match resolve_prefixed_name(RMODES, val) {
                    PrefixMatch::ExactOrUnique("on") => self.resume_support = ResumeSupportMode::On,
                    PrefixMatch::ExactOrUnique("off") => {
                        self.resume_support = ResumeSupportMode::Off;
                    }
                    PrefixMatch::ExactOrUnique("automatic") => {
                        self.resume_support = ResumeSupportMode::Smart(100 * 1024);
                    }
                    _ => {
                        if let Ok(kb) = val.parse::<u64>() {
                            self.resume_support =
                                ResumeSupportMode::Smart(kb.saturating_mul(1024));
                        } else {
                            let hint =
                                self.tr("The value of 'resume' must be on, off or automatic.");
                            return Err(self.wrong_args("option", hint));
                        }
                    }
                }
            }
            "include" | "exclude" => {
                if val.eq_ignore_ascii_case("clear") {
                    self.option_mask = FileMask::default();
                    self.option_mask_used = false;
                } else {
                    let parsed =
                        FileMask::parse(val).map_err(|e| self.wrong_args("option", &e))?;
                    if (!parsed.include.is_empty() && !parsed.exclude.is_empty())
                        || val.contains('|')
                    {
                        return Err(self.wrong_args(
                            "option",
                            &format!(
                                "Do not use '|' in 'option {opt_name}'; set 'include' or 'exclude' separately."
                            ),
                        ));
                    }
                    let mut combined = FileMask::default();
                    if opt_name == "include" {
                        combined.include = parsed.include;
                    } else {
                        combined.exclude = if !parsed.exclude.is_empty() {
                            parsed.exclude
                        } else {
                            parsed.include
                        };
                    }
                    self.option_mask = combined;
                    self.option_mask_used = true;
                }
            }
            "failonnomatch" => {
                self.fail_on_nomatch = parse_option_on_off(val, "failonnomatch")
                    .map_err(|h| self.wrong_args("option", &h))?;
            }
            "synchdelete" => {
                self.synch_delete = parse_option_on_off(val, "synchdelete")
                    .map_err(|h| self.wrong_args("option", &h))?;
            }
            "reconnecttime" => {
                if val.eq_ignore_ascii_case("off") {
                    self.reconnect_time_secs = 0;
                } else {
                    let secs: u64 = val
                        .parse()
                        .ok()
                        .filter(|&s| (1..=3600).contains(&s))
                        .ok_or_else(|| {
                            let h = self.tr("The value of 'reconnecttime' must be a number of seconds from 1 to 3600, or 'off'.");
                            self.wrong_args("option", h)
                        })?;
                    self.reconnect_time_secs = secs;
                }
            }
            "editor" => {
                self.editor_cmd = args[1..].join(" ");
            }
            "editmaxsize" => {
                if val.is_empty() || !val.bytes().all(|b| b.is_ascii_digit()) {
                    let h = self.tr("The value of 'editmaxsize' must be a number of bytes.");
                    return Err(self.wrong_args("option", h));
                }
                let bytes: u64 = val.parse().map_err(|_| {
                    let h = self.tr("The value of 'editmaxsize' must be a number of bytes.");
                    self.wrong_args("option", h)
                })?;
                if bytes == 0 {
                    let h =
                        self.tr("The value of 'editmaxsize' must be a positive number of bytes.");
                    return Err(self.wrong_args("option", h));
                }
                if bytes > (1u64 << 40) {
                    return Err(self.wrong_args(
                        "option",
                        "The value of 'editmaxsize' exceeds the maximum supported size (1 TiB).",
                    ));
                }
                self.edit_max_size = bytes;
            }
            "preset" => {
                if val.eq_ignore_ascii_case("off") {
                    self.presets_disabled = true;
                    self.active_preset_name = None;
                } else if val.eq_ignore_ascii_case("auto") {
                    self.presets_disabled = false;
                    self.active_preset_name = None;
                } else {
                    let store = TransferPresetStore::load_from_dir(&self.cfg.config_dir)?;
                    let Some(found) = store.find(val) else {
                        let p = TransferPresetStore::presets_path(&self.cfg.config_dir);
                        let p_str = p.display().to_string();
                        let h = self.trp(
                            "There is no transfer preset named '{name}' in '{path}'; create it with 'savepreset'.",
                            &[("name", val), ("path", &p_str)],
                        );
                        return Err(self.wrong_args("option", &h));
                    };
                    self.presets_disabled = false;
                    self.active_preset_name = Some(found.name.clone());
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn cmd_lcd(&mut self, args: &[String]) -> Result<(), String> {
        if args.len() != 1 {
            let h = self.tr("Syntax: lcd <directory>");
            return Err(self.wrong_args("lcd", h));
        }
        let expanded = expand_tilde(&args[0]);
        let candidate = if Path::new(&expanded).is_absolute() {
            PathBuf::from(expanded)
        } else {
            self.local_cwd.join(expanded)
        };
        let canon = std::fs::canonicalize(&candidate)
            .map_err(|e| format!("Cannot change local directory to '{}': {e}", args[0]))?;
        if !canon.is_dir() {
            return Err(format!("'{}' is not a directory.", args[0]));
        }
        self.local_cwd = canon;
        println!("{}", self.local_cwd.display());
        Ok(())
    }

    fn cmd_lls(&self, args: &[String]) -> Result<(), String> {
        let mut target_dir = self.local_cwd.clone();
        let mut mask_opt: Option<String> = None;
        for a in args {
            if a.starts_with('-') {
                continue;
            }
            let expanded = expand_tilde(a);
            let p = if Path::new(&expanded).is_absolute() {
                PathBuf::from(&expanded)
            } else {
                self.local_cwd.join(&expanded)
            };
            if p.is_dir() {
                target_dir = p;
            } else if has_wildcard(&expanded) {
                target_dir = p
                    .parent()
                    .filter(|d| !d.as_os_str().is_empty())
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| self.local_cwd.clone());
                mask_opt = p.file_name().map(|s| s.to_string_lossy().into_owned());
            } else if p.exists() {
                let info = stat_local_path(&p);
                let name = p
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or(expanded);
                println!(
                    "{} {:>10} {} {} {}",
                    format_permissions_10(info.mode, info.is_dir, info.is_symlink),
                    info.size,
                    format_file_date(info.mtime),
                    format_file_clock(info.mtime),
                    name
                );
                return Ok(());
            } else {
                return Err(format!("Local path '{a}' does not exist."));
            }
        }
        let rd = std::fs::read_dir(&target_dir)
            .map_err(|e| format!("Cannot read local directory '{}': {e}", target_dir.display()))?;
        let mut rows = Vec::new();
        for item in rd.flatten() {
            let name = item.file_name().to_string_lossy().into_owned();
            if let Some(ref m) = mask_opt {
                if !matches_wildcard(m, &name) {
                    continue;
                }
            }
            let info = stat_local_path(&item.path());
            rows.push((name, info));
        }
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, info) in rows {
            println!(
                "{} {:>10} {} {} {}",
                format_permissions_10(info.mode, info.is_dir, info.is_symlink),
                info.size,
                format_file_date(info.mtime),
                format_file_clock(info.mtime),
                name
            );
        }
        Ok(())
    }

    fn cmd_presets(&self, args: &[String]) -> Result<(), String> {
        if !args.is_empty() {
            return Err("Syntax: presets".to_string());
        }
        let store = TransferPresetStore::load_from_dir(&self.cfg.config_dir)?;
        if store.presets().is_empty() {
            let p = TransferPresetStore::presets_path(&self.cfg.config_dir);
            let p_str = p.display().to_string();
            println!(
                "{}",
                self.trp(
                    "There are no transfer presets in '{path}' (create one with 'savepreset').",
                    &[("path", &p_str)],
                )
            );
            return Ok(());
        }
        for p in store.presets() {
            let active = !self.presets_disabled
                && self
                    .active_preset_name
                    .as_deref()
                    .is_some_and(|a| a.eq_ignore_ascii_case(&p.name));
            let mark = if active { "* " } else { "  " };
            println!("{mark}{}: {}", p.name, p.describe());
        }
        Ok(())
    }

    fn cmd_savepreset(&mut self, args: &[String]) -> Result<(), String> {
        if args.len() < 2 {
            return Err("Syntax: savepreset <name> <setting>[=<value>]...".to_string());
        }
        let mut store = TransferPresetStore::load_from_dir(&self.cfg.config_dir)?;
        let mut preset = store.find(&args[0]).cloned().unwrap_or(TransferPreset {
            name: args[0].clone(),
            ..TransferPreset::default()
        });
        preset.name = args[0].clone();
        for item in &args[1..] {
            if let Some((k, v)) = item.split_once('=') {
                preset.parse_setting(k, v)?;
            } else {
                preset.parse_setting(item, "")?;
            }
        }
        store.add_or_update(preset)?;
        store.save_to_dir(&self.cfg.config_dir)?;
        println!(
            "{}",
            self.trp("Preset '{name}' saved.", &[("name", &args[0])])
        );
        Ok(())
    }

    fn cmd_rmspreset(&mut self, args: &[String]) -> Result<(), String> {
        if args.len() != 1 {
            return Err("Syntax: rmspreset <name>".to_string());
        }
        let mut store = TransferPresetStore::load_from_dir(&self.cfg.config_dir)?;
        store.remove(&args[0]).map_err(|_| {
            let p = TransferPresetStore::presets_path(&self.cfg.config_dir);
            let p_str = p.display().to_string();
            self.trp(
                "There is no transfer preset named '{name}' in '{path}'.",
                &[("name", &args[0]), ("path", &p_str)],
            )
        })?;
        store.save_to_dir(&self.cfg.config_dir)?;
        if self
            .active_preset_name
            .as_deref()
            .is_some_and(|a| a.eq_ignore_ascii_case(&args[0]))
        {
            self.active_preset_name = None;
        }
        println!("Removed transfer preset '{}'.", args[0]);
        Ok(())
    }

    async fn cmd_sessions(&mut self, args: &[String]) -> Result<(), String> {
        let vault = DefaultOsVault;
        let mut store = SessionStore::load_from_dir(&self.cfg.config_dir, &vault)?;
        if args.is_empty() || (args.len() == 1 && args[0].eq_ignore_ascii_case("list")) {
            if store.sites().is_empty() {
                println!(
                    "{}",
                    self.tr("There are no stored sessions. Use 'savesession <name>' to store the current connection.")
                );
                return Ok(());
            }
            for s in store.sites() {
                let port = if s.port == 0 {
                    s.protocol.default_port()
                } else {
                    s.port
                };
                let user_prefix = if s.username.is_empty() {
                    String::new()
                } else {
                    format!("{}@", s.username)
                };
                println!(
                    "{}  {}://{}{}:{}",
                    s.name,
                    s.protocol.as_str(),
                    user_prefix,
                    s.host,
                    port
                );
            }
            return Ok(());
        }

        if args.len() == 2 && args[0].eq_ignore_ascii_case("export") {
            let dest = PathBuf::from(expand_tilde(&args[1]));
            let mut portable = SessionStore::new();
            for s in store.sites() {
                let mut copy = s.clone();
                copy.password = None;
                copy.password_raw = None;
                copy.proxy_password = None;
                copy.proxy_password_raw = None;
                copy.tunnel.password = None;
                copy.tunnel_password_raw = None;
                copy.tunnel_passphrase = None;
                copy.tunnel_passphrase_raw = None;
                portable.upsert(copy);
            }
            let text = portable.serialize_ini(None)?;
            linscp_platform::write_private_file_atomic(&dest, text.as_bytes())
                .map_err(|e| e.to_string())?;
            println!(
                "Exported {} session(s) to '{}'.",
                store.sites().len(),
                dest.display()
            );
            return Ok(());
        }

        if args.len() == 2 && args[0].eq_ignore_ascii_case("import") {
            let src = PathBuf::from(expand_tilde(&args[1]));
            let text = std::fs::read_to_string(&src)
                .map_err(|e| format!("Cannot read '{}': {e}", src.display()))?;
            let imported = SessionStore::parse_ini(&text, None)?;
            let count = imported.sites().len();
            for s in imported.sites() {
                store.upsert(s.clone());
            }
            store.save_to_dir(&self.cfg.config_dir, &vault)?;
            println!("Imported {count} session(s) from '{}'.", src.display());
            return Ok(());
        }

        if args.len() == 1 {
            let Some(site) = store.find(&args[0]).cloned() else {
                return Err(self.trp(
                    "There is no stored session named '{name}'.",
                    &[("name", &args[0])],
                ));
            };
            let mut spec = site_spec_from_stored(&site)?;
            apply_env_credential_fallbacks(&mut spec);
            return self.open_slot_from_spec(spec).await;
        }

        Err("Syntax: sessions [ NAME | list | export <file> | import <file> ]".to_string())
    }

    fn cmd_savesession(&mut self, args: &[String]) -> Result<(), String> {
        if args.is_empty() {
            return Err("Syntax: savesession <name> [ <site-url> ] [ options ]".to_string());
        }
        let name = args[0].trim();
        if name.is_empty() || name.starts_with('/') || name.ends_with('/') || name.contains("//") {
            return Err(format!("Invalid session name '{name}'."));
        }

        let vault = DefaultOsVault;
        let mut store = SessionStore::load_from_dir(&self.cfg.config_dir, &vault)?;

        let mut rest_idx = 1usize;
        let mut spec = if args.get(1).is_some_and(|a| !a.starts_with('-')) {
            rest_idx = 2;
            parse_site_url(&args[1])?
        } else if let Some(existing) = store.find(name) {
            if let Ok(slot) = self.active_slot() {
                slot.spec.clone()
            } else {
                ParsedSiteSpec {
                    session: existing.to_session_config(),
                    raw_fields: existing.extra_fields.clone(),
                    preset_name: existing.preset.clone(),
                    ..ParsedSiteSpec::default()
                }
            }
        } else {
            self.active_slot()?.spec.clone()
        };

        apply_open_switches(&mut spec, &args[rest_idx..], true, &self.cfg.locale)?;
        let site = stored_site_from_spec(name, &spec);
        store.upsert(site);
        store.save_to_dir(&self.cfg.config_dir, &vault)?;
        println!("Saved session '{name}'.");
        Ok(())
    }

    fn cmd_rmsession(&mut self, args: &[String]) -> Result<(), String> {
        if args.len() != 1 {
            return Err("Syntax: rmsession <name>".to_string());
        }
        let vault = DefaultOsVault;
        let mut store = SessionStore::load_from_dir(&self.cfg.config_dir, &vault)?;
        let target = args[0].trim_end_matches('/');
        if store.remove(target) {
            store.save_to_dir(&self.cfg.config_dir, &vault)?;
            println!("Removed stored session '{target}'.");
            return Ok(());
        }
        let removed_in_folder = store.remove_folder(target);
        if removed_in_folder > 0 {
            store.save_to_dir(&self.cfg.config_dir, &vault)?;
            println!("Removed {removed_in_folder} session(s) in folder '{target}'.");
            return Ok(());
        }
        Err(self.trp(
            "There is no stored session named '{name}'.",
            &[("name", &args[0])],
        ))
    }

    fn cmd_session(&mut self, args: &[String]) -> Result<(), String> {
        if args.is_empty() {
            if self.slots.is_empty() {
                println!(
                    "{}",
                    self.tr("Not connected. Use 'open' to connect to a site first.")
                );
                return Ok(());
            }
            for (idx, slot) in self.slots.iter().enumerate() {
                let mark = if idx == self.active_slot { "*" } else { " " };
                println!(
                    "{mark} {}  {} ({})",
                    idx + 1,
                    slot.spec.session_label,
                    slot.spec.session.protocol.as_str()
                );
            }
            return Ok(());
        }
        if args.len() != 1 {
            return Err("Syntax: session [ <index> ]".to_string());
        }
        let idx_1: usize = args[0]
            .parse()
            .ok()
            .filter(|&n| n >= 1 && n <= self.slots.len())
            .ok_or_else(|| format!("There is no open session at index '{}'.", args[0]))?;
        self.active_slot = idx_1 - 1;
        println!(
            "Active session: {} ({})",
            self.slots[self.active_slot].spec.session_label, idx_1
        );
        Ok(())
    }

    async fn cmd_open(&mut self, args: &[String]) -> Result<(), String> {
        let mut positional = Vec::new();
        let mut switch_tokens = Vec::new();
        let mut in_raw = false;
        for tok in args {
            if in_raw {
                switch_tokens.push(tok.clone());
                continue;
            }
            if tok.eq_ignore_ascii_case("-rawsettings") || tok.eq_ignore_ascii_case("/rawsettings")
            {
                in_raw = true;
                switch_tokens.push(tok.clone());
            } else if tok.starts_with('-') || is_slash_switch(tok) {
                switch_tokens.push(tok.clone());
            } else {
                positional.push(tok.clone());
            }
        }
        if positional.len() != 1 {
            return Err(self.wrong_args(
                "open",
                "Syntax: open <site-url-or-stored-name> [ options ]",
            ));
        }
        let target = &positional[0];
        let mut spec = if target.contains("://") {
            parse_site_url(target)?
        } else {
            // Validate switches first even if stored session lookup fails, so `open sftp://host -nonsense` or unknown switches report cleanly
            let mut probe = ParsedSiteSpec::default();
            apply_open_switches(&mut probe, &switch_tokens, false, &self.cfg.locale)?;
            let vault = DefaultOsVault;
            let store = SessionStore::load_from_dir(&self.cfg.config_dir, &vault)?;
            let Some(site) = store.find(target) else {
                return Err(format!(
                    "'{target}' is neither a session URL (scheme://host) nor a stored session."
                ));
            };
            site_spec_from_stored(site)?
        };
        apply_open_switches(&mut spec, &switch_tokens, false, &self.cfg.locale)?;
        apply_env_credential_fallbacks(&mut spec);
        self.open_slot_from_spec(spec).await?;
        let label = self.slots[self.active_slot].spec.session_label.clone();
        self.emit_status(&self.trp("Session '{host}' opened.", &[("host", &label)]));
        Ok(())
    }

    async fn cmd_close(&mut self, args: &[String]) -> Result<(), String> {
        if self.slots.is_empty() {
            return Err(self
                .tr("Not connected. Use 'open' to connect to a site first.")
                .to_string());
        }
        let idx = if args.is_empty() {
            self.active_slot
        } else if args.len() == 1 {
            let n: usize = args[0]
                .parse()
                .ok()
                .filter(|&n| n >= 1 && n <= self.slots.len())
                .ok_or_else(|| format!("There is no open session at index '{}'.", args[0]))?;
            n - 1
        } else {
            return Err("Syntax: close [ <index> ]".to_string());
        };
        let removed = self.slots.remove(idx);
        let _ = removed.session.close().await;
        if self.active_slot >= self.slots.len() && !self.slots.is_empty() {
            self.active_slot = self.slots.len() - 1;
        }
        self.emit_status(&self.trp(
            "Session '{name}' closed.",
            &[("name", &removed.spec.session_label)],
        ));
        Ok(())
    }

    fn cmd_pwd(&mut self, args: &[String]) -> Result<(), String> {
        if !args.is_empty() {
            return Err("Syntax: pwd".to_string());
        }
        let cwd = self.active_slot()?.remote_cwd.clone();
        println!("{cwd}");
        self.logger.record_cwd(&cwd, Ok(()));
        Ok(())
    }

    async fn cmd_cd(&mut self, args: &[String]) -> Result<(), String> {
        if args.len() > 1 {
            return Err("Syntax: cd [ <directory> ]".to_string());
        }
        let slot = self.active_slot()?;
        let next = if args.is_empty() {
            slot.session.pwd().await.map_err(|e| e.to_string())?
        } else {
            let candidate = resolve_remote_path(&slot.remote_cwd, &args[0]);
            if candidate != "/" {
                if let Some(info) = slot
                    .session
                    .stat(&candidate)
                    .await
                    .map_err(|e| e.to_string())?
                {
                    if !info.is_dir && !info.is_symlink {
                        let msg = format!("'{candidate}' is not a directory.");
                        self.logger.record_cwd(&candidate, Err(&msg));
                        return Err(msg);
                    }
                } else if slot.session.scheme() != ProtocolScheme::S3 {
                    let msg = format!("Remote directory '{candidate}' does not exist.");
                    self.logger.record_cwd(&candidate, Err(&msg));
                    return Err(msg);
                }
            }
            slot.session.realpath(&candidate).await.unwrap_or(candidate)
        };
        self.slots[self.active_slot].remote_cwd = next.clone();
        println!("{next}");
        self.logger.record_cwd(&next, Ok(()));
        Ok(())
    }

    async fn cmd_ls(&mut self, args: &[String]) -> Result<(), String> {
        let mut show_all = false;
        let mut names_only = false;
        let mut target_arg: Option<String> = None;
        for a in args {
            match a.as_str() {
                "-a" => show_all = true,
                "-1" => names_only = true,
                "-l" | "-la" | "-al" => {
                    if a.contains('a') {
                        show_all = true;
                    }
                }
                s if s.starts_with('-') => {
                    let h = self.trp("Unknown switch '{switch}'.", &[("switch", s)]);
                    return Err(self.wrong_args("ls", &h));
                }
                other => {
                    if target_arg.is_some() {
                        return Err(
                            "Syntax: ls [-l] [-a] [-1] [ <directory>[/<mask>] ]".to_string(),
                        );
                    }
                    target_arg = Some(other.to_string());
                }
            }
        }

        let cwd = self.active_slot()?.remote_cwd.clone();
        let (dir_path, mask_opt) = if let Some(ref raw) = target_arg {
            let resolved = resolve_remote_path(&cwd, raw);
            if has_wildcard(raw) {
                let (p, m) = remote_parent_and_name(&resolved);
                (p, Some(m))
            } else {
                (resolved, None)
            }
        } else {
            (cwd, None)
        };

        let raw_entries = match self.slots[self.active_slot]
            .session
            .list_dir(&dir_path)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                let msg = e.to_string();
                self.logger.record_ls(&dir_path, None, Err(&msg));
                return Err(msg);
            }
        };

        let mut filtered: Vec<FileEntry> = raw_entries
            .into_iter()
            .filter(|e| {
                if !show_all && e.name.starts_with('.') {
                    return false;
                }
                if let Some(ref m) = mask_opt {
                    if !matches_wildcard(m, &e.name) {
                        return false;
                    }
                }
                true
            })
            .collect();
        filtered.sort_by(|a, b| a.name.cmp(&b.name));

        for entry in &filtered {
            if names_only {
                println!("{}", entry.name);
            } else {
                let link_target = if entry.is_symlink {
                    let full = join_remote_path(&dir_path, &entry.name);
                    self.slots[self.active_slot].session.readlink(&full).await.ok()
                } else {
                    None
                };
                println!("{}", format_listing_line(entry, link_target.as_deref()));
            }
        }
        self.logger.record_ls(&dir_path, Some(&filtered), Ok(()));
        Ok(())
    }

    async fn cmd_stat(&mut self, args: &[String]) -> Result<(), String> {
        if args.len() != 1 {
            return Err("Syntax: stat <file>".to_string());
        }
        let cwd = self.active_slot()?.remote_cwd.clone();
        let path = resolve_remote_path(&cwd, &args[0]);
        match self.slots[self.active_slot].session.stat(&path).await {
            Ok(Some(entry)) => {
                let link_target = if entry.is_symlink {
                    self.slots[self.active_slot].session.readlink(&path).await.ok()
                } else {
                    None
                };
                println!("{}", format_listing_line(&entry, link_target.as_deref()));
                self.logger.record_stat(&path, Some(&entry), Ok(()));
                Ok(())
            }
            Ok(None) => {
                let msg = format!("Remote path '{path}' does not exist.");
                self.logger.record_stat(&path, None, Err(&msg));
                Err(msg)
            }
            Err(e) => {
                let msg = e.to_string();
                self.logger.record_stat(&path, None, Err(&msg));
                Err(msg)
            }
        }
    }

    async fn cmd_attr(&mut self, args: &[String]) -> Result<(), String> {
        if args.len() != 1 {
            return Err("Syntax: attr <file>".to_string());
        }
        let cwd = self.active_slot()?.remote_cwd.clone();
        let path = resolve_remote_path(&cwd, &args[0]);
        let Some(entry) = self.slots[self.active_slot]
            .session
            .stat(&path)
            .await
            .map_err(|e| e.to_string())?
        else {
            return Err(format!(
                "Cannot read the attributes of '{path}': {}",
                self.tr("There is no such file or directory.")
            ));
        };
        let perms = if entry.permissions.is_empty() {
            format_permissions_10(
                if entry.is_dir { 0o755 } else { 0o644 },
                entry.is_dir,
                entry.is_symlink,
            )
        } else {
            entry.permissions.clone()
        };
        let sz_str = entry.size.to_string();
        let mod_str = format_ls_time(entry.mtime);
        println!("{}", self.trp("Path:        {path}", &[("path", &path)]));
        println!("{}", self.trp("Size:        {size}", &[("size", &sz_str)]));
        println!(
            "{}",
            self.trp("Permissions: {permissions}", &[("permissions", &perms)])
        );
        println!("{}", self.trp("Modified:    {time}", &[("time", &mod_str)]));
        println!("{}", self.trp("SizeBytes:   {size}", &[("size", &sz_str)]));
        if entry.mtime > 0 {
            let epoch = entry.mtime.to_string();
            println!(
                "{}",
                self.trp("ModifiedEpoch: {time}", &[("time", &epoch)])
            );
            println!(
                "{}",
                self.trp("AccessedEpoch: {time}", &[("time", &epoch)])
            );
        }
        let owner = match (&entry.owner, &entry.group) {
            (Some(o), Some(g)) if !o.is_empty() && !g.is_empty() => format!("{o}:{g}"),
            (Some(o), _) if !o.is_empty() => o.clone(),
            _ => "unknown".to_string(),
        };
        println!("{}", self.trp("Owner:       {owner}", &[("owner", &owner)]));
        Ok(())
    }

    async fn cmd_mkdir(&mut self, args: &[String]) -> Result<(), String> {
        let mut parents = false;
        let mut dirs = Vec::new();
        for a in args {
            if a.eq_ignore_ascii_case("-parents") || a.eq_ignore_ascii_case("-p") {
                parents = true;
            } else if a.starts_with('-') {
                let h = self.trp("Unsupported switch '{switch}'; it will not be ignored.", &[("switch", a)]);
                return Err(self.wrong_args("mkdir", &h));
            } else {
                dirs.push(a.clone());
            }
        }
        if dirs.is_empty() {
            return Err("Syntax: mkdir [-parents] <directory>...".to_string());
        }
        let cwd = self.active_slot()?.remote_cwd.clone();
        for raw in dirs {
            let path = resolve_remote_path(&cwd, &raw);
            if parents {
                let mut cur = String::new();
                for seg in path.split('/').filter(|s| !s.is_empty()) {
                    cur.push('/');
                    cur.push_str(seg);
                    if self.slots[self.active_slot]
                        .session
                        .stat(&cur)
                        .await
                        .map_err(|e| e.to_string())?
                        .is_none()
                    {
                        if let Err(e) = self.slots[self.active_slot].session.mkdir(&cur).await {
                            let msg = e.to_string();
                            self.logger.record_mkdir(&cur, Err(&msg));
                            return Err(msg);
                        }
                        self.logger.record_mkdir(&cur, Ok(()));
                    }
                }
            } else {
                if let Err(e) = self.slots[self.active_slot].session.mkdir(&path).await {
                    let msg = e.to_string();
                    self.logger.record_mkdir(&path, Err(&msg));
                    return Err(msg);
                }
                self.logger.record_mkdir(&path, Ok(()));
            }
        }
        Ok(())
    }

    async fn cmd_rmdir(&mut self, args: &[String]) -> Result<(), String> {
        if args.is_empty() || args.iter().any(|a| a.starts_with('-')) {
            return Err("Syntax: rmdir <directory> [ <directory>... ]".to_string());
        }
        let cwd = self.active_slot()?.remote_cwd.clone();
        for raw in args {
            let path = resolve_remote_path(&cwd, raw);
            if let Err(e) = self.slots[self.active_slot].session.remove_dir(&path).await {
                let msg = e.to_string();
                self.logger.record_rm(&path, false, Err(&msg));
                return Err(msg);
            }
            self.logger.record_rm(&path, false, Ok(()));
        }
        Ok(())
    }

    async fn cmd_rm(&mut self, args: &[String]) -> Result<(), String> {
        let mut only_file = false;
        let mut recursive = false;
        let mut version_id: Option<String> = None;
        let mut patterns = Vec::new();

        for a in args {
            let low = a.to_ascii_lowercase();
            if low == "-onlyfile" {
                only_file = true;
            } else if low == "-r" || low == "-recursive" {
                recursive = true;
            } else if low.starts_with("-versionid=") {
                if version_id.is_some() {
                    return Err(self.wrong_args("rm", self.tr("Give '-versionid' only once.")));
                }
                let vid = &a["-versionid=".len()..];
                if vid.is_empty() {
                    return Err(
                        self.wrong_args("rm", self.tr("The value of '-versionid' cannot be empty."))
                    );
                }
                version_id = Some(vid.to_string());
            } else if a.starts_with('-') {
                let h = self.trp(
                    "Unsupported switch '{switch}'; it will not be ignored.",
                    &[("switch", a)],
                );
                return Err(self.wrong_args("rm", &h));
            } else {
                patterns.push(a.clone());
            }
        }
        if patterns.is_empty() {
            return Err("Syntax: rm [-onlyfile] [-r] [-versionid=ID] <file>...".to_string());
        }

        let scheme = self.active_slot()?.session.scheme();
        if version_id.is_some() && scheme != ProtocolScheme::S3 {
            return Err(self.wrong_args(
                "rm",
                self.tr("'-versionid' is available only for S3 object versions."),
            ));
        }

        let cwd = self.active_slot()?.remote_cwd.clone();
        for pat in patterns {
            let resolved = resolve_remote_path(&cwd, &pat);
            if let Some(ref vid) = version_id {
                if let Err(e) = self.slots[self.active_slot]
                    .session
                    .s3_remove_version(&resolved, vid)
                    .await
                {
                    let msg = e.to_string();
                    self.logger.record_rm(&resolved, false, Err(&msg));
                    return Err(msg);
                }
                self.logger.record_rm(&resolved, false, Ok(()));
                continue;
            }

            let targets = self.expand_remote_pattern(&resolved).await?;
            if targets.is_empty() {
                if self.fail_on_nomatch {
                    let msg = format!("No file matching '{pat}' found.");
                    self.logger.record_rm(&resolved, recursive, Err(&msg));
                    return Err(msg);
                }
                continue;
            }
            for (path, entry) in targets {
                if entry.is_dir {
                    if only_file {
                        continue;
                    }
                    self.remove_remote_tree(&path).await?;
                    self.logger.record_rm(&path, true, Ok(()));
                } else {
                    if let Err(e) = self.slots[self.active_slot].session.remove_file(&path).await {
                        let msg = e.to_string();
                        self.logger.record_rm(&path, false, Err(&msg));
                        return Err(msg);
                    }
                    self.logger.record_rm(&path, false, Ok(()));
                }
            }
        }
        Ok(())
    }

    async fn remove_remote_tree(&mut self, dir_path: &str) -> Result<(), String> {
        let entries = self.slots[self.active_slot]
            .session
            .list_dir(dir_path)
            .await
            .map_err(|e| e.to_string())?;
        for e in entries {
            if e.name == "." || e.name == ".." {
                continue;
            }
            let child = join_remote_path(dir_path, &e.name);
            if e.is_dir && !e.is_symlink {
                Box::pin(self.remove_remote_tree(&child)).await?;
            } else {
                self.slots[self.active_slot]
                    .session
                    .remove_file(&child)
                    .await
                    .map_err(|err| err.to_string())?;
            }
        }
        self.slots[self.active_slot]
            .session
            .remove_dir(dir_path)
            .await
            .map_err(|e| e.to_string())
    }

    async fn cmd_mv_or_cp(&mut self, args: &[String], is_copy: bool) -> Result<(), String> {
        let name = if is_copy { "cp" } else { "mv" };
        if args.len() < 2 || args.iter().any(|a| a.starts_with('-')) {
            return Err(format!("Syntax: {name} <source>... <target>"));
        }
        let cwd = self.active_slot()?.remote_cwd.clone();
        let raw_target = &args[args.len() - 1];
        let target_ends_slash = raw_target.ends_with('/');
        let target_resolved = resolve_remote_path(&cwd, raw_target);
        let target_stat = self.slots[self.active_slot]
            .session
            .stat(&target_resolved)
            .await
            .ok()
            .flatten();
        let target_is_dir = target_ends_slash || target_stat.as_ref().is_some_and(|e| e.is_dir);

        let mut expanded_sources = Vec::new();
        for src in &args[..args.len() - 1] {
            let resolved_src = resolve_remote_path(&cwd, src);
            let matches = self.expand_remote_pattern(&resolved_src).await?;
            if matches.is_empty() {
                let msg = format!("Source '{src}' does not exist.");
                self.logger
                    .record_mv_or_cp(is_copy, &resolved_src, &target_resolved, Err(&msg));
                return Err(msg);
            }
            expanded_sources.extend(matches);
        }

        if expanded_sources.len() > 1 && !target_is_dir {
            return Err(format!(
                "Target '{raw_target}' must be an existing directory when moving/copying multiple sources."
            ));
        }

        for (src_path, src_entry) in expanded_sources {
            let dest_path = if target_is_dir {
                join_remote_path(&target_resolved, &src_entry.name)
            } else {
                target_resolved.clone()
            };
            let op_res = if is_copy {
                self.slots[self.active_slot]
                    .session
                    .copy_file(&src_path, &dest_path)
                    .await
            } else {
                self.slots[self.active_slot]
                    .session
                    .rename(&src_path, &dest_path)
                    .await
            };
            match op_res {
                Ok(()) => self
                    .logger
                    .record_mv_or_cp(is_copy, &src_path, &dest_path, Ok(())),
                Err(e) => {
                    let msg = e.to_string();
                    self.logger
                        .record_mv_or_cp(is_copy, &src_path, &dest_path, Err(&msg));
                    return Err(msg);
                }
            }
        }
        Ok(())
    }

    async fn cmd_chmod(&mut self, args: &[String]) -> Result<(), String> {
        let mut recursive = false;
        let mut positional = Vec::new();
        for a in args {
            let low = a.to_ascii_lowercase();
            if low == "-r" || low == "-recursive" {
                recursive = true;
            } else if a.starts_with('-') && positional.is_empty() {
                let h = self.trp(
                    "Unsupported switch '{switch}'; it will not be ignored.",
                    &[("switch", a)],
                );
                return Err(self.wrong_args("chmod", &h));
            } else {
                positional.push(a.clone());
            }
        }
        if positional.len() < 2 {
            return Err("Syntax: chmod <mode> <file>... [-recursive]".to_string());
        }
        let mode_expr = &positional[0];
        let cwd = self.active_slot()?.remote_cwd.clone();
        let mut changed = 0usize;

        for raw in &positional[1..] {
            let resolved = resolve_remote_path(&cwd, raw);
            let matches = self.expand_remote_pattern(&resolved).await?;
            if matches.is_empty() {
                return Err(format!("Cannot find '{raw}': No matching files."));
            }
            for (path, entry) in matches {
                self.apply_chmod_entry(&path, &entry, mode_expr, recursive, &mut changed)
                    .await?;
            }
        }
        if recursive {
            println!(
                "{changed} {}.",
                if changed == 1 {
                    "file changed"
                } else {
                    "files changed"
                }
            );
        }
        Ok(())
    }

    async fn apply_chmod_entry(
        &mut self,
        path: &str,
        entry: &FileEntry,
        mode_expr: &str,
        recursive: bool,
        changed: &mut usize,
    ) -> Result<(), String> {
        if entry.is_symlink {
            return Ok(());
        }
        let cur_mode = mode_from_permissions_str(&entry.permissions);
        let new_mode = parse_permissions_expr(mode_expr, cur_mode, entry.is_dir)?;
        if let Err(e) = self.slots[self.active_slot]
            .session
            .chmod(path, new_mode)
            .await
        {
            let msg = e.to_string();
            self.logger
                .record_chmod(path, new_mode, recursive, Err(&msg));
            return Err(msg);
        }
        self.logger.record_chmod(path, new_mode, recursive, Ok(()));
        *changed += 1;

        if recursive && entry.is_dir {
            let children = self.slots[self.active_slot]
                .session
                .list_dir(path)
                .await
                .map_err(|e| e.to_string())?;
            for c in children {
                if c.name == "." || c.name == ".." || c.is_symlink {
                    continue;
                }
                let child_path = join_remote_path(path, &c.name);
                Box::pin(self.apply_chmod_entry(&child_path, &c, mode_expr, true, changed)).await?;
            }
        }
        Ok(())
    }

    async fn cmd_ln(&mut self, args: &[String]) -> Result<(), String> {
        if args.len() != 2 {
            return Err("Syntax: ln <target> <link>".to_string());
        }
        let cwd = self.active_slot()?.remote_cwd.clone();
        let target = &args[0];
        let link = resolve_remote_path(&cwd, &args[1]);
        self.slots[self.active_slot]
            .session
            .symlink(target, &link)
            .await
            .map_err(|e| e.to_string())
    }

    async fn cmd_checksum(&mut self, args: &[String]) -> Result<(), String> {
        if args.len() != 2 {
            return Err("Syntax: checksum <algorithm> <file>".to_string());
        }
        let alg = &args[0];
        let cwd = self.active_slot()?.remote_cwd.clone();
        let path = resolve_remote_path(&cwd, &args[1]);
        match self.slots[self.active_slot]
            .session
            .checksum(alg, &path)
            .await
        {
            Ok(hex) => {
                println!("{hex}  {path}");
                self.logger
                    .record_checksum(&path, alg, Some(&hex), Ok(()));
                Ok(())
            }
            Err(e) => {
                let msg = e.to_string();
                self.logger.record_checksum(&path, alg, None, Err(&msg));
                Err(msg)
            }
        }
    }

    async fn cmd_call(&mut self, raw_line: &str, args: &[String]) -> Result<(), String> {
        if args.is_empty() {
            return Err("Syntax: call <command>".to_string());
        }
        let trimmed = raw_line.trim_start();
        let command_str = if let Some(rest) = trimmed.strip_prefix('!') {
            rest.trim().to_string()
        } else if let Some(idx) = trimmed.find(char::is_whitespace) {
            trimmed[idx..].trim().to_string()
        } else {
            args.join(" ")
        };

        let cwd = self.active_slot()?.remote_cwd.clone();
        let exec_cmd = if cwd != "/" && !cwd.is_empty() {
            format!("cd -- '{}' && {}", cwd.replace('\'', "'\\''"), command_str)
        } else {
            command_str.clone()
        };

        let out = match self.slots[self.active_slot]
            .session
            .exec_command(&exec_cmd)
            .await
        {
            Ok(o) => o,
            Err(e) => {
                let msg = e.to_string();
                self.logger
                    .record_call(&command_str, &cwd, "", &msg, -1, Err(&msg));
                return Err(msg);
            }
        };

        let stdout_txt = String::from_utf8_lossy(&out.stdout);
        let stderr_txt = String::from_utf8_lossy(&out.stderr);
        if !stdout_txt.is_empty() {
            print!("{stdout_txt}");
            if !stdout_txt.ends_with('\n') {
                println!();
            }
            let _ = std::io::stdout().flush();
        }
        if !stderr_txt.is_empty() {
            eprint!("{stderr_txt}");
            if !stderr_txt.ends_with('\n') {
                eprintln!();
            }
            let _ = std::io::stderr().flush();
        }
        let code = out.exit_code.map(|c| c as i32).unwrap_or(0);
        if code == 0 {
            self.logger
                .record_call(&command_str, &cwd, &stdout_txt, &stderr_txt, 0, Ok(()));
            Ok(())
        } else {
            let msg = format!("Command '{command_str}' failed with return code {code}.");
            self.logger.record_call(
                &command_str,
                &cwd,
                &stdout_txt,
                &stderr_txt,
                code,
                Err(&msg),
            );
            Err(msg)
        }
    }

    async fn cmd_copyid(&mut self, args: &[String]) -> Result<(), String> {
        if args.len() > 1 {
            return Err("Syntax: copyid [ <keyfile> ]".to_string());
        }
        let slot = self.active_slot()?;
        if !is_ssh_scheme(slot.session.scheme()) {
            return Err("'copyid' requires an SFTP or SCP session.".to_string());
        }
        let key_path = if let Some(explicit) = args.first() {
            expand_tilde(explicit)
        } else if let Some(ref kp) = slot.spec.session.keyfile {
            kp.clone()
        } else {
            return Err(
                "No private key file is configured; pass 'copyid <keyfile>'.".to_string(),
            );
        };
        let pub_candidate = format!("{key_path}.pub");
        let pub_line = if Path::new(&pub_candidate).is_file() {
            std::fs::read_to_string(&pub_candidate)
                .map_err(|e| format!("Cannot read '{pub_candidate}': {e}"))?
                .lines()
                .find(|l| !l.trim().is_empty())
                .ok_or_else(|| format!("'{pub_candidate}' is empty."))?
                .trim()
                .to_string()
        } else {
            let raw_priv = std::fs::read_to_string(&key_path)
                .map_err(|e| format!("Cannot read '{key_path}': {e}"))?;
            extract_openssh_public_key_line(&raw_priv, slot.spec.passphrase.as_deref())
                .map_err(|e| format!("Cannot decode private key '{key_path}': {e}"))?
        };
        let escaped = pub_line.replace('\'', "'\\''");
        let install_sh = format!(
            "umask 077 && mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && (grep -qxF '{escaped}' ~/.ssh/authorized_keys || printf '%s\\n' '{escaped}' >> ~/.ssh/authorized_keys)"
        );
        let out = self.slots[self.active_slot]
            .session
            .exec_command(&install_sh)
            .await
            .map_err(|e| e.to_string())?;
        if out.exit_code.unwrap_or(0) != 0 {
            return Err(format!(
                "Installing public key failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        println!(
            "{}",
            self.trp(
                "Public key installed in '{path}'.",
                &[("path", "~/.ssh/authorized_keys")],
            )
        );
        Ok(())
    }

    fn base_transfer_flags(&self, sample_filename: Option<&str>) -> Result<TransferFlags, String> {
        let mut flags = TransferFlags {
            transfer_mode: self.transfer_mode,
            resume_support: self.resume_support,
            ..TransferFlags::default()
        };

        if !self.presets_disabled {
            if let Ok(store) = TransferPresetStore::load_from_dir(&self.cfg.config_dir) {
                if let Some(ref explicit_name) = self.active_preset_name {
                    if let Some(p) = store.find(explicit_name) {
                        flags.apply_preset(p);
                    }
                } else if let Ok(slot) = self.active_slot() {
                    let hostport = format!("{}:{}", slot.spec.session.host, slot.spec.session.port);
                    if let Some(p) = store.match_session(
                        &hostport,
                        &slot.spec.session.username,
                        &slot.remote_cwd,
                        &self.local_cwd.display().to_string(),
                    ) {
                        flags.apply_preset(p);
                    }
                    if let Some(fname) = sample_filename {
                        if let Some(mp) = store.match_mask(fname) {
                            flags.apply_preset(mp);
                        }
                    }
                }
            }
        }

        if self.option_mask_used {
            flags.file_mask = self.option_mask.clone();
        }
        Ok(flags)
    }

    async fn cmd_get(&mut self, args: &[String]) -> Result<(), String> {
        // Parse & validate switches BEFORE RequireConnection so syntax/switch errors report even offline
        let (mut flags, paths) = self.parse_transfer_command_args("get", args, false)?;
        if paths.is_empty() {
            return Err(self.wrong_args(
                "get",
                "Syntax: get [ <switches> ] <file>... [ <local-target> ]",
            ));
        }
        let cwd = self.active_slot()?.remote_cwd.clone();
        if flags.version_id.is_some() && self.active_slot()?.session.scheme() != ProtocolScheme::S3
        {
            return Err(self.wrong_args(
                "get",
                self.tr("'-versionid' is available only for S3 downloads."),
            ));
        }

        let (sources, explicit_local_target) = if paths.len() >= 2 {
            let last = &paths[paths.len() - 1];
            (
                &paths[..paths.len() - 1],
                Some(if last == "-" {
                    PathBuf::from("-")
                } else {
                    resolve_local_against(&self.local_cwd, last)
                }),
            )
        } else {
            (&paths[..], None)
        };

        let mut matched_items: Vec<(String, FileEntry)> = Vec::new();
        for src in sources {
            let resolved = resolve_remote_path(&cwd, src);
            if flags.version_id.is_some() {
                let vid = flags.version_id.as_deref().unwrap_or("");
                let Some(entry) = self.slots[self.active_slot]
                    .session
                    .s3_stat_version(&resolved, vid)
                    .await
                    .map_err(|e| e.to_string())?
                else {
                    return Err(format!(
                        "Remote object version '{resolved}' (version '{vid}') does not exist."
                    ));
                };
                matched_items.push((resolved, entry));
            } else {
                let found = self.expand_remote_pattern(&resolved).await?;
                if found.is_empty() && self.fail_on_nomatch {
                    let msg = format!("No file matching '{src}' found.");
                    self.logger
                        .record_transfer(false, &resolved, "", None, Err(&msg));
                    return Err(msg);
                }
                matched_items.extend(found);
            }
        }

        if flags.latest_only && matched_items.len() > 1 {
            if let Some(newest) = matched_items.iter().max_by_key(|(_, e)| e.mtime).cloned() {
                matched_items = vec![newest];
            }
        }

        let target_must_be_dir = matched_items.len() > 1
            || explicit_local_target
                .as_ref()
                .is_some_and(|p| p != Path::new("-") && p.is_dir());

        for (rpath, rentry) in matched_items {
            if !flags.file_mask.accepts(
                &rentry.name,
                rentry.is_dir,
                rentry.size,
                rentry.mtime.max(0) as u64,
                &rentry.name,
            ) {
                continue;
            }
            if !self.presets_disabled && self.active_preset_name.is_none() {
                if let Ok(store) = TransferPresetStore::load_from_dir(&self.cfg.config_dir) {
                    if let Some(mp) = store.match_mask(&rentry.name) {
                        flags.apply_preset(mp);
                    }
                }
            }
            let local_dest = match &explicit_local_target {
                Some(p) if p == Path::new("-") => PathBuf::from("-"),
                Some(p) if target_must_be_dir => p.join(&rentry.name),
                Some(p) => p.clone(),
                None => self.local_cwd.join(&rentry.name),
            };
            if rentry.is_dir {
                download_directory_recursive(
                    self.slots[self.active_slot].session.as_ref(),
                    &rpath,
                    &local_dest,
                    "",
                    &flags,
                    &mut self.logger,
                    None,
                )
                .await?;
            } else {
                download_single_file(
                    self.slots[self.active_slot].session.as_ref(),
                    &rpath,
                    Some(&rentry),
                    &local_dest,
                    &flags,
                    &mut self.logger,
                    None,
                )
                .await?;
            }
        }
        Ok(())
    }

    async fn cmd_put(&mut self, args: &[String]) -> Result<(), String> {
        let (mut flags, paths) = self.parse_transfer_command_args("put", args, true)?;
        if paths.is_empty() {
            return Err(self.wrong_args(
                "put",
                "Syntax: put [ <switches> ] <file>... [ <remote-target> ]",
            ));
        }
        let cwd = self.active_slot()?.remote_cwd.clone();

        let (sources, explicit_remote_target, target_trailing_slash) = if paths.len() >= 2 {
            let last = &paths[paths.len() - 1];
            (
                &paths[..paths.len() - 1],
                Some(resolve_remote_path(&cwd, last)),
                last.ends_with('/'),
            )
        } else {
            (&paths[..], None, false)
        };

        let mut local_items: Vec<(PathBuf, String, i64, bool, u64)> = Vec::new();
        for src in sources {
            if src == "-" {
                local_items.push((PathBuf::from("-"), "stdin".to_string(), 0, false, 0));
                continue;
            }
            let expanded = expand_tilde(src);
            if has_wildcard(&expanded) {
                let full_pat = resolve_local_against(&self.local_cwd, &expanded);
                let dir = full_pat
                    .parent()
                    .filter(|d| !d.as_os_str().is_empty())
                    .unwrap_or(&self.local_cwd);
                let leaf_pat = full_pat
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let mut hit = 0usize;
                if let Ok(rd) = std::fs::read_dir(dir) {
                    let mut names: Vec<_> = rd.flatten().collect();
                    names.sort_by_key(|d| d.file_name());
                    for de in names {
                        let name = de.file_name().to_string_lossy().into_owned();
                        if matches_wildcard(&leaf_pat, &name) {
                            let st = stat_local_path(&de.path());
                            local_items.push((de.path(), name, st.mtime, st.is_dir, st.size));
                            hit += 1;
                        }
                    }
                }
                if hit == 0 && self.fail_on_nomatch {
                    return Err(format!("No local file matching '{src}' found."));
                }
            } else {
                let p = resolve_local_against(&self.local_cwd, &expanded);
                let st = stat_local_path(&p);
                if !st.exists {
                    let msg = format!("Local file '{src}' does not exist.");
                    self.logger.record_transfer(true, src, "", None, Err(&msg));
                    return Err(msg);
                }
                let name = p
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "file".to_string());
                local_items.push((p, name, st.mtime, st.is_dir, st.size));
            }
        }

        if flags.latest_only && local_items.len() > 1 {
            if let Some(newest) = local_items.iter().max_by_key(|t| t.2).cloned() {
                local_items = vec![newest];
            }
        }

        let remote_target_is_dir = target_trailing_slash
            || local_items.len() > 1
            || if let Some(ref rt) = explicit_remote_target {
                self.slots[self.active_slot]
                    .session
                    .stat(rt)
                    .await
                    .ok()
                    .flatten()
                    .is_some_and(|e| e.is_dir)
            } else {
                true
            };

        for (lpath, lname, _, is_dir, sz) in local_items {
            if lpath != Path::new("-") && !flags.file_mask.accepts(&lname, is_dir, sz, 0, &lname) {
                continue;
            }
            if !self.presets_disabled && self.active_preset_name.is_none() {
                if let Ok(store) = TransferPresetStore::load_from_dir(&self.cfg.config_dir) {
                    if let Some(mp) = store.match_mask(&lname) {
                        flags.apply_preset(mp);
                    }
                }
            }
            let rdest = match &explicit_remote_target {
                Some(rt) if remote_target_is_dir => join_remote_path(rt, &lname),
                Some(rt) => rt.clone(),
                None => join_remote_path(&cwd, &lname),
            };
            if is_dir {
                upload_directory_recursive(
                    self.slots[self.active_slot].session.as_ref(),
                    &lpath,
                    &rdest,
                    "",
                    &flags,
                    &mut self.logger,
                    None,
                )
                .await?;
            } else {
                upload_single_file(
                    self.slots[self.active_slot].session.as_ref(),
                    &lpath,
                    &rdest,
                    &flags,
                    &mut self.logger,
                    None,
                )
                .await?;
            }
        }
        Ok(())
    }

    fn parse_transfer_command_args(
        &self,
        cmd_name: &str,
        args: &[String],
        is_upload: bool,
    ) -> Result<(TransferFlags, Vec<String>), String> {
        let mut flags = self.base_transfer_flags(None)?;
        let mut paths = Vec::new();
        let mut i = 0usize;
        while i < args.len() {
            let a = &args[i];
            if a == "--" {
                paths.extend_from_slice(&args[i + 1..]);
                break;
            }
            if a == "-" || (!a.starts_with('-') && !is_slash_switch(a)) {
                paths.push(a.clone());
                i += 1;
                continue;
            }
            let norm = normalize_switch_prefix(a);
            let low = norm.to_ascii_lowercase();
            match low.as_str() {
                "-delete" => flags.delete_source = true,
                "-resume" => flags.resume = true,
                "-append" => flags.append = true,
                "-neweronly" => flags.newer_only = true,
                "-noneweronly" => flags.newer_only = false,
                "-latest" => flags.latest_only = true,
                "-preservetime" => {
                    flags.preserve_time = true;
                    flags.preserve_time_dirs = false;
                }
                "-preservetime=all" => {
                    flags.preserve_time = true;
                    flags.preserve_time_dirs = true;
                }
                "-nopreservetime" => {
                    flags.preserve_time = false;
                    flags.preserve_time_dirs = false;
                }
                "-r" => flags.recursive = true,
                "-permissions" => {
                    flags.permissions = PresetPermissions::FromFile;
                }
                "-nopermissions" => {
                    flags.permissions = PresetPermissions::Off;
                }
                _ if low.starts_with("-permissions=") => {
                    let v = &norm["-permissions=".len()..];
                    if v.eq_ignore_ascii_case("off") {
                        flags.permissions = PresetPermissions::Off;
                    } else if v.eq_ignore_ascii_case("fromfile") {
                        flags.permissions = PresetPermissions::FromFile;
                    } else {
                        let mode = parse_permissions_expr(v, 0o644, false)?;
                        flags.permissions = PresetPermissions::Mode(mode);
                    }
                }
                _ if low.starts_with("-transfer=") => {
                    let v = &norm["-transfer=".len()..];
                    flags.transfer_mode = parse_transfer_mode(v).ok_or_else(|| {
                        format!(
                            "Invalid '-transfer' mode '{v}' (expected binary, ascii or automatic)."
                        )
                    })?;
                }
                _ if low.starts_with("-eol=") => {
                    let v = &norm["-eol=".len()..];
                    flags.eol_override = Some(EolStyle::parse(v).ok_or_else(|| {
                        format!("Invalid '-eol' style '{v}' (expected lf, crlf or cr).")
                    })?);
                }
                _ if low.starts_with("-speed=") => {
                    let v = &norm["-speed=".len()..];
                    let kb: u64 = v
                        .parse()
                        .map_err(|_| format!("Invalid '-speed' value '{v}' (expected KB/s)."))?;
                    flags.speed_kbytes_per_sec = if kb == 0 { None } else { Some(kb) };
                }
                _ if low.starts_with("-resumesupport=") => {
                    let v = &norm["-resumesupport=".len()..];
                    match v.to_ascii_lowercase().as_str() {
                        "on" => flags.resume_support = ResumeSupportMode::On,
                        "off" => flags.resume_support = ResumeSupportMode::Off,
                        "default" => flags.resume_support = ResumeSupportMode::Smart(100 * 1024),
                        _ => {
                            let kb: u64 = v.parse().map_err(|_| {
                                format!(
                                    "Invalid '-resumesupport' value '{v}' (expected on, off, default or KB)."
                                )
                            })?;
                            flags.resume_support =
                                ResumeSupportMode::Smart(kb.saturating_mul(1024));
                        }
                    }
                }
                _ if low.starts_with("-filemask=") => {
                    let v = &norm["-filemask=".len()..];
                    flags.file_mask = FileMask::parse(v)?;
                }
                _ if low.starts_with("-versionid=") => {
                    if is_upload {
                        return Err(self.wrong_args(
                            cmd_name,
                            self.tr("'-versionid' is available only for S3 downloads."),
                        ));
                    }
                    if flags.version_id.is_some() {
                        return Err(self.wrong_args(
                            cmd_name,
                            self.tr("Give '-versionid' only once."),
                        ));
                    }
                    let v = &norm["-versionid=".len()..];
                    if v.is_empty() {
                        return Err(self.wrong_args(
                            cmd_name,
                            self.tr("The value of '-versionid' cannot be empty."),
                        ));
                    }
                    flags.version_id = Some(v.to_string());
                }
                _ if low.starts_with("-preset=") => {
                    let v = &norm["-preset=".len()..];
                    let store = TransferPresetStore::load_from_dir(&self.cfg.config_dir)?;
                    let Some(p) = store.find(v) else {
                        return Err(format!("There is no transfer preset named '{v}'."));
                    };
                    flags.apply_preset(p);
                }
                _ if low == "-rawtransfersettings" || low.starts_with("-rawtransfersettings=") => {
                    let explicit_count = low
                        .strip_prefix("-rawtransfersettings=")
                        .map(|c| {
                            c.parse::<usize>().map_err(|_| {
                                format!("Invalid '-rawtransfersettings' count '{c}'.")
                            })
                        })
                        .transpose()?;
                    if let Some(cnt) = explicit_count {
                        for _ in 0..cnt {
                            i += 1;
                            let Some(kv) = args.get(i) else {
                                return Err(
                                    "'-rawtransfersettings' ended before reading all pairs."
                                        .to_string(),
                                );
                            };
                            apply_raw_transfer_pair(&mut flags, kv)?;
                        }
                    } else {
                        while i + 1 < args.len()
                            && args[i + 1].contains('=')
                            && !args[i + 1].starts_with('-')
                        {
                            i += 1;
                            apply_raw_transfer_pair(&mut flags, &args[i])?;
                        }
                    }
                }
                _ => {
                    let h = self.trp(
                        "Unsupported switch '{switch}'; it will not be ignored. Prefix a filename beginning with '-' with './'.",
                        &[("switch", a)],
                    );
                    return Err(self.wrong_args(cmd_name, &h));
                }
            }
            i += 1;
        }
        if flags.version_id.is_some() {
            if flags.delete_source || flags.append {
                return Err(self.wrong_args(
                    cmd_name,
                    self.tr("'-versionid' cannot be combined with '-delete' or '-append'."),
                ));
            }
            if flags.latest_only {
                return Err(self.wrong_args(
                    cmd_name,
                    self.tr("'-latest' cannot be combined with '-versionid': one names the newest object, the other one exact version."),
                ));
            }
        }
        Ok((flags, paths))
    }

    async fn cmd_synchronize(&mut self, args: &[String]) -> Result<(), String> {
        let base_tflags = self.base_transfer_flags(None)?;
        let mut opts = SyncOptions {
            delete_obsolete: self.synch_delete,
            transfer_mode: base_tflags.transfer_mode,
            preserve_time: base_tflags.preserve_time,
            permissions: base_tflags.permissions,
            speed_kbytes_per_sec: base_tflags.speed_kbytes_per_sec,
            file_mask: base_tflags.file_mask,
            ..SyncOptions::default()
        };

        let mut positional = Vec::new();
        for a in args {
            if !a.starts_with('-') && !is_slash_switch(a) {
                positional.push(a.clone());
                continue;
            }
            let norm = normalize_switch_prefix(a);
            let low = norm.to_ascii_lowercase();
            match low.as_str() {
                "-delete" => opts.delete_obsolete = true,
                "-nodelete" => opts.delete_obsolete = false,
                "-mirror" => opts.mirror = true,
                "-preview" => opts.preview_only = true,
                "-nonrecursive" => opts.recursive = false,
                "-preservetime" => opts.preserve_time = true,
                "-nopreservetime" => opts.preserve_time = false,
                "-permissions" => opts.permissions = PresetPermissions::FromFile,
                "-nopermissions" => opts.permissions = PresetPermissions::Off,
                _ if low.starts_with("-permissions=") => {
                    let mode =
                        parse_permissions_expr(&norm["-permissions=".len()..], 0o644, false)?;
                    opts.permissions = PresetPermissions::Mode(mode);
                }
                _ if low.starts_with("-criteria=") => {
                    opts.criteria = SyncCriteria::parse(&norm["-criteria=".len()..])?;
                }
                _ if low.starts_with("-conflict=") => {
                    opts.conflict_policy = SyncConflictPolicy::parse(&norm["-conflict=".len()..])?;
                }
                _ if low.starts_with("-filemask=") => {
                    opts.file_mask = FileMask::parse(&norm["-filemask=".len()..])?;
                }
                _ if low.starts_with("-transfer=") => {
                    let v = &norm["-transfer=".len()..];
                    opts.transfer_mode = parse_transfer_mode(v)
                        .ok_or_else(|| format!("Invalid '-transfer' mode '{v}'."))?;
                }
                _ if low.starts_with("-speed=") => {
                    let kb: u64 = norm["-speed=".len()..]
                        .parse()
                        .map_err(|_| "Invalid '-speed' value.".to_string())?;
                    opts.speed_kbytes_per_sec = if kb == 0 { None } else { Some(kb) };
                }
                _ => {
                    let h = self.trp(
                        "Unsupported switch '{switch}'; it will not be ignored.",
                        &[("switch", a)],
                    );
                    return Err(self.wrong_args("synchronize", &h));
                }
            }
        }

        if positional.is_empty() || positional.len() > 3 {
            return Err(self.wrong_args(
                "synchronize",
                "Syntax: synchronize local|remote|both [ <localdir> [ <remotedir> ] ] [ switches ]",
            ));
        }
        const SYNC_MODES: &[&str] = &["local", "remote", "both"];
        opts.mode = match resolve_prefixed_name(SYNC_MODES, &positional[0]) {
            PrefixMatch::ExactOrUnique(m) => SyncMode::parse(m).unwrap_or(SyncMode::Local),
            _ => {
                return Err(self.wrong_args(
                    "synchronize",
                    &format!(
                        "Invalid synchronize direction '{}' (expected local, remote or both).",
                        positional[0]
                    ),
                ));
            }
        };

        // Validate `both` combination constraints BEFORE requiring an active connection!
        if opts.mode == SyncMode::Both {
            if opts.criteria.checksum {
                return Err(self.wrong_args(
                    "synchronize",
                    self.tr("'-criteria=checksum' cannot be combined with the 'both' direction, which compares the record of the previous synchronization instead of the files; synchronize 'local' or 'remote' to compare contents."),
                ));
            }
            if !opts.criteria.time && !opts.criteria.size && !opts.criteria.checksum {
                return Err(self.wrong_args(
                    "synchronize",
                    self.tr("'-criteria=none' cannot be combined with the 'both' direction: with nothing compared there is no way to tell which side changed."),
                ));
            }
            if opts.mirror {
                return Err(self.wrong_args(
                    "synchronize",
                    self.tr("'-mirror' cannot be combined with the 'both' direction."),
                ));
            }
        }

        let local_root = if let Some(ld) = positional.get(1) {
            resolve_local_against(&self.local_cwd, &expand_tilde(ld))
        } else {
            self.local_cwd.clone()
        };
        let remote_cwd = self.active_slot()?.remote_cwd.clone();
        let remote_root = if let Some(rd) = positional.get(2) {
            resolve_remote_path(&remote_cwd, rd)
        } else {
            remote_cwd
        };
        let hostport = {
            let s = &self.active_slot()?.spec.session;
            format!("{}:{}", s.host, s.port)
        };

        let state_key =
            SyncState::make_key(&hostport, &local_root.display().to_string(), &remote_root);
        let state_file = SyncState::state_path(&self.cfg.config_dir, &state_key);
        let mut state = SyncState::load(&state_file)?;

        let plan = plan_synchronization(
            self.slots[self.active_slot].session.as_ref(),
            &local_root,
            &remote_root,
            &opts,
            &state,
        )
        .await?;

        if plan.is_empty() {
            println!("Nothing to synchronize.");
            return Ok(());
        }

        if opts.preview_only {
            for item in &plan {
                println!(
                    "{:<12} {} ({})",
                    item.action.as_str(),
                    item.rel_path,
                    item.reason
                );
            }
        }

        let (applied, conflicts) = apply_sync_plan(
            self.slots[self.active_slot].session.as_ref(),
            &local_root,
            &remote_root,
            &plan,
            &opts,
            &mut state,
            &mut self.logger,
        )
        .await?;

        if !opts.preview_only && opts.mode == SyncMode::Both {
            state.save(&state_file)?;
        }

        if conflicts > 0 {
            return Err(format!(
                "Synchronization encountered {conflicts} conflict(s); pass '-conflict=local|remote|newer' or resolve manually."
            ));
        }
        if !opts.preview_only {
            println!("Synchronized {applied} item(s).");
        }
        Ok(())
    }

    async fn cmd_keepuptodate(&mut self, args: &[String]) -> Result<(), String> {
        let base_tflags = self.base_transfer_flags(None)?;
        let mut opts = KeepUpToDateOptions {
            delete_obsolete: self.synch_delete,
            transfer_mode: base_tflags.transfer_mode,
            preserve_time: base_tflags.preserve_time,
            permissions: base_tflags.permissions,
            speed_kbytes_per_sec: base_tflags.speed_kbytes_per_sec,
            file_mask: base_tflags.file_mask,
            ..KeepUpToDateOptions::default()
        };
        let mut positional = Vec::new();
        for a in args {
            if !a.starts_with('-') && !is_slash_switch(a) {
                positional.push(a.clone());
                continue;
            }
            let norm = normalize_switch_prefix(a);
            let low = norm.to_ascii_lowercase();
            match low.as_str() {
                "-delete" => opts.delete_obsolete = true,
                "-continue" => opts.continue_on_error = true,
                _ if low.starts_with("-interval=") => {
                    let secs: f64 = norm["-interval=".len()..]
                        .parse()
                        .ok()
                        .filter(|&v: &f64| v > 0.0)
                        .ok_or_else(|| "Invalid '-interval' value.".to_string())?;
                    opts.interval_ms = ((secs * 1000.0) as u64).max(50);
                }
                _ if low.starts_with("-count=") || low.starts_with("-iterations=") => {
                    let eq = norm.find('=').unwrap() + 1;
                    let n: u32 = norm[eq..]
                        .parse()
                        .ok()
                        .filter(|&n| n > 0)
                        .ok_or_else(|| "Invalid '-count' value.".to_string())?;
                    opts.max_passes = n;
                }
                _ if low.starts_with("-filemask=") => {
                    opts.file_mask = FileMask::parse(&norm["-filemask=".len()..])?;
                }
                _ if low.starts_with("-transfer=") => {
                    let v = &norm["-transfer=".len()..];
                    opts.transfer_mode = parse_transfer_mode(v)
                        .ok_or_else(|| format!("Invalid '-transfer' mode '{v}'."))?;
                }
                _ => {
                    let h = self.trp(
                        "Unsupported switch '{switch}'; it will not be ignored.",
                        &[("switch", a)],
                    );
                    return Err(self.wrong_args("keepuptodate", &h));
                }
            }
        }
        if positional.len() > 2 {
            return Err(
                "Syntax: keepuptodate [ <localdir> [ <remotedir> ] ] [ switches ]".to_string(),
            );
        }
        let local_root = if let Some(ld) = positional.first() {
            resolve_local_against(&self.local_cwd, &expand_tilde(ld))
        } else {
            self.local_cwd.clone()
        };
        let remote_cwd = self.active_slot()?.remote_cwd.clone();
        let remote_root = if let Some(rd) = positional.get(1) {
            resolve_remote_path(&remote_cwd, rd)
        } else {
            remote_cwd
        };
        let verbose = self.cfg.log_level >= 0;
        run_keep_up_to_date(
            self.slots[self.active_slot].session.as_ref(),
            &local_root,
            &remote_root,
            &opts,
            &mut self.logger,
            |msg| {
                if verbose {
                    println!("{msg}");
                    let _ = std::io::stdout().flush();
                }
            },
        )
        .await?;
        Ok(())
    }

    async fn cmd_edit(&mut self, args: &[String]) -> Result<(), String> {
        let mut opts = EditOptions {
            editor: self.editor_cmd.clone(),
            max_size: self.edit_max_size,
            confirm_upload: self.is_interactive_confirm(),
            ..EditOptions::default()
        };
        let mut paths = Vec::new();
        for a in args {
            let low = a.to_ascii_lowercase();
            if low == "-force" {
                opts.force = true;
            } else if low == "-keep" || low == "-keeptemp" {
                opts.keep_temp_file = true;
            } else if low == "-binary" {
                opts.allow_binary = true;
            } else if low.starts_with("-editor=") {
                opts.editor = a["-editor=".len()..].to_string();
            } else if low.starts_with("-eol=") {
                let e = low["-eol=".len()..].to_string();
                if !matches!(e.as_str(), "preserve" | "lf" | "crlf") {
                    return Err("The value of '-eol' must be preserve, lf or crlf.".to_string());
                }
                opts.eol = e;
            } else if low.starts_with("-encoding=") {
                opts.encoding = a["-encoding=".len()..].to_string();
            } else if low == "-monitor" {
                opts.monitor = true;
                opts.monitor_passes = 1;
            } else if low.starts_with("-monitor=") {
                let val = &a["-monitor=".len()..];
                let passes: u32 = val.parse().ok().filter(|&n| n > 0).ok_or_else(|| {
                    "The value of '-monitor' must be a positive number of passes.".to_string()
                })?;
                opts.monitor = true;
                opts.monitor_passes = passes;
            } else if a.starts_with('-') {
                let h = self.trp(
                    "Unsupported switch '{switch}'; it will not be ignored.",
                    &[("switch", a)],
                );
                return Err(self.wrong_args("edit", &h));
            } else {
                paths.push(a.clone());
            }
        }
        if paths.len() != 1 {
            let h = self.tr("Syntax: edit [-force] [-keep] [-editor=COMMAND] <remotefile>. One file at a time.");
            return Err(self.wrong_args("edit", h));
        }
        let cwd = self.active_slot()?.remote_cwd.clone();
        let remote_path = resolve_remote_path(&cwd, &paths[0]);
        let verbose = self.cfg.log_level >= 0;
        edit_remote_file(
            self.slots[self.active_slot].session.as_ref(),
            &remote_path,
            &opts,
            &mut self.logger,
            |msg| {
                if verbose {
                    println!("{msg}");
                    let _ = std::io::stdout().flush();
                }
            },
        )
        .await
    }

    async fn cmd_etag(&mut self, args: &[String]) -> Result<(), String> {
        let mut match_etag: Option<String> = None;
        let mut nomatch_etag: Option<String> = None;
        let mut get_given = false;
        let mut clear_given = false;
        let mut paths = Vec::new();

        for a in args {
            let low = a.to_ascii_lowercase();
            if low == "-get" {
                get_given = true;
            } else if low == "-clear" {
                clear_given = true;
            } else if low.starts_with("-match=") {
                let v = &a["-match=".len()..];
                if v.is_empty() {
                    return Err("'-match=' requires a non-empty ETag.".to_string());
                }
                match_etag = Some(v.to_string());
            } else if low.starts_with("-nomatch=") {
                let v = &a["-nomatch=".len()..];
                if v.is_empty() {
                    return Err("'-nomatch=' requires a non-empty ETag.".to_string());
                }
                nomatch_etag = Some(v.to_string());
            } else if a.starts_with('-') {
                let h = self.trp("Unknown switch '{switch}'.", &[("switch", a)]);
                return Err(self.wrong_args("etag", &h));
            } else {
                paths.push(a.clone());
            }
        }

        let mode_count = usize::from(get_given)
            + usize::from(clear_given)
            + usize::from(match_etag.is_some())
            + usize::from(nomatch_etag.is_some());
        if paths.len() != 1 || mode_count != 1 {
            return Err(self.wrong_args(
                "etag",
                self.tr("Give exactly one of -match=ETAG, -nomatch=ETAG, -get or -clear."),
            ));
        }

        let slot = self.active_slot()?;
        let scheme = slot.session.scheme();
        let proto_name = scheme.as_str();
        let path = resolve_remote_path(&slot.remote_cwd, &paths[0]);

        if get_given {
            if !is_webdav_scheme(scheme) {
                println!(
                    "{}",
                    self.trp(
                        "(ETag not available for {protocol} protocol.)",
                        &[("protocol", proto_name)],
                    )
                );
                return Ok(());
            }
            let (etag_opt, missing) = self.slots[self.active_slot]
                .session
                .dav_get_etag(&path)
                .await
                .map_err(|e| e.to_string())?;
            if let Some(etag) = etag_opt.filter(|s| !s.is_empty()) {
                println!("{etag}");
            } else if missing {
                println!(
                    "{}",
                    self.trp("No ETag: '{path}' does not exist.", &[("path", &path)])
                );
            } else {
                println!(
                    "{}",
                    self.trp(
                        "The server reported no ETag for '{path}'.",
                        &[("path", &path)],
                    )
                );
            }
            return Ok(());
        }

        if !is_webdav_scheme(scheme) {
            return Err(self.trp(
                "(ETag not available for {protocol} protocol.)",
                &[("protocol", proto_name)],
            ));
        }

        if clear_given {
            self.slots[self.active_slot]
                .session
                .dav_set_etag_precondition(&path, None)
                .await
                .map_err(|e| e.to_string())?;
            println!(
                "{}",
                self.trp("Cleared ETag precondition on {path}.", &[("path", &path)])
            );
            return Ok(());
        }

        let (hdr_kind, val) = if let Some(ref m) = match_etag {
            ("If-Match", m.clone())
        } else {
            ("If-None-Match", nomatch_etag.clone().unwrap_or_default())
        };
        let pre = DavEtagPrecondition {
            if_match: match_etag,
            if_none_match: nomatch_etag,
        };
        self.slots[self.active_slot]
            .session
            .dav_set_etag_precondition(&path, Some(pre))
            .await
            .map_err(|e| e.to_string())?;
        println!(
            "{}",
            self.trp(
                "{type}: {etag} on {path}.",
                &[("type", hdr_kind), ("etag", &val), ("path", &path)],
            )
        );
        Ok(())
    }

    async fn cmd_lock(&mut self, args: &[String]) -> Result<(), String> {
        let mut timeout_secs = 3600u32;
        let mut paths = Vec::new();
        for a in args {
            let low = a.to_ascii_lowercase();
            if low.starts_with("-timeout=") {
                timeout_secs = a["-timeout=".len()..]
                    .parse::<u32>()
                    .ok()
                    .filter(|&t| t > 0)
                    .ok_or_else(|| {
                        "'-timeout=' must be a positive number of seconds.".to_string()
                    })?;
            } else if a.starts_with('-') {
                let h = self.trp("Unknown switch '{switch}'.", &[("switch", a)]);
                return Err(self.wrong_args("lock", &h));
            } else {
                paths.push(a.clone());
            }
        }
        if paths.len() != 1 {
            return Err("Syntax: lock <file> [-timeout=SECONDS]".to_string());
        }
        let slot = self.active_slot()?;
        if !is_webdav_scheme(slot.session.scheme()) {
            return Err("'lock' is supported only for WebDAV sessions.".to_string());
        }
        let path = resolve_remote_path(&slot.remote_cwd, &paths[0]);
        let token = self.slots[self.active_slot]
            .session
            .dav_lock(&path, timeout_secs)
            .await
            .map_err(|e| e.to_string())?;
        let _ = token;
        println!(
            "{}",
            self.trp("Lock acquired on '{path}'.", &[("path", &path)])
        );
        Ok(())
    }

    async fn cmd_unlock(&mut self, args: &[String]) -> Result<(), String> {
        let mut token_opt: Option<String> = None;
        let mut paths = Vec::new();
        for a in args {
            let low = a.to_ascii_lowercase();
            if low.starts_with("-token=") {
                token_opt = Some(a["-token=".len()..].to_string());
            } else if a.starts_with('-') {
                let h = self.trp("Unknown switch '{switch}'.", &[("switch", a)]);
                return Err(self.wrong_args("unlock", &h));
            } else {
                paths.push(a.clone());
            }
        }
        if paths.len() != 1 {
            return Err("Syntax: unlock <file>".to_string());
        }
        let slot = self.active_slot()?;
        if !is_webdav_scheme(slot.session.scheme()) {
            return Err("'unlock' is supported only for WebDAV sessions.".to_string());
        }
        let path = resolve_remote_path(&slot.remote_cwd, &paths[0]);
        self.slots[self.active_slot]
            .session
            .dav_unlock(&path, token_opt.as_deref())
            .await
            .map_err(|e| e.to_string())?;
        println!(
            "{}",
            self.trp("Lock released on '{path}'.", &[("path", &path)])
        );
        Ok(())
    }

    async fn cmd_property(&mut self, args: &[String]) -> Result<(), String> {
        let mut get_name: Option<String> = None;
        let mut set_pair: Option<(String, String)> = None;
        let mut paths = Vec::new();

        for a in args {
            let low = a.to_ascii_lowercase();
            if low.starts_with("-get=") {
                get_name = Some(a["-get=".len()..].to_string());
            } else if low.starts_with("-set=") {
                let rest = &a["-set=".len()..];
                let Some((k, v)) = rest.split_once('=') else {
                    return Err(self.wrong_args("property", self.tr("'-set' takes NAME=VALUE.")));
                };
                set_pair = Some((k.to_string(), v.to_string()));
            } else if a.starts_with('-') {
                let h = self.trp("Unknown switch '{switch}'.", &[("switch", a)]);
                return Err(self.wrong_args("property", &h));
            } else {
                paths.push(a.clone());
            }
        }
        if paths.len() != 1
            || get_name.is_some() == set_pair.is_some()
            || get_name.as_deref() == Some("")
        {
            return Err(self.wrong_args(
                "property",
                self.tr("Syntax: property <file> -get=NAME | property <file> -set=NAME=VALUE"),
            ));
        }

        let slot = self.active_slot()?;
        if !is_webdav_scheme(slot.session.scheme()) {
            return Err("'property' is supported only for WebDAV sessions.".to_string());
        }
        let path = resolve_remote_path(&slot.remote_cwd, &paths[0]);

        if let Some((k, v)) = set_pair {
            self.slots[self.active_slot]
                .session
                .dav_set_property(&path, &k, &v)
                .await
                .map_err(|e| e.to_string())?;
            println!(
                "{}",
                self.trp(
                    "Set {name} on {path}.",
                    &[("name", &k), ("path", &path)],
                )
            );
            return Ok(());
        }

        let name = get_name.unwrap();
        match self.slots[self.active_slot]
            .session
            .dav_get_property(&path, &name)
            .await
            .map_err(|e| e.to_string())?
        {
            Some(val) => println!(
                "{}",
                self.trp("{name}={value}", &[("name", &name), ("value", &val)])
            ),
            None => println!(
                "{}",
                self.trp(
                    "{name} is not set on {path}.",
                    &[("name", &name), ("path", &path)],
                )
            ),
        }
        Ok(())
    }

    async fn cmd_versions(&mut self, args: &[String]) -> Result<(), String> {
        if args.len() > 1 || args.first().is_some_and(|a| a.starts_with('-')) {
            return Err(self.wrong_args("versions", self.tr("Syntax: versions [<object-or-prefix>]")));
        }
        let slot = self.active_slot()?;
        if slot.session.scheme() != ProtocolScheme::S3 {
            return Err(self.wrong_args(
                "versions",
                self.tr("The 'versions' command is available only for S3 sessions."),
            ));
        }
        let path = if let Some(arg) = args.first() {
            resolve_remote_path(&slot.remote_cwd, arg)
        } else {
            slot.remote_cwd.clone()
        };
        let versions = self.slots[self.active_slot]
            .session
            .s3_list_versions(&path)
            .await
            .map_err(|e| {
                let es = e.to_string();
                self.trp(
                    "Could not list S3 object versions for '{path}': {reason}",
                    &[("path", &path), ("reason", &es)],
                )
            })?;
        if versions.is_empty() {
            println!(
                "{}",
                self.trp(
                    "No S3 object versions found for '{path}'.",
                    &[("path", &path)],
                )
            );
            return Ok(());
        }
        println!(
            "{}",
            self.trp("Object versions for '{path}':", &[("path", &path)])
        );
        let bucket_root = match path[1..].find('/') {
            Some(idx) => &path[..idx + 1],
            None => path.as_str(),
        };
        for item in versions {
            let state = if item.is_delete_marker {
                self.tr("delete marker")
            } else if item.is_latest {
                self.tr("latest")
            } else {
                self.tr("version")
            };
            let size_str = if item.is_delete_marker {
                "-".to_string()
            } else {
                item.size.to_string()
            };
            let mod_str = if item.mtime == 0 {
                "?".to_string()
            } else {
                format_ls_time(item.mtime)
            };
            println!(
                "{state}  {bucket_root}/{}  {}  {size_str}  {mod_str}",
                item.key, item.version_id
            );
        }
        Ok(())
    }

    async fn cmd_terminal(&mut self, args: &[String]) -> Result<(), String> {
        let mut desktop = false;
        for a in args {
            if a.eq_ignore_ascii_case("-desktop") {
                desktop = true;
            } else {
                return Err("Syntax: terminal [-desktop]".to_string());
            }
        }
        let spec = self.active_slot()?.spec.clone();
        if !is_ssh_scheme(spec.session.protocol) {
            return Err("'terminal' requires an SSH/SFTP/SCP session.".to_string());
        }
        if desktop {
            let user = if spec.session.username.is_empty() {
                linscp_platform::terminal::current_username()
            } else {
                spec.session.username.clone()
            };
            return launch_desktop_ssh_terminal(
                &spec.session.host,
                spec.session.port,
                &user,
                &self.slots[self.active_slot].remote_cwd,
            );
        }
        let (conn, jump) = connect_ssh_for_shell(
            &spec,
            &self.cfg.config_dir,
            self.is_interactive_confirm(),
            self.is_interactive_auth(),
            &self.cfg.locale,
            self.cfg.log_level,
            None,
        )
        .await?;
        let code = run_pty_shell_session(&conn).await?;
        let _ = conn.disconnect().await;
        if let Some(j) = jump {
            let _ = j.close().await;
        }
        if code != 0 {
            return Err(format!("Remote shell exited with status {code}."));
        }
        Ok(())
    }

    async fn expand_remote_pattern(
        &mut self,
        resolved_pattern: &str,
    ) -> Result<Vec<(String, FileEntry)>, String> {
        if has_wildcard(resolved_pattern) {
            let (parent, mask) = remote_parent_and_name(resolved_pattern);
            let entries = self.slots[self.active_slot]
                .session
                .list_dir(&parent)
                .await
                .map_err(|e| e.to_string())?;
            let mut out: Vec<(String, FileEntry)> = entries
                .into_iter()
                .filter(|e| e.name != "." && e.name != ".." && matches_wildcard(&mask, &e.name))
                .map(|e| {
                    let p = join_remote_path(&parent, &e.name);
                    (p, e)
                })
                .collect();
            out.sort_by(|a, b| a.0.cmp(&b.0));
            Ok(out)
        } else {
            match self.slots[self.active_slot]
                .session
                .stat(resolved_pattern)
                .await
                .map_err(|e| e.to_string())?
            {
                Some(mut entry) => {
                    if entry.name.is_empty() || entry.name == "/" {
                        let (_, leaf) = remote_parent_and_name(resolved_pattern);
                        if !leaf.is_empty() {
                            entry.name = leaf;
                        }
                    }
                    Ok(vec![(resolved_pattern.to_string(), entry)])
                }
                None => Ok(Vec::new()),
            }
        }
    }
}

/// Splits a `-command=...` string on unquoted `;` delimiters while preserving
/// `;` inside single or double quotes (`\"` and `\\` escaped inside double quotes).
pub fn split_semicolon_commands(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = input.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;

    while let Some(c) = chars.next() {
        if in_single {
            cur.push(c);
            if c == '\'' {
                in_single = false;
            }
        } else if in_double {
            cur.push(c);
            if c == '\\' && matches!(chars.peek(), Some('"' | '\\')) {
                cur.push(chars.next().unwrap());
            } else if c == '"' {
                in_double = false;
            }
        } else {
            match c {
                '\'' => {
                    in_single = true;
                    cur.push(c);
                }
                '"' => {
                    in_double = true;
                    cur.push(c);
                }
                '\\' => {
                    cur.push('\\');
                    if let Some(nc) = chars.next() {
                        cur.push(nc);
                    }
                }
                ';' => {
                    out.push(std::mem::take(&mut cur));
                }
                _ => cur.push(c),
            }
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Runs an interactive SSH PTY shell (`linscp -shell <site>` or `terminal`),
/// enforcing `xterm-256color`, `SIGWINCH` window-change forwarding, full stdout/stderr
/// draining, and strict verification that `ChannelMsg::Eof` arrived alongside `exit-status`.
pub async fn run_pty_shell_session(conn: &SshConnection) -> Result<i32, String> {
    let (cols, rows) = terminal_size();
    let mut channel = conn
        .open_pty_shell("xterm-256color", cols, rows)
        .await
        .map_err(|e| e.to_string())?;

    let _raw_guard = RawTerminalGuard::enter();

    let (stdin_tx, mut stdin_rx) = tokio::sync::mpsc::channel::<Option<Vec<u8>>>(16);
    let stop_stdin = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_flag = stop_stdin.clone();

    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            if stop_flag.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            match read_stdin_chunk(&mut buf) {
                Ok(0) => {
                    let _ = stdin_tx.blocking_send(None);
                    break;
                }
                Ok(n) => {
                    if stdin_tx.blocking_send(Some(buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    let _ = stdin_tx.blocking_send(None);
                    break;
                }
            }
        }
    });

    let mut saw_eof = false;
    let mut exit_code: Option<u32> = None;
    let mut sent_stdin_eof = false;
    let mut resize_tick = tokio::time::interval(Duration::from_millis(100));

    loop {
        tokio::select! {
            msg_opt = channel.wait() => {
                match msg_opt {
                    Some(ChannelMsg::Data { data }) => {
                        let _ = std::io::stdout().write_all(&data);
                        let _ = std::io::stdout().flush();
                    }
                    Some(ChannelMsg::ExtendedData { data, .. }) => {
                        let _ = std::io::stderr().write_all(&data);
                        let _ = std::io::stderr().flush();
                    }
                    Some(ChannelMsg::Eof) => {
                        saw_eof = true;
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        exit_code = Some(exit_status);
                    }
                    Some(ChannelMsg::ExitSignal { .. }) => {
                        if exit_code.is_none() {
                            exit_code = Some(128);
                        }
                    }
                    Some(ChannelMsg::Close) | None => {
                        break;
                    }
                    _ => {}
                }
            }
            in_item = stdin_rx.recv(), if !sent_stdin_eof => {
                match in_item {
                    Some(Some(bytes)) => {
                        if channel.data(&bytes[..]).await.is_err() {
                            break;
                        }
                    }
                    Some(None) | None => {
                        sent_stdin_eof = true;
                        let _ = channel.eof().await;
                    }
                }
            }
            _ = resize_tick.tick() => {
                if take_window_resized() {
                    let (nc, nr) = terminal_size();
                    let _ = channel.window_change(nc, nr, 0, 0).await;
                }
            }
        }
    }

    stop_stdin.store(true, std::sync::atomic::Ordering::Relaxed);
    drop(_raw_guard);

    match (exit_code, saw_eof) {
        (Some(code), true) => Ok(code as i32),
        (Some(_), false) => Err(
            "Remote SSH shell closed with an exit-status before sending channel EOF (output may have been truncated)."
                .to_string(),
        ),
        (None, _) => Err("Remote SSH shell closed without reporting an exit status.".to_string()),
    }
}

pub fn apply_open_switches(
    spec: &mut ParsedSiteSpec,
    switches: &[String],
    allow_preset_switch: bool,
    locale: &str,
) -> Result<(), String> {
    let mut i = 0usize;
    while i < switches.len() {
        let raw = &switches[i];
        let norm = normalize_switch_prefix(raw);
        let low = norm.to_ascii_lowercase();

        if low == "-rawsettings" {
            let raw_pairs: Vec<String> = switches[i + 1..].to_vec();
            if raw_pairs.is_empty() {
                return Err("'-rawsettings' requires at least one NAME=VALUE setting.".to_string());
            }
            apply_raw_settings(spec, &raw_pairs)?;
            break;
        } else if low.starts_with("-hostkey=") {
            spec.session.hostkey = norm["-hostkey=".len()..].to_string();
        } else if low.starts_with("-password=") {
            spec.session.password = Some(norm["-password=".len()..].to_string());
        } else if low.starts_with("-username=") {
            spec.session.username = norm["-username=".len()..].to_string();
        } else if low.starts_with("-privatekey=") || low.starts_with("-keyfile=") {
            let eq = norm.find('=').unwrap() + 1;
            let val = &norm[eq..];
            spec.session.keyfile = if val.is_empty() {
                None
            } else {
                Some(expand_tilde(val))
            };
        } else if low.starts_with("-passphrase=") {
            spec.passphrase = Some(norm["-passphrase=".len()..].to_string());
        } else if low.starts_with("-clientcert=") {
            let val = expand_tilde(&norm["-clientcert=".len()..]);
            spec.raw_fields
                .insert("tls_certificate_file".to_string(), val);
        } else if low.starts_with("-certificate=") {
            let val = &norm["-certificate=".len()..];
            if val == "*" {
                spec.session.hostkey = "*".to_string();
            } else {
                apply_raw_settings(spec, &[format!("PinnedPublicKey={val}")])?;
            }
        } else if low.starts_with("-timeout=") {
            let secs: u64 = norm["-timeout=".len()..]
                .parse()
                .ok()
                .filter(|&s| s > 0)
                .ok_or_else(|| "'-timeout=' must be a positive number of seconds.".to_string())?;
            spec.timeout_secs = secs;
        } else if low == "-implicit" || low == "-implicit=on" {
            apply_raw_settings(spec, &["Ftps=1".to_string()])?;
        } else if low == "-implicit=off" {
            apply_raw_settings(spec, &["Ftps=0".to_string()])?;
        } else if low == "-explicit" || low == "-explicit=on" {
            apply_raw_settings(spec, &["Ftps=3".to_string()])?;
        } else if low == "-explicit=off" {
            apply_raw_settings(spec, &["Ftps=0".to_string()])?;
        } else if low == "-passive" || low == "-passive=on" {
            apply_raw_settings(spec, &["FtpPasvMode=1".to_string()])?;
        } else if low == "-passive=off" {
            apply_raw_settings(spec, &["FtpPasvMode=0".to_string()])?;
        } else if low.starts_with("-sessionname=") {
            spec.session_label = norm["-sessionname=".len()..].to_string();
        } else if allow_preset_switch && low.starts_with("-preset=") {
            spec.preset_name = norm["-preset=".len()..].to_string();
        } else {
            let sw_err = translate_with(
                CatalogDomain::Cli,
                locale,
                "Unknown switch '{switch}'.",
                &[("switch", raw)],
            );
            return Err(translate_with(
                CatalogDomain::Cli,
                locale,
                "Wrong arguments of '{command}' command. {hint}",
                &[("command", "open"), ("hint", &sw_err)],
            ));
        }
        i += 1;
    }
    Ok(())
}

fn apply_raw_transfer_pair(flags: &mut TransferFlags, pair: &str) -> Result<(), String> {
    let Some((k, v)) = pair.split_once('=') else {
        return Err(format!(
            "Invalid '-rawtransfersettings' item '{pair}' (expected NAME=VALUE)."
        ));
    };
    match k.trim().to_ascii_lowercase().as_str() {
        "preservetimedirs" => {
            flags.preserve_time_dirs = matches!(v.trim(), "1" | "on" | "true");
        }
        "preservetime" => {
            flags.preserve_time = matches!(v.trim(), "1" | "on" | "true");
        }
        "transfermode" => {
            flags.transfer_mode = match v.trim() {
                "0" | "binary" => TransferMode::Binary,
                "1" | "ascii" => TransferMode::Ascii,
                "2" | "automatic" => TransferMode::Automatic,
                _ => return Err(format!("Invalid TransferMode '{v}'.")),
            };
        }
        "neweronly" => {
            flags.newer_only = matches!(v.trim(), "1" | "on" | "true");
        }
        "speedlimit" => {
            let kb: u64 = v
                .trim()
                .parse()
                .map_err(|_| format!("Invalid SpeedLimit '{v}'."))?;
            flags.speed_kbytes_per_sec = if kb == 0 { None } else { Some(kb) };
        }
        other => {
            return Err(format!("Unsupported raw transfer setting '{other}'."));
        }
    }
    Ok(())
}

fn canonical_alias(name: &str) -> &str {
    match name {
        "!" => "call",
        "?" | "man" => "help",
        "del" => "rm",
        "delsession" => "rmsession",
        "dir" => "ls",
        "end" | "quit" | "bye" => "exit",
        "md" => "mkdir",
        "mget" | "recv" => "get",
        "mput" | "send" => "put",
        "rename" => "mv",
        "symlink" => "ln",
        "sync" => "synchronize",
        other => other,
    }
}

fn parse_option_on_off(val: &str, opt_name: &str) -> Result<bool, String> {
    const VALS: &[&str] = &["on", "off"];
    match resolve_prefixed_name(VALS, val) {
        PrefixMatch::ExactOrUnique("on") => Ok(true),
        PrefixMatch::ExactOrUnique("off") => Ok(false),
        _ => Err(format!("The value of '{opt_name}' must be 'on' or 'off'.")),
    }
}

fn is_slash_switch(tok: &str) -> bool {
    if !tok.starts_with('/') || tok.len() < 2 {
        return false;
    }
    let body = &tok[1..];
    if let Some((name, _)) = body.split_once(['=', ':']) {
        return !name.is_empty() && !name.contains('/');
    }
    false
}

pub fn normalize_switch_prefix(raw: &str) -> String {
    let body = if let Some(b) = raw.strip_prefix("--") {
        b
    } else if let Some(b) = raw.strip_prefix('-') {
        b
    } else if is_slash_switch(raw) {
        &raw[1..]
    } else {
        return raw.to_string();
    };
    if let Some(idx) = body.find(['=', ':']) {
        format!("-{}={}", &body[..idx], &body[idx + 1..])
    } else {
        format!("-{body}")
    }
}

fn resolve_local_against(cwd: &Path, input: &str) -> PathBuf {
    let p = Path::new(input);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        cwd.join(p)
    }
}

fn format_ls_3col_date(mtime: i64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (y, m, d, hh, mm, _, _) = linscp_platform::terminal::local_ymdhms_wday(mtime.max(0));
    let mon = MONTHS
        .get(m.saturating_sub(1) as usize)
        .copied()
        .unwrap_or("Jan");
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|dur| dur.as_secs() as i64)
        .unwrap_or(0);
    // Standard POSIX `ls -l`: recent files within ~6 months show `HH:MM`, older/future show `YYYY`
    let diff = (now_secs - mtime).abs();
    if mtime > 0 && diff < 180 * 86_400 {
        format!("{mon} {d:>2} {hh:02}:{mm:02}")
    } else {
        format!("{mon} {d:>2}  {y:04}")
    }
}

fn format_listing_line(entry: &FileEntry, link_target: Option<&str>) -> String {
    let perms = if entry.permissions.len() == 10 {
        entry.permissions.clone()
    } else {
        let m = mode_from_permissions_str(&entry.permissions);
        let default_m = if m != 0 {
            m
        } else if entry.is_dir {
            0o755
        } else {
            0o644
        };
        format_permissions_10(default_m, entry.is_dir, entry.is_symlink)
    };
    let owner = entry.owner.as_deref().filter(|s| !s.is_empty()).unwrap_or("0");
    let group = entry.group.as_deref().filter(|s| !s.is_empty()).unwrap_or("0");
    let ts = format_ls_3col_date(entry.mtime);
    let display_name = match link_target {
        Some(tgt) if entry.is_symlink && !tgt.is_empty() && !entry.name.contains(" -> ") => {
            format!("{} -> {tgt}", entry.name)
        }
        _ => entry.name.clone(),
    };
    format!(
        "{perms} 1 {owner:<8} {group:<8} {:>10} {ts} {display_name}",
        entry.size
    )
}
