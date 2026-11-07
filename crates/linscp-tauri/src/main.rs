#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! `linscp-gui` — the native window, plus the one-shot actions its own
//! documentation and file-manager actions invoke.
//!
//! The window is the default: a bare double-click, a desktop `Exec=` line or any
//! argument Tauri adds still opens it. Two documented features are *not* the
//! window, though, and both are started by another process:
//!
//! * `--install-shell-integration` / `--uninstall-shell-integration` write or
//!   remove the per-user "Upload with LinSCP" actions.
//! * `--shell-upload FILES…` is what those actions run; it records the selection
//!   and exits so the file manager's request finishes immediately.
//!
//! Both were unreachable until this file looked at its arguments at all (audit item
//! A3): the definitions were written by code no shipped entry point called. The
//! parsing lives in `linscp_platform::cli_args` and the work in
//! `linscp_service::cli_actions`, so both are unit tested on hosts that can run
//! them; this file only connects the two and speaks.

use std::io::Write;
use std::path::PathBuf;

use linscp_platform::cli_args::{self, Action};
use linscp_service::cli_actions::ActionOutcome;

fn main() {
    let action = cli_args::parse(&std::env::args().skip(1).collect::<Vec<_>>());
    match action {
        Action::OpenWindow => linscp_tauri::run_native_app(tauri::generate_context!()),
        Action::Help => {
            // `Help` is printed, not run: it must never depend on a running window.
            let mut out = Output::open();
            out.write_stdout(cli_args::USAGE);
        }
        action => {
            let outcome = run_action(action);
            let mut out = Output::open();
            out.write_outcome(&outcome);
            std::process::exit(outcome.exit_code);
        }
    }
}

/// Where an action's words go.
///
/// On every platform but Windows this is standard output and standard error, which
/// a file manager or a script has already connected. Windows needs more than that:
/// the release binary is built with `windows_subsystem = "windows"`, so it is
/// started without a console and its standard handles point at nothing. Attaching to
/// the parent's console gives it one, and writing to the console itself — not to the
/// `stdout` nobody is reading — is what makes the answer visible in the terminal that
/// ran it.
struct Output {
    #[cfg(windows)]
    console: Option<std::fs::File>,
}

impl Output {
    fn open() -> Self {
        Self {
            #[cfg(windows)]
            console: linscp_platform::windows::attach_parent_console(),
        }
    }

    fn write_stdout(&mut self, text: &str) {
        #[cfg(windows)]
        if let Some(console) = self.console.as_mut() {
            // `\r\n`, because the console translates nothing for a File.
            let _ = console.write_all(text.replace('\n', "\r\n").as_bytes());
            let _ = console.flush();
            return;
        }
        print!("{text}");
        let _ = std::io::stdout().flush();
    }

    fn write_outcome(&mut self, outcome: &ActionOutcome) {
        for line in &outcome.stdout {
            self.write_stdout(&format!("{line}\n"));
        }
        // Diagnostic text goes to the same place; a windowing process has no
        // separate error stream to give it to.
        for line in &outcome.stderr {
            self.write_stdout(&format!("{line}\n"));
        }
    }
}

/// Performs the action. `main` has already established that this is not a window.
fn run_action(action: Action) -> ActionOutcome {
    match action {
        Action::InstallShellIntegration => {
            // The definitions must run *this* executable, wherever it was installed:
            // a package upgrade or a moved AppImage would otherwise leave them
            // pointing at a path that no longer exists.
            let launcher = std::env::current_exe().unwrap_or_else(|_| "linscp-gui".into());
            linscp_service::cli_actions::install_shell_integration(&launcher)
        }
        Action::UninstallShellIntegration => linscp_service::cli_actions::uninstall_shell_integration(),
        Action::ShellUpload(files) => {
            // A file manager passes absolute paths; a script may not, and this
            // process's working directory is not necessarily where the user was.
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            linscp_service::cli_actions::shell_upload_from(
                &linscp_platform::config_dir(),
                &files,
                &cwd,
            )
        }
        // Already handled above; kept so this function cannot silently do nothing
        // if a future action is added without a branch here.
        Action::OpenWindow | Action::Help => ActionOutcome {
            exit_code: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
        },
    }
}
