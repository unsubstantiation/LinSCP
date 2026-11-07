//! Command-line actions of the native window binary (`linscp-gui`).
//!
//! The GUI is not a CLI: it exists to open a window on the page. But two of its
//! documented features are *invoked by something other than the user*, and both of
//! them start a second copy of the binary:
//!
//! * `--install-shell-integration` / `--uninstall-shell-integration` — writes or
//!   removes the per-user "Upload with LinSCP" file-manager actions.
//! * `--shell-upload FILES…` — the command those actions run with the user's
//!   selection. It records a pending manifest and exits; the running window picks
//!   the selection up from disk (`/api/shell/pending`).
//!
//! Both used to be unreachable, because `main.rs` started Tauri without looking at
//! its arguments, so the shipped artifact ignored the command line its own
//! documentation described (audit item A3). This module is the whole argument
//! surface: it is pure — arguments in, an `Action` out — so the decisions can be
//! tested on any host, and executing them happens in the caller.
//!
//! Anything this module does not recognise is *not* an error: the caller opens the
//! window exactly as before. That keeps double-clicking the binary, a desktop
//! `Exec=` line and every existing launch path working unchanged.

use std::path::PathBuf;

/// What the process was asked to do before (or instead of) opening a window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Start the window. The default, and what any unrecognised argument gets.
    OpenWindow,
    /// Write the per-user file-manager actions (Dolphin, GNOME Files, Nemo on
    /// Linux; the Explorer *Send To* shortcut on Windows).
    InstallShellIntegration,
    /// Remove the actions `InstallShellIntegration` wrote, and nothing else.
    UninstallShellIntegration,
    /// Record this selection as a pending upload and exit. The paths are what the
    /// file manager produced; they are validated when the manifest is written.
    ShellUpload(Vec<PathBuf>),
    /// Print the usage text and exit successfully.
    Help,
}

/// Arguments that mean "this copy is not the window".
///
/// Spelled out rather than pattern-matched so a future flag cannot silently start
/// opening windows: adding one here is how a new action becomes reachable.
const INSTALL: &str = "--install-shell-integration";
const UNINSTALL: &str = "--uninstall-shell-integration";
const SHELL_UPLOAD: &str = "--shell-upload";
const HELP: &str = "--help";

/// Turns the process arguments (without `argv[0]`) into the action to perform.
///
/// * `--shell-upload` consumes **every** following argument, including ones that
///   begin with `-`: a file may be called `-notes.txt`, and the file manager passes
///   the selection verbatim. It must be last, so nothing is silently swallowed.
/// * `--install…`/`--uninstall…` ignore anything after them; they are one-shot
///   commands whose meaning cannot depend on extra words.
/// * `--ACTION=value` is rejected rather than guessed at: an unknown form falls
///   through to opening the window, which is the safe default.
pub fn parse<S: AsRef<str>>(args: &[S]) -> Action {
    let words: Vec<&str> = args.iter().map(|a| a.as_ref()).collect();

    if words.iter().any(|word| *word == HELP) {
        return Action::Help;
    }

    // Every action flag is one-shot. If two are given the command line is
    // contradictory, so the window opens and the user sees something rather than
    // this code picking a winner.
    let action_flags = [INSTALL, UNINSTALL, SHELL_UPLOAD];
    let present: Vec<&str> = action_flags
        .iter()
        .copied()
        .filter(|flag| words.contains(flag))
        .collect();
    if present.len() != 1 {
        return Action::OpenWindow;
    }
    let flag = present[0];

    match flag {
        INSTALL => Action::InstallShellIntegration,
        UNINSTALL => Action::UninstallShellIntegration,
        SHELL_UPLOAD => {
            let position = words.iter().position(|word| *word == SHELL_UPLOAD).unwrap_or(0);
            let files: Vec<PathBuf> = words[position + 1..].iter().map(PathBuf::from).collect();
            if files.is_empty() {
                // An action with an empty selection has nothing to stage; the
                // manifest writer would refuse it too, but opening a window from a
                // file-manager right-click would be worse than doing nothing.
                Action::OpenWindow
            } else {
                Action::ShellUpload(files)
            }
        }
        _ => Action::OpenWindow,
    }
}

/// The usage text `--help` prints. Kept next to the parser so the two cannot drift.
pub const USAGE: &str = "\
LinSCP \u{2014} dual-pane file transfer client.

Usage:
  linscp-gui                                  Open the window (the default).
  linscp-gui --install-shell-integration      Add the per-user \"Upload with LinSCP\"
                                              action to Dolphin, GNOME Files and Nemo
                                              (Linux) or to the Explorer Send To menu
                                              (Windows), for this user only.
  linscp-gui --uninstall-shell-integration    Remove exactly what the install wrote.
  linscp-gui --shell-upload FILE...           Stage FILE... as a pending upload for a
                                              running LinSCP window, then exit. This
                                              is what the installed actions run;
                                              nothing is transferred until the window
                                              confirms.
  linscp-gui --help                           Print this text.

Any other argument, including none, opens the window.
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_launch_opens_the_window() {
        assert_eq!(parse::<&str>(&[]), Action::OpenWindow);
        // Tauri and webview runtimes add arguments of their own on some platforms;
        // none of them may be mistaken for an action.
        assert_eq!(parse(&["--ozone-platform=wayland"]), Action::OpenWindow);
        assert_eq!(parse(&["--webview-arg"]), Action::OpenWindow);
        assert_eq!(parse(&["a-path-without-a-flag"]), Action::OpenWindow);
    }

    #[test]
    fn the_shell_actions_are_reachable() {
        assert_eq!(parse(&[INSTALL]), Action::InstallShellIntegration);
        assert_eq!(parse(&[UNINSTALL]), Action::UninstallShellIntegration);
        // `--ACTION=value` is not the documented form; do not guess at it.
        assert_eq!(parse(&["--install-shell-integration=yes"]), Action::OpenWindow);
    }

    #[test]
    fn shell_upload_takes_the_whole_selection() {
        assert_eq!(
            parse(&[SHELL_UPLOAD, "/home/alice/report.pdf", "/home/alice/photos"]),
            Action::ShellUpload(vec![
                PathBuf::from("/home/alice/report.pdf"),
                PathBuf::from("/home/alice/photos"),
            ])
        );
        // One argument per selected file is the contract the Windows *Send To*
        // shortcut depends on: it forwards Explorer's own argument list with `%*`,
        // so anything that merged arguments here would stage the wrong names.
        assert_eq!(
            parse(&[SHELL_UPLOAD, "/tmp/a b/one.txt", "/tmp/two.txt"]),
            Action::ShellUpload(vec![
                PathBuf::from("/tmp/a b/one.txt"),
                PathBuf::from("/tmp/two.txt"),
            ])
        );
        // A file name may begin with a dash: the selection is taken verbatim.
        assert_eq!(
            parse(&[SHELL_UPLOAD, "-notes.txt", "--not-a-flag"]),
            Action::ShellUpload(vec![
                PathBuf::from("-notes.txt"),
                PathBuf::from("--not-a-flag"),
            ])
        );
    }

    #[test]
    fn shell_upload_without_a_selection_does_nothing() {
        // A right-click on nothing must not open a window, and must not record an
        // empty manifest either.
        assert_eq!(parse(&[SHELL_UPLOAD]), Action::OpenWindow);
        assert_eq!(parse(&["--shell-upload"]), Action::OpenWindow);
    }

    /// The flags the shipped file-manager definitions contain have to be the flags
    /// this parser accepts. `gui_os` writes the definitions as literal text, so a
    /// rename here would silently produce actions that open windows instead of
    /// staging selections — the exact failure A3 was.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_installed_definitions_use_flags_this_parser_knows() {
        let definitions = linscp_platform_gui_definitions();
        assert!(
            definitions.contains(SHELL_UPLOAD),
            "the Linux actions must call {SHELL_UPLOAD}: {definitions}"
        );
        assert!(
            !definitions.contains(INSTALL),
            "an action must not install actions: {definitions}"
        );
        // Whatever the definitions contain, this parser has to read it back as the
        // upload action rather than as "open a window".
        for line in definitions.lines().filter(|line| line.contains(SHELL_UPLOAD)) {
            assert!(
                line.contains("--shell-upload %F") || line.contains("--shell-upload \"$@\""),
                "unexpected action line: {line}"
            );
        }
    }

    /// The exact text `gui_os` writes for the three Linux managers, obtained by
    /// asking the module rather than by copying the format strings here.
    ///
    /// `gui_os` has its own tests for the same file, which also set `XDG_DATA_HOME`;
    /// cargo runs tests in one process, so the two must not overlap. Hold the lock in
    /// both places.
    #[cfg(target_os = "linux")]
    fn linscp_platform_gui_definitions() -> String {
        let _guard = crate::gui_os::data_home_lock();
        // The definitions are built inside `install_shell_integration`, which writes
        // them to `$XDG_DATA_HOME`; running it is the only way to read the real text.
        // A scratch data home keeps the developer's menus untouched.
        let scratch = std::env::temp_dir().join("linscp-cli-args-definitions");
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).expect("scratch data home");
        let previous = std::env::var_os("XDG_DATA_HOME");
        std::env::set_var("XDG_DATA_HOME", &scratch);
        let installed = crate::gui_os::install_shell_integration(std::path::Path::new(
            "/opt/linscp/bin/linscp-gui",
        ));
        match previous {
            Some(value) => std::env::set_var("XDG_DATA_HOME", value),
            None => std::env::remove_var("XDG_DATA_HOME"),
        }
        let mut text = String::new();
        for (_, path, _) in installed.expect("write the definitions into the scratch directory") {
            text.push_str(&std::fs::read_to_string(&path).unwrap_or_default());
        }
        let _ = std::fs::remove_dir_all(&scratch);
        text
    }

    #[test]
    fn contradictory_actions_open_the_window() {
        assert_eq!(parse(&[INSTALL, UNINSTALL]), Action::OpenWindow);
        assert_eq!(parse(&[INSTALL, SHELL_UPLOAD, "a.txt"]), Action::OpenWindow);
    }

    #[test]
    fn help_wins_because_it_cannot_do_anything() {
        assert_eq!(parse(&[HELP]), Action::Help);
        assert_eq!(parse(&[SHELL_UPLOAD, "a.txt", HELP]), Action::Help);
        assert!(USAGE.contains(INSTALL));
        assert!(USAGE.contains(UNINSTALL));
        assert!(USAGE.contains(SHELL_UPLOAD));
    }
}
