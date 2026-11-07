//! Runs the one-shot command-line actions of the native window binary.
//!
//! `linscp-platform::cli_args` decides *what* was asked for; this module does it,
//! because the pieces it needs — the pending-manifest writer and the caller's
//! configuration directory — live here. Keeping the execution out of `main.rs` is
//! deliberate: `main.rs` opens a window and cannot be unit tested, while these are
//! plain functions a test can call.
//!
//! Nothing here transfers a file. `--shell-upload` records the selection and exits;
//! the running window reads it back from disk and asks the user what to do with it,
//! which is the same contract the Android share sheet uses.

use std::path::{Path, PathBuf};

use crate::ops;

/// What an action printed and what exit status it decided on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionOutcome {
    /// 0 for a completed action, non-zero for a refusal worth a failing exit code.
    pub exit_code: i32,
    /// Lines to write to standard output, in order.
    pub stdout: Vec<String>,
    /// Lines to write to standard error, in order.
    pub stderr: Vec<String>,
}

impl ActionOutcome {
    fn ok(lines: Vec<String>) -> Self {
        Self { exit_code: 0, stdout: lines, stderr: Vec::new() }
    }

    fn failed(message: String) -> Self {
        Self { exit_code: 1, stdout: Vec::new(), stderr: vec![message] }
    }

    /// The whole outcome as one string, as a person would see it. Tests compare
    /// this; the hosts write `stdout`/`stderr` to their own streams.
    pub fn to_text(&self) -> String {
        let mut text = String::new();
        for line in &self.stdout {
            text.push_str(line);
            text.push('\n');
        }
        for line in &self.stderr {
            text.push_str(line);
            text.push('\n');
        }
        text
    }
}

/// Describes one install/uninstall target the way the caller reports it.
fn describe_targets(targets: &[(String, String, String)]) -> Vec<String> {
    if targets.is_empty() {
        return vec!["Nothing to do: no file manager on this account can be configured.".to_string()];
    }
    targets
        .iter()
        .map(|(manager, path, outcome)| format!("{manager}: {outcome} ({path})"))
        .collect()
}

/// Writes (or rewrites) the per-user file-manager actions for `launcher`.
///
/// `launcher` is the path the definitions run; the caller passes its own
/// executable so a moved or renamed install keeps working after a reinstall.
pub fn install_shell_integration(launcher: &Path) -> ActionOutcome {
    match linscp_platform::gui_os::install_shell_integration(launcher) {
        Ok(targets) => ActionOutcome::ok(describe_targets(&targets)),
        Err(error) => ActionOutcome::failed(error),
    }
}

/// Removes exactly what [`install_shell_integration`] wrote.
pub fn uninstall_shell_integration() -> ActionOutcome {
    match linscp_platform::gui_os::uninstall_shell_integration() {
        Ok(targets) => ActionOutcome::ok(describe_targets(&targets)),
        Err(error) => ActionOutcome::failed(error),
    }
}

/// Records `files` as a pending upload for a running window and reports the id.
///
/// The manifest is the hand-off: this process may exit before the window reads it,
/// so nothing is kept in memory. A refusal here is the user's answer to "why did
/// nothing happen when I clicked Upload with LinSCP", so it is printed verbatim.
pub fn shell_upload(config_root: &Path, files: &[PathBuf]) -> ActionOutcome {
    if files.is_empty() {
        return ActionOutcome::failed(
            "Nothing to stage: the selection was empty.".to_string(),
        );
    }
    match ops::record_shell_upload_manifest(config_root, files) {
        Ok(manifest) => {
            let id = manifest
                .get("id")
                .and_then(|value| value.as_str())
                .unwrap_or("")
                .to_string();
            let count = files.len();
            let noun = if count == 1 { "item" } else { "items" };
            ActionOutcome::ok(vec![
                format!("Staged {count} {noun} for upload (selection {id})."),
                "Open LinSCP to confirm the upload; nothing is transferred until you do.".to_string(),
            ])
        }
        Err(error) => ActionOutcome::failed(error),
    }
}

/// Runs the action without assuming anything about the current directory.
///
/// `--shell-upload` may be given relative paths (a file manager usually passes
/// absolute ones, but a script need not), and `record_shell_upload_manifest`
/// resolves them against the process's working directory — which, for a program
/// launched from a desktop icon, is whatever the file manager felt like. This
/// wrapper is the one the hosts call so the behaviour is defined and testable:
/// relative paths resolve against `cwd`.
pub fn shell_upload_from(
    config_root: &Path,
    files: &[PathBuf],
    cwd: &Path,
) -> ActionOutcome {
    let resolved: Vec<PathBuf> = files
        .iter()
        .map(|file| if file.is_absolute() { file.clone() } else { cwd.join(file) })
        .collect();
    shell_upload(config_root, &resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "linscp-cli-actions-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch config directory");
        root
    }

    #[test]
    fn a_selection_becomes_a_pending_manifest_the_window_can_read() {
        let config = scratch("upload");
        let file = config.join("report.pdf");
        std::fs::write(&file, b"payload").expect("stage a file to select");

        let outcome = shell_upload(&config, std::slice::from_ref(&file));
        assert_eq!(outcome.exit_code, 0, "{}", outcome.to_text());
        assert!(
            outcome.to_text().contains("Open LinSCP to confirm"),
            "{}",
            outcome.to_text()
        );

        // The window reads pending selections from disk per request, so a manifest
        // written by a process that already exited has to be visible there.
        let pending = ops::list_shell_manifests(&config);
        assert_eq!(pending.len(), 1, "one selection is pending: {pending:?}");
        let items = pending[0]["items"].as_array().expect("items array");
        assert_eq!(items.len(), 1, "{:?}", pending[0]);
        assert_eq!(
            items[0]["name"].as_str(),
            Some("report.pdf"),
            "the window shows the file by name: {:?}",
            pending[0]
        );

        let _ = std::fs::remove_dir_all(&config);
    }

    #[test]
    fn a_relative_selection_resolves_against_the_directory_it_was_named_in() {
        let config = scratch("relative");
        let workdir = config.join("work");
        std::fs::create_dir_all(&workdir).expect("scratch working directory");
        std::fs::write(workdir.join("report.pdf"), b"payload").expect("stage a file to select");

        // A file manager can pass "report.pdf"; the manifest has to name the file
        // that exists, not one relative to whatever directory this process started in.
        let outcome = shell_upload_from(&config, &[PathBuf::from("report.pdf")], &workdir);
        assert_eq!(outcome.exit_code, 0, "{}", outcome.to_text());
        let pending = ops::list_shell_manifests(&config);
        assert_eq!(pending.len(), 1);
        let path = pending[0]["items"][0]["path"].as_str().expect("path");
        assert!(
            Path::new(path).is_absolute(),
            "the manifest names an absolute path: {path}"
        );
        assert!(Path::new(path).exists(), "{path}");

        let _ = std::fs::remove_dir_all(&config);
    }

    #[test]
    fn an_empty_selection_and_a_missing_file_are_refused_out_loud() {
        let config = scratch("refusals");
        let empty = shell_upload(&config, &[]);
        assert_ne!(empty.exit_code, 0);
        assert!(empty.to_text().contains("selection was empty"), "{}", empty.to_text());

        let missing = shell_upload(&config, &[config.join("not-there.txt")]);
        assert_ne!(missing.exit_code, 0, "a vanished selection must fail the action");
        assert!(
            !missing.stderr.is_empty(),
            "the reason has to reach stderr, not vanish"
        );
        assert!(
            ops::list_shell_manifests(&config).is_empty(),
            "a refused selection leaves no pending manifest behind"
        );

        let _ = std::fs::remove_dir_all(&config);
    }

    /// An install that cannot be carried out has to say so, and must not touch the
    /// user's menus first. The refusal paths are the ones reachable without a
    /// desktop, so this test writes nothing anywhere.
    ///
    /// The body is platform-specific, so the annotations are too: a test whose body
    /// compiles away would otherwise trip `unused_variables` for the `#[test]`'s own
    /// machinery.
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn an_install_that_cannot_be_carried_out_is_reported_not_swallowed() {
        #[cfg(target_os = "linux")]
        {
            // A quote cannot be carried into the generated shell script, so the
            // install refuses before it writes a single definition.
            let outcome = install_shell_integration(Path::new("/opt/lin'scp/linscp-gui"));
            assert_ne!(outcome.exit_code, 0, "{}", outcome.to_text());
            assert!(outcome.to_text().contains("quote"), "{}", outcome.to_text());
            assert!(outcome.stdout.is_empty(), "{}", outcome.to_text());
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            // Android and macOS have no file manager reading these definitions.
            let outcome = install_shell_integration(Path::new("/opt/linscp/linscp-gui"));
            assert_ne!(outcome.exit_code, 0, "{}", outcome.to_text());
            assert!(
                outcome.to_text().contains("Linux and Windows only"),
                "{}",
                outcome.to_text()
            );
        }
        // Not exercised on Windows: the only way to reach a refusal there without
        // rewriting the runner's own Send To menu is to install for real, which the
        // Windows CI job does instead.
    }
}
