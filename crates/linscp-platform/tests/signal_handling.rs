//! Signal dispositions are process-wide. The parent launches this test binary
//! again so the signal test cannot alter the rest of the test runner.
#![cfg(unix)]

use std::os::unix::process::ExitStatusExt;
use std::process::Command;

use linscp_platform::terminal::{
    clear_interrupted, ensure_default_sigint, install_cli_signal_handlers,
    is_interrupted, restore_default_signal_handlers, take_window_resized,
};

fn signal_disposition(signal: libc::c_int) -> libc::sighandler_t {
    // SAFETY: sigaction writes a valid signal action into a properly allocated
    // structure. No process-wide disposition is changed by this query.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        assert_eq!(libc::sigaction(signal, std::ptr::null(), &mut action), 0);
        action.sa_sigaction
    }
}

#[test]
fn posix_watch_signal_handlers_are_isolated_and_restore_defaults() {
    const CHILD_ENV: &str = "LINSCP_TEST_SIGNAL_CHILD";
    if std::env::var_os(CHILD_ENV).is_some() {
        // Simulate a supervisor that ignores termination signals before exec.
        // SAFETY: These valid signals are configured only in the child process.
        unsafe {
            let mut ignored: libc::sigaction = std::mem::zeroed();
            ignored.sa_sigaction = libc::SIG_IGN;
            libc::sigemptyset(&mut ignored.sa_mask);
            assert_eq!(libc::sigaction(libc::SIGINT, &ignored, std::ptr::null_mut()), 0);
            assert_eq!(libc::sigaction(libc::SIGTERM, &ignored, std::ptr::null_mut()), 0);
        }
        ensure_default_sigint();
        assert_eq!(signal_disposition(libc::SIGINT), libc::SIG_DFL);
        assert_eq!(signal_disposition(libc::SIGTERM), libc::SIG_DFL);
        install_cli_signal_handlers();
        assert!(!is_interrupted());
        for signal in [libc::SIGINT, libc::SIGTERM] {
            // SAFETY: raises a signal on this isolated child after installation.
            assert_eq!(unsafe { libc::raise(signal) }, 0);
            assert!(is_interrupted());
            clear_interrupted();
            assert!(!is_interrupted());
        }
        let _ = take_window_resized();
        assert_eq!(unsafe { libc::raise(libc::SIGWINCH) }, 0);
        assert!(take_window_resized());
        assert!(!take_window_resized());
        restore_default_signal_handlers();
        assert_eq!(signal_disposition(libc::SIGINT), libc::SIG_DFL);
        assert_eq!(signal_disposition(libc::SIGTERM), libc::SIG_DFL);
        assert!(!is_interrupted());
        // The parent checks that the restored handler really terminates this
        // child, rather than trusting the disposition query alone.
        unsafe { libc::raise(libc::SIGTERM) };
        panic!("restored SIGTERM unexpectedly returned");
    }

    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "posix_watch_signal_handlers_are_isolated_and_restore_defaults", "--nocapture"])
        .env(CHILD_ENV, "1")
        .output().expect("launch isolated signal test");
    assert_eq!(child.status.signal(), Some(libc::SIGTERM),
        "child did not complete the signal checks: stdout={} stderr={}",
        String::from_utf8_lossy(&child.stdout), String::from_utf8_lossy(&child.stderr));
}
