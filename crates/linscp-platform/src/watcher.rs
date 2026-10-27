//! Cross-platform local directory and file change watcher (`inotify` on Linux,
//! `ReadDirectoryChangesW` on Windows, `PollWatcher` on Android) used by
//! `keepuptodate` and `edit -monitor`.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::sync::Mutex;
use std::time::Duration;

use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};

use crate::PlatformError;

pub struct LocalDirWatcher {
    _watcher: RecommendedWatcher,
    rx: Mutex<Receiver<Vec<PathBuf>>>,
}

impl LocalDirWatcher {
    pub fn watch(path: &Path, recursive: bool) -> Result<Self, PlatformError> {
        let (tx, rx) = mpsc::channel();
        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Some(paths) = res.ok().map(|e| e.paths).filter(|p| !p.is_empty()) {
                    let _ = tx.send(paths);
                }
            },
            Config::default().with_poll_interval(Duration::from_millis(250)),
        )
        .map_err(|err| PlatformError::Watch(err.to_string()))?;

        let mode = if recursive {
            RecursiveMode::Recursive
        } else {
            RecursiveMode::NonRecursive
        };
        watcher
            .watch(path, mode)
            .map_err(|err| PlatformError::Watch(err.to_string()))?;

        Ok(Self {
            _watcher: watcher,
            rx: Mutex::new(rx),
        })
    }

    /// Blocks up to `timeout` waiting for at least one local filesystem event.
    pub fn recv_timeout(&self, timeout: Duration) -> Option<Vec<PathBuf>> {
        let guard = self.rx.lock().expect("watcher receiver lock");
        let mut batch = guard.recv_timeout(timeout).ok()?;
        while let Ok(more) = guard.try_recv() {
            batch.extend(more);
        }
        batch.sort();
        batch.dedup();
        Some(batch)
    }

    /// Drains any queued change paths without blocking.
    pub fn drain_changed_paths(&self) -> Vec<PathBuf> {
        let guard = self.rx.lock().expect("watcher receiver lock");
        let mut batch = Vec::new();
        while let Ok(more) = guard.try_recv() {
            batch.extend(more);
        }
        batch.sort();
        batch.dedup();
        batch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_watcher_observes_newly_written_file() {
        let dir = std::env::temp_dir().join(format!(
            "linscp-watch-test-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let watcher = LocalDirWatcher::watch(&dir, false).expect("start watcher");
        let sample = dir.join("hello.txt");
        std::fs::write(&sample, b"changed").unwrap();
        let observed = watcher.recv_timeout(Duration::from_secs(5));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(observed.is_some(), "expected filesystem change notification");
    }
}
