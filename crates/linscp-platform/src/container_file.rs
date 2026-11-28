//! Standalone encrypted container file operations; not yet used by the app.
//!
//! A stable sidecar lock coordinates cooperating processes across atomic
//! replacements. The directory must be trusted against arbitrary renames by
//! other users; neither this lock nor pathname checks defeat hostile writers
//! with directory write access. Plaintext is never written to disk.
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::{container_cipher, PlatformError};

#[cfg(unix)]
fn create_owner_file(path: &Path) -> Result<File, PlatformError> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(path)?)
}

#[cfg(windows)]
fn create_owner_file(path: &Path) -> Result<File, PlatformError> {
    crate::windows::create_container_private_file(path)
}

#[cfg(not(any(unix, windows)))]
fn create_owner_file(_path: &Path) -> Result<File, PlatformError> {
    Err(PlatformError::Unsupported("Secure container files are not supported on this platform".into()))
}

fn invalid(message: &str) -> PlatformError {
    PlatformError::Io(std::io::Error::other(message))
}

/// Exclusive access to a container. Keep the guard while reading and updating.
/// The lock file is persistent and must not be unlinked while clients may run.
pub struct ContainerFile {
    path: PathBuf,
    parent: PathBuf,
    _lock: File,
}

impl ContainerFile {
    /// Acquire the stable sidecar lock without altering or creating the parent.
    pub fn try_acquire(path: &Path) -> Result<Self, PlatformError> {
        let name = path.file_name().ok_or_else(|| invalid("Container requires a file name"))?;
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let parent = std::fs::canonicalize(parent)?;
        if !parent.is_dir() { return Err(invalid("Container parent is not a directory")); }
        let path = parent.join(name);
        let mut lock_name = name.to_os_string();
        lock_name.push(".lock");
        let lock_path = parent.join(lock_name);
        let lock = match create_owner_file(&lock_path) {
            Ok(file) => file,
            Err(PlatformError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => crate::open_private_file_no_follow(&lock_path)?,
            Err(e) => return Err(e),
        };
        lock.try_lock().map_err(|e| invalid(&format!("Cannot acquire container lock: {e}")))?;
        Ok(Self { path, parent, _lock: lock })
    }

    /// Read and authenticate an existing file, with a hard limit before decryption.
    pub fn open(&self, password: &str) -> Result<Zeroizing<Vec<u8>>, PlatformError> {
        let file = crate::open_private_file_no_follow(&self.path)?;
        let max = container_cipher::MAX_PLAINTEXT + 8 + 16 + 12 + 16;
        let mut bytes = Vec::new();
        file.take(max as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > max { return Err(invalid("Application vault exceeds size limit")); }
        container_cipher::open(&bytes, password)
    }

    /// Create a new container without replacing an existing file.
    pub fn create(&self, password: &str, value: &[u8]) -> Result<(), PlatformError> {
        let encrypted = container_cipher::seal(value, password)?;
        self.publish(&encrypted, false)
    }

    /// Authenticate the existing container before replacing it; a wrong password
    /// or damaged file cannot be silently overwritten by this operation.
    pub fn save(&self, password: &str, value: &[u8]) -> Result<(), PlatformError> {
        let _existing = self.open(password)?;
        let encrypted = container_cipher::seal(value, password)?;
        self.publish(&encrypted, true)
    }

    fn publish(&self, encrypted: &[u8], replace: bool) -> Result<(), PlatformError> {
        let mut random = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut random);
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let temp = self.parent.join(format!(".linscp-container-{suffix}.tmp"));
        let mut file = create_owner_file(&temp)?;
        let result = (|| -> Result<(), PlatformError> {
            file.write_all(encrypted)?;
            file.sync_all()?;
            drop(file);
            if replace { crate::atomic_replace_file(&temp, &self.path)?; }
            else { crate::publish_no_replace(&temp, &self.path)?; }
            // Failure here means publication may have succeeded, but durable
            // directory metadata could not be confirmed; report it explicitly.
            crate::sync_directory(&self.parent)?;
            Ok(())
        })();
        if result.is_err() { let _ = std::fs::remove_file(&temp); }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_save_lock_and_failure_preserve_data() {
        let dir = std::env::temp_dir().join(format!("linscp-container-{}-{}", std::process::id(), rand::random::<u64>()));
        std::fs::create_dir(&dir).unwrap();
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let path = dir.join("vault.dat");
        let container = ContainerFile::try_acquire(&path).unwrap();
        assert!(ContainerFile::try_acquire(&path).is_err());
        container.create("test password", b"secret").unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(!before.windows(6).any(|w| w == b"secret"));
        assert!(container.create("test password", b"replacement").is_err());
        assert!(container.save("wrong password", b"replacement").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        container.save("test password", b"updated").unwrap();
        assert_eq!(container.open("test password").unwrap().as_slice(), b"updated");
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o755);
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        drop(container);
        assert_eq!(ContainerFile::try_acquire(&path).unwrap().open("test password").unwrap().as_slice(), b"updated");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn damaged_file_is_not_overwritten() {
        let dir = std::env::temp_dir().join(format!("linscp-container-damage-{}-{}", std::process::id(), rand::random::<u64>()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("vault.dat");
        let container = ContainerFile::try_acquire(&path).unwrap();
        container.create("test password", b"secret").unwrap();
        let mut damaged = std::fs::read(&path).unwrap();
        *damaged.last_mut().unwrap() ^= 1;
        std::fs::write(&path, &damaged).unwrap();
        assert!(container.save("test password", b"replacement").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), damaged);
        drop(container);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
