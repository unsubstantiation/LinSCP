//! Portable async protocol traits and fail-closed SSH host-key verification
//! policy shared across Linux, Windows, and Android.

use async_trait::async_trait;
use linscp_types::{FileEntry, HostKeyChallenge, ProtocolScheme};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtoError {
    #[error("SSH host key policy rejects wildcard or unverified trust '{0}'")]
    WeakHostKeyPolicy(String),
    #[error("Host key verification required for {role} {host}:{port} ({state})")]
    HostKeyChallengeRequired {
        role: String,
        state: String,
        host: String,
        port: u16,
        fingerprint: String,
    },
    #[error("Operation '{0}' is not supported by protocol {1:?}")]
    UnsupportedCapability(&'static str, ProtocolScheme),
    #[error("{0}")]
    Transport(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolCapabilities {
    pub pty_shell: bool,
    pub remote_exec: bool,
    pub symlinks: bool,
    pub posix_permissions: bool,
    pub server_checksum: bool,
    pub object_versioning: bool,
}

pub const fn capabilities_for(scheme: ProtocolScheme) -> ProtocolCapabilities {
    match scheme {
        ProtocolScheme::Sftp | ProtocolScheme::Ssh => ProtocolCapabilities {
            pty_shell: true,
            remote_exec: true,
            symlinks: true,
            posix_permissions: true,
            server_checksum: true,
            object_versioning: false,
        },
        ProtocolScheme::Scp => ProtocolCapabilities {
            pty_shell: true,
            remote_exec: true,
            symlinks: false,
            posix_permissions: true,
            server_checksum: true,
            object_versioning: false,
        },
        ProtocolScheme::Ftp | ProtocolScheme::Ftps | ProtocolScheme::Ftpes => ProtocolCapabilities {
            pty_shell: false,
            remote_exec: false,
            symlinks: false,
            posix_permissions: true,
            server_checksum: true,
            object_versioning: false,
        },
        ProtocolScheme::Dav
        | ProtocolScheme::Davs
        | ProtocolScheme::Webdav
        | ProtocolScheme::Webdavs => ProtocolCapabilities {
            pty_shell: false,
            remote_exec: false,
            symlinks: false,
            posix_permissions: false,
            server_checksum: false,
            object_versioning: false,
        },
        ProtocolScheme::S3 => ProtocolCapabilities {
            pty_shell: false,
            remote_exec: false,
            symlinks: false,
            posix_permissions: false,
            server_checksum: true,
            object_versioning: true,
        },
        ProtocolScheme::Local => ProtocolCapabilities {
            pty_shell: false,
            remote_exec: false,
            symlinks: true,
            posix_permissions: true,
            server_checksum: true,
            object_versioning: false,
        },
    }
}

/// Evaluates an observed server host-key fingerprint against a pinned policy
/// (`-hostkey` or `known_hosts` entry). Wildcard `"*"` and `"acceptnew"` are
/// unconditionally rejected so connections always fail closed.
pub fn evaluate_host_key(
    tab_id: u64,
    role: &str,
    host: &str,
    port: u16,
    pinned: Option<&str>,
    known_hosts_match: Option<&str>,
    observed_fingerprint: &str,
) -> Result<(), Result<HostKeyChallenge, ProtoError>> {
    if let Some(pin) = pinned.map(str::trim).filter(|s| !s.is_empty()) {
        let lower = pin.to_ascii_lowercase();
        if lower == "*" || lower == "acceptnew" || lower == "any" || lower == "none" {
            return Err(Err(ProtoError::WeakHostKeyPolicy(pin.to_string())));
        }
        if pin == observed_fingerprint {
            return Ok(());
        }
        return Err(Ok(HostKeyChallenge {
            tab_id,
            role: role.to_string(),
            state: "changed".to_string(),
            host: host.to_string(),
            port,
            fingerprint: observed_fingerprint.to_string(),
        }));
    }

    match known_hosts_match {
        Some(existing) if existing == observed_fingerprint => Ok(()),
        Some(_) => Err(Ok(HostKeyChallenge {
            tab_id,
            role: role.to_string(),
            state: "changed".to_string(),
            host: host.to_string(),
            port,
            fingerprint: observed_fingerprint.to_string(),
        })),
        None => Err(Ok(HostKeyChallenge {
            tab_id,
            role: role.to_string(),
            state: "unknown".to_string(),
            host: host.to_string(),
            port,
            fingerprint: observed_fingerprint.to_string(),
        })),
    }
}

/// Async remote filesystem & command session implemented by each pure-Rust
/// protocol backend (`russh`, `suppaftp`, `reqwest` WebDAV, SigV4 S3).
#[async_trait]
pub trait RemoteSession: Send + Sync {
    fn scheme(&self) -> ProtocolScheme;
    async fn pwd(&self) -> Result<String, ProtoError>;
    async fn list_dir(&self, remote_path: &str) -> Result<Vec<FileEntry>, ProtoError>;
    async fn mkdir(&self, remote_path: &str) -> Result<(), ProtoError>;
    async fn remove_file(&self, remote_path: &str) -> Result<(), ProtoError>;
    async fn remove_dir(&self, remote_path: &str) -> Result<(), ProtoError>;
    async fn rename(&self, from: &str, to: &str) -> Result<(), ProtoError>;
    async fn chmod(&self, remote_path: &str, mode: u32) -> Result<(), ProtoError>;
    async fn checksum(&self, algorithm: &str, remote_path: &str) -> Result<String, ProtoError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_key_policy_rejects_wildcard_and_acceptnew() {
        for forbidden in ["*", "acceptnew", "AcceptNew", "none"] {
            let outcome = evaluate_host_key(
                1,
                "destination",
                "example.com",
                22,
                Some(forbidden),
                None,
                "SHA256:abc",
            );
            assert_eq!(
                outcome,
                Err(Err(ProtoError::WeakHostKeyPolicy(forbidden.to_string())))
            );
        }
    }

    #[test]
    fn host_key_policy_distinguishes_tunnel_and_destination_challenges() {
        let tunnel = evaluate_host_key(
            7,
            "tunnel",
            "bastion.example.com",
            2222,
            None,
            None,
            "SHA256:bastionKey",
        )
        .expect_err("untrusted bastion must challenge")
        .expect("challenge payload");
        assert_eq!(tunnel.role, "tunnel");
        assert_eq!(tunnel.state, "unknown");
        assert_eq!(tunnel.port, 2222);

        let mismatched = evaluate_host_key(
            7,
            "destination",
            "app.internal",
            22,
            Some("SHA256:old"),
            None,
            "SHA256:new",
        )
        .expect_err("changed host key must challenge")
        .expect("challenge payload");
        assert_eq!(mismatched.role, "destination");
        assert_eq!(mismatched.state, "changed");
    }
}
