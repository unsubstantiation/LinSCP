//! Optional SSH GSSAPI (`gssapi-with-mic`) capability gate.
//!
//! Default builds keep zero native C/Kerberos dependencies across Linux,
//! Windows, and Android and fail closed whenever GSSAPI authentication or
//! key exchange is requested. Enabling the `gssapi` feature exposes the
//! `GssapiTokenProvider` trait bridged directly to `russh`'s RFC 4462
//! `gssapi-with-mic` state machine.

use crate::ProtoError;

/// Kerberos V5 GSSAPI mechanism OID (`1.2.840.113554.1.2.2`) in DER TLV form.
pub const KRB5_MECHANISM_OID_DER: &[u8] =
    &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];

/// Whether this `linscp-proto` build compiled with `gssapi-with-mic` support.
pub const fn is_gssapi_supported() -> bool {
    cfg!(feature = "gssapi")
}

/// Whether RFC 4462 GSSAPI key exchange is implemented by the active transport.
pub const fn is_gssapi_kex_supported() -> bool {
    false
}

/// Fails closed when a session explicitly requests GSSAPI authentication on a
/// build without the `gssapi` feature enabled, or requests GSSAPI KEX.
pub fn ensure_gssapi_available(require_kex: bool) -> Result<(), ProtoError> {
    if require_kex && !is_gssapi_kex_supported() {
        return Err(ProtoError::Transport(
            "This build's libssh does not support GSSAPI key exchange, so AuthGSSAPIKEX cannot be honored."
                .to_string(),
        ));
    }
    if !is_gssapi_supported() {
        return Err(ProtoError::Transport(
            "GSSAPI authentication was requested, but this build was compiled without the 'gssapi' feature."
                .to_string(),
        ));
    }
    Ok(())
}

/// Pluggable GSSAPI / SSPI security-context provider for `gssapi-with-mic`.
#[async_trait::async_trait]
pub trait GssapiTokenProvider: Send + Sync {
    /// DER-encoded mechanism OIDs offered by this provider (defaults to KRB5).
    fn mechanism_oids(&self) -> Vec<Vec<u8>> {
        vec![KRB5_MECHANISM_OID_DER.to_vec()]
    }

    /// Advances the GSSAPI security context one step.
    /// Returns `Ok(GssapiExchangeStep::Continue(token))` while handshaking, or
    /// `Ok(GssapiExchangeStep::Complete { token, mic })` once established.
    async fn step(
        &mut self,
        selected_mechanism: Option<Vec<u8>>,
        input_token: Option<Vec<u8>>,
        mic_data: Vec<u8>,
    ) -> Result<GssapiExchangeStep, ProtoError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GssapiExchangeStep {
    Continue(Vec<u8>),
    Complete {
        token: Option<Vec<u8>>,
        mic: Option<Vec<u8>>,
    },
}

#[cfg(feature = "gssapi")]
pub(crate) mod russh_bridge {
    use super::{GssapiExchangeStep, GssapiTokenProvider};
    use crate::ProtoError;

    #[derive(Debug, thiserror::Error)]
    pub enum RusshGssError {
        #[error(transparent)]
        Send(#[from] russh::SendError),
        #[error("{0}")]
        Proto(#[from] ProtoError),
    }

    pub struct ProviderAdapter<'a> {
        pub provider: &'a mut dyn GssapiTokenProvider,
    }

    impl russh::GssapiAuthenticator for ProviderAdapter<'_> {
        type Error = RusshGssError;

        async fn gssapi_step(
            &mut self,
            selected_mechanism: Option<Vec<u8>>,
            input_token: Option<Vec<u8>>,
            mic_data: Vec<u8>,
        ) -> Result<russh::GssapiStep, Self::Error> {
            match self
                .provider
                .step(selected_mechanism, input_token, mic_data)
                .await?
            {
                GssapiExchangeStep::Continue(token) => {
                    Ok(russh::GssapiStep::Continue { token })
                }
                GssapiExchangeStep::Complete { token, mic } => {
                    Ok(russh::GssapiStep::Complete { token, mic })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gssapi_kex_always_fails_closed() {
        assert!(!is_gssapi_kex_supported());
        assert!(ensure_gssapi_available(true).is_err());
    }
}
