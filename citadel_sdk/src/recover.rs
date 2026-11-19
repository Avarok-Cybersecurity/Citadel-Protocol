//! Account recovery on a device that holds no bundle for the account, with its recovery phrase.
//!
//! ```no_run
//! # use citadel_sdk::prelude::*;
//! # async fn f(remote: NodeRemote<StackedRatchet>) -> Result<(), NetworkError> {
//! let seed = RecoverySeed::parse("…the 24 words the user typed…")?;
//! let phrase = RecoveryPhrase::new(seed, "example.com")?;
//! let recovery = AccountRecovery {
//!     username: "alice".into(),
//!     phrase: phrase.clone(),
//!     device_label: "Alice's laptop".into(),
//!     admission: None,
//! };
//! let recovered = remote
//!     .recover("example.com:25000", recovery, Default::default(), None)
//!     .await?;
//! // Every other device's bundle is revoked. Sign in with the phrase, to a session that may only
//! // manage credentials: set a new password, then sign in with it.
//! let conn = remote
//!     .connect_with_defaults(AuthenticationRequest::sign_in(
//!         recovered.cid,
//!         SignInFactors::recovery_phrase(phrase),
//!     ))
//!     .await?;
//! conn.set_password("a new password", SignInFactors::default()).await?;
//! # Ok(()) }
//! ```

use crate::prelude::*;
use futures::StreamExt;

/// What a recovery gives: the account this device now holds the only bundle of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoverSuccess {
    pub cid: u64,
}

#[async_trait]
pub trait AccountRecoveryExt<R: Ratchet>: Remote<R> {
    /// Recovers `recovery.username` at the server at `addr`. A wrong phrase, an unknown name, a
    /// throttled attempt and a server that cannot install the bundle all fail alike
    /// (`PqSignInFailed`); a server that asks admission refuses without a token
    /// (`PqSignInAdmissionRequired`); a server below the recovery release is refused before
    /// anything is sent (`RecoveryUnsupported`).
    async fn recover<T: std::net::ToSocketAddrs + Send>(
        &self,
        addr: T,
        recovery: AccountRecovery,
        security_settings: SessionSecuritySettings,
        server_password: Option<PreSharedKey>,
    ) -> Result<RecoverSuccess, NetworkError> {
        let remote_addr = addr.to_socket_addrs()?.next().ok_or(citadel_io::error!(
            citadel_io::ErrorCode::RemoteInvalidSocketAddr
        ))?;
        let request = RecoverAccount {
            remote_addr,
            endpoint: None,
            static_security_settings: security_settings,
            session_password: server_password.unwrap_or_default(),
            recovery,
        };
        await_recovery(self, request).await
    }

    /// As [`recover`](Self::recover), at a server reached by a WebSocket URL; the recovered
    /// account remembers the URL, as a registration's does.
    #[cfg(not(target_family = "wasm"))]
    async fn recover_at_endpoint(
        &self,
        endpoint: citadel_io::WebSocketEndpoint,
        recovery: AccountRecovery,
        security_settings: SessionSecuritySettings,
        server_password: Option<PreSharedKey>,
    ) -> Result<RecoverSuccess, NetworkError> {
        let request = RecoverAccount {
            remote_addr: endpoint.resolve().await?,
            endpoint: Some(endpoint),
            static_security_settings: security_settings,
            session_password: server_password.unwrap_or_default(),
            recovery,
        };
        await_recovery(self, request).await
    }
}

impl<R: Ratchet, T: Remote<R>> AccountRecoveryExt<R> for T {}

async fn await_recovery<R: Ratchet, Rem: Remote<R> + ?Sized>(
    remote: &Rem,
    request: RecoverAccount,
) -> Result<RecoverSuccess, NetworkError> {
    let request = NodeRequest::RecoverAccount(request);
    let mut subscription = remote.send_callback_subscription(request).await?;
    while let Some(status) = subscription.next().await {
        match status.into_result()? {
            NodeResult::RecoverOkay(RecoverOkay { cid, .. }) => return Ok(RecoverSuccess { cid }),
            NodeResult::Disconnect(err) => {
                return Err(citadel_io::error!(
                    citadel_io::ErrorCode::RemoteDisconnected,
                    err.message
                ));
            }
            evt => {
                log::warn!(target: "citadel", "Invalid NodeResult for a recovery: {evt:?}");
            }
        }
    }
    Err(citadel_io::error!(
        citadel_io::ErrorCode::RemoteKernelStreamDied,
        "recover"
    ))
}
