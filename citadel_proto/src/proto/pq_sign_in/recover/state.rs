//! What a session remembers between the recovery lane's messages.

use citadel_user::auth::pq::admission::AdmissionToken;
use citadel_user::auth::pq::client::ClientLogin;
use citadel_user::auth::pq::messages::RecoverStart;
use citadel_user::auth::pq::phrase::RecoveryPhrase;
use citadel_user::auth::pq::server::PendingLogin;

/// What a device recovering an account brings to the exchange.
pub(crate) struct RecoverAsk {
    pub username: String,
    pub phrase: RecoveryPhrase,
    pub device_label: String,
    pub admission: Option<AdmissionToken>,
}

/// Client: a `RECOVER_START` sent, waiting for its challenge.
pub(crate) struct ClientRecover {
    pub start: RecoverStart,
    pub login: ClientLogin,
    pub binding: [u8; 32],
}

/// Server: a challenge issued, waiting for its proof.
pub(crate) struct ServerRecover {
    pub pending: PendingLogin,
    pub username: String,
}

/// Kept in the register state, beside a registration's own.
#[derive(Default)]
pub(crate) struct RecoverState {
    /// Client: what to recover with, until `RECOVER_START` is sent.
    pub ask: Option<RecoverAsk>,
    /// Client: the STAGE0 payload it sent, for the channel binding.
    pub sent_stage0: Option<Vec<u8>>,
    /// Client: between `RECOVER_START` and `RECOVER_CHALLENGE`.
    pub proving: Option<ClientRecover>,
    /// Client: from `RECOVER_PROOF` until `RECOVER_DONE`.
    pub username: Option<String>,
    /// Server: the binding of this session's key exchange, from STAGE0.
    pub binding: Option<[u8; 32]>,
    /// Server: between `RECOVER_CHALLENGE` and `RECOVER_PROOF`.
    pub pending: Option<ServerRecover>,
}

impl RecoverState {
    /// Whether this session is recovering rather than registering, on either side: a
    /// registration's STAGE2 and SUCCESS are refused while it is.
    pub fn in_progress(&self) -> bool {
        self.ask.is_some()
            || self.proving.is_some()
            || self.username.is_some()
            || self.pending.is_some()
    }
}
