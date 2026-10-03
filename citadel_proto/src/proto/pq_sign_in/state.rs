//! What a session remembers between the messages of a post-quantum sign-in.

use super::manage::ServerManagement;
use super::security_key::SecurityKeyPrf;
use citadel_io::time::Instant;
use citadel_types::auth::SessionScope;
use citadel_types::crypto::SecBuffer;
use citadel_user::auth::pq::client::{ClientLogin, ClientRegistration};
use citadel_user::auth::pq::messages::LoginStart;
use citadel_user::auth::pq::recovery::RecoveryCode;
use citadel_user::auth::pq::server::{PendingLogin, PendingRegistration};
use zeroize::Zeroizing;

/// The factors a client offers for one sign-in.
pub(crate) struct OfferedFactors {
    pub password: Option<SecBuffer>,
    pub security_key: Option<SecurityKeyPrf>,
    pub recovery_code: Option<RecoveryCode>,
}

/// Kept in the connect state.
pub(crate) struct PqConnectState {
    /// Both sides: what the session may do. `Recovery` after a recovery-code sign-in.
    pub scope: SessionScope,
    /// Both sides: until when a sign-in may wait for a security-key touch.
    pub presence_until: Option<Instant>,
    /// Server: a management exchange in progress.
    pub manage: Option<ServerManagement>,
    /// Client: the factors offered, until `AUTH_START` is sent.
    pub offered: Option<OfferedFactors>,
    /// Client: between `AUTH_START` and `AUTH_CHALLENGE`, with the key to ask if challenged.
    pub client: Option<(LoginStart, ClientLogin, Option<SecurityKeyPrf>)>,
    /// Client: from STAGE0 until SUCCESS, when it joins the session's pre-shared keys.
    pub session_key: Option<Zeroizing<[u8; 32]>>,
    /// Server: between `AUTH_CHALLENGE` and STAGE0.
    pub server: Option<ServerPending>,
}

impl Default for PqConnectState {
    fn default() -> Self {
        Self {
            scope: SessionScope::Full,
            presence_until: None,
            manage: None,
            offered: None,
            client: None,
            session_key: None,
            server: None,
        }
    }
}

/// What the server expects in STAGE0 after the challenge it issued.
pub(crate) enum ServerPending {
    Factors(PendingLogin),
    /// A legacy account. `Some` when the login also offered to upgrade it.
    Legacy(Option<PendingRegistration>),
}

/// Kept in the register state.
#[derive(Default)]
pub(crate) struct PqRegisterState {
    /// Client: the password, until `PQ_START` is sent. The server never sees it.
    pub password: Option<SecBuffer>,
    /// Client: between `PQ_START` and `PQ_REPLY`.
    pub client: Option<ClientRegistration>,
    /// Client: whether STAGE2 enrolled post-quantum factors, so the account is kept as one.
    pub registered: bool,
    /// Client: the new account's recovery codes, for `RegisterOkay`.
    pub recovery_codes: Vec<String>,
    /// Server: between `PQ_REPLY` and STAGE2.
    pub server: Option<PendingRegistration>,
}
