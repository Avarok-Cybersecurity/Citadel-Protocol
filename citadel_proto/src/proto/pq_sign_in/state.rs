//! What a session remembers between the messages of a post-quantum sign-in.

use citadel_types::crypto::SecBuffer;
use citadel_user::auth::pq::client::{ClientLogin, ClientRegistration};
use citadel_user::auth::pq::messages::LoginStart;
use citadel_user::auth::pq::server::{PendingLogin, PendingRegistration};
use zeroize::Zeroizing;

/// The factors a client offers for one sign-in.
pub(crate) struct OfferedFactors {
    pub password: Option<SecBuffer>,
}

/// Kept in the connect state.
#[derive(Default)]
pub(crate) struct PqConnectState {
    /// Client: the factors offered, until `AUTH_START` is sent.
    pub offered: Option<OfferedFactors>,
    /// Client: between `AUTH_START` and `AUTH_CHALLENGE`.
    pub client: Option<(LoginStart, ClientLogin)>,
    /// Client: from STAGE0 until SUCCESS, when it joins the session's pre-shared keys.
    pub session_key: Option<Zeroizing<[u8; 32]>>,
    /// Server: between `AUTH_CHALLENGE` and STAGE0.
    pub server: Option<ServerPending>,
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
    /// Server: between `PQ_REPLY` and STAGE2.
    pub server: Option<PendingRegistration>,
}
