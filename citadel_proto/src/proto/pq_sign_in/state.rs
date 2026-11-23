//! What a session remembers between the messages of a post-quantum sign-in.

use super::manage::ServerManagement;
use super::security_key::SecurityKeyPrf;
use citadel_io::time::Instant;
use citadel_types::auth::SessionScope;
use citadel_types::crypto::SecBuffer;
use citadel_user::auth::pq::admission::AdmissionToken;
use citadel_user::auth::pq::client::{ClientLogin, ClientRegistration};
use citadel_user::auth::pq::messages::LoginStart;
use citadel_user::auth::pq::phrase::RecoveryPhrase;
use citadel_user::auth::pq::resume::ResumeCredential;
use citadel_user::auth::pq::server::{PendingLogin, PendingRegistration};
use citadel_user::auth::pq::throttle::Attempt;
use zeroize::Zeroizing;

/// The factors a client offers for one sign-in.
pub(crate) struct OfferedFactors {
    pub password: Option<SecBuffer>,
    pub security_key: Option<SecurityKeyPrf>,
    pub recovery_phrase: Option<RecoveryPhrase>,
    pub admission: Option<AdmissionToken>,
    pub resume: Option<ResumeCredential>,
    pub resume_lifetime_s: Option<u64>,
}

/// Kept in the connect state.
pub(crate) struct PqConnectState {
    /// Both sides: what the session may do. `Recovery` (the recovery console) after a sign-in
    /// with the recovery phrase.
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
    /// Server: what the sign-in in flight counts as against the throttle, from `AUTH_START`
    /// until its proof is checked.
    pub attempt: Option<Attempt>,
    /// Client: the resume credential this sign-in asks for or was told it may ask for (see
    /// `pq_sign_in::resume`).
    pub resume: super::resume::ClientResume,
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
            attempt: None,
            resume: Default::default(),
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
    /// Client: the domain the new account's recovery phrase is bound to, until `PQ_REPLY`.
    pub recovery_domain: Option<String>,
    /// Client: the new account's recovery phrase, for `RegisterOkay`.
    pub recovery_phrase: Option<Vec<String>>,
    /// Server: between `PQ_REPLY` and STAGE2.
    pub server: Option<PendingRegistration>,
    /// Client: the admission token, until `PQ_START` is sent.
    pub admission: Option<AdmissionToken>,
    /// Server: `PQ_START` passed the admission check, so a legacy STAGE2 (a server without
    /// post-quantum settings) is not asked again.
    pub admitted: bool,
    /// Both sides: a recovery in place of a registration (see `pq_sign_in::recover`).
    pub recover: super::recover::state::RecoverState,
}
