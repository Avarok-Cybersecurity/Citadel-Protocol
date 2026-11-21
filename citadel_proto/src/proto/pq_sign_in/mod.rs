//! Post-quantum sign-in on the wire (see `citadel_user::auth::pq` for the cryptography).
//!
//! - Register, after the key exchange: `PQ_START` (C→S `RegStart`), `PQ_REPLY` (S→C
//!   `RegStartReply`), then STAGE2 carries the `RegFinish` keys. The server hashes nothing.
//! - Connect, after pre-connect: `AUTH_START` (C→S `LoginStart`), `AUTH_CHALLENGE` (S→C
//!   `LoginChallenge`), then STAGE0 carries the `LoginProof`. A legacy account answers with a
//!   legacy challenge, logs in with its Argon2 credentials, and upgrades in the same STAGE0.
//!
//! Every node this one takes part with runs it (`version_gate`). The legacy exchange remains only
//! for a server with no post-quantum settings, and a registration given no password. Every
//! message travels inside the session's post-quantum channel.

pub(crate) mod admission;
pub(crate) mod admit;
mod challenge;
pub(crate) mod connect;
pub(crate) mod manage;
mod packets;
pub(crate) mod presence;
pub(crate) mod recover;
pub(crate) mod refusal;
pub(crate) mod register;
pub(crate) mod restrict;
pub mod security_key;
pub(crate) mod state;
pub(crate) mod throttle;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_challenge;
#[cfg(test)]
mod tests_older_layouts;
#[cfg(test)]
mod tests_wire_recovery;

use crate::auth::AuthenticationRequest;
use crate::error::NetworkError;
use crate::proto::packet_crafter::peer_cmd::C2S_IDENTITY_CID;
use crate::proto::session::HdpSessionInitMode;
use crate::proto::state_container::StateContainerInner;
use citadel_crypt::ratchets::Ratchet;
use citadel_user::auth::pq::admission::AdmissionToken;
use state::OfferedFactors;

/// Client, at session start: the factors this session's login or registration offers.
pub(crate) fn store_offered<R: Ratchet>(
    state: &mut StateContainerInner<R>,
    mode: &HdpSessionInitMode,
) {
    match mode {
        HdpSessionInitMode::Connect(AuthenticationRequest::Credentialed { password, .. }) => {
            state.connect_state.pq.offered = Some(OfferedFactors {
                password: Some(password.clone()),
                security_key: None,
                recovery_phrase: None,
                admission: None,
            });
        }
        HdpSessionInitMode::Connect(AuthenticationRequest::SignIn { factors, .. }) => {
            state.connect_state.pq.offered = Some(OfferedFactors {
                password: factors.password.clone(),
                security_key: factors.security_key.clone(),
                recovery_phrase: factors.recovery_phrase.clone(),
                admission: factors.admission.clone().map(AdmissionToken::new),
            });
        }
        HdpSessionInitMode::Register(_, _, _, password, admission, recovery_domain) => {
            state.register_state.pq.password = password.clone();
            state.register_state.pq.admission = admission.clone();
            state.register_state.pq.recovery_domain = recovery_domain.clone();
        }
        HdpSessionInitMode::Recover(_, _, ask) => {
            state.register_state.pq.recover.ask = Some(recover::state::RecoverAsk {
                username: ask.username.clone(),
                phrase: ask.phrase.clone(),
                device_label: ask.device_label.clone(),
                admission: ask.admission.clone().map(AdmissionToken::new),
            });
        }
        HdpSessionInitMode::Connect(AuthenticationRequest::Passwordless { .. }) => {}
    }
}

/// Both sides, just before the C2S channel's ratchet manager is built: the sign-in's session key
/// joins the channel's pre-shared keys, so every key the channel ratchets to depends on the
/// factors that admitted it, and a side that did not prove them cannot follow a rekey.
pub(crate) fn mix_session_key<R: Ratchet>(
    state: &mut StateContainerInner<R>,
    session_key: &[u8; 32],
) -> Result<(), NetworkError> {
    let psk = state
        .get_session_password(C2S_IDENTITY_CID)
        .cloned()
        .ok_or_else(|| NetworkError::msg("The C2S pre-shared key was not stored"))?;
    state.store_session_password(C2S_IDENTITY_CID, psk.add_password(session_key));
    Ok(())
}
