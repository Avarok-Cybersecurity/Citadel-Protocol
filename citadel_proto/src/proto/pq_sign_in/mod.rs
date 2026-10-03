//! Post-quantum sign-in on the wire (see `citadel_user::auth::pq` for the cryptography).
//!
//! - Register, after the key exchange: `PQ_START` (C→S `RegStart`), `PQ_REPLY` (S→C
//!   `RegStartReply`), then STAGE2 carries the `RegFinish` keys. The server hashes nothing.
//! - Connect, after pre-connect: `AUTH_START` (C→S `LoginStart`), `AUTH_CHALLENGE` (S→C
//!   `LoginChallenge`), then STAGE0 carries the `LoginProof`. A legacy account answers with a
//!   legacy challenge, logs in with its Argon2 credentials, and upgrades in the same STAGE0.
//!
//! Both sides use it only with a node at or above [`PQ_SIGN_IN_SINCE`]; with an older one they
//! keep the legacy exchange, so 0.11 and 0.12 nodes interoperate. Every message travels inside
//! the session's post-quantum channel.

pub(crate) mod admit;
pub(crate) mod connect;
mod packets;
pub(crate) mod register;
pub(crate) mod state;

#[cfg(test)]
mod tests;

use crate::auth::AuthenticationRequest;
use crate::constants::{protocol_version_at_least, PQ_SIGN_IN_SINCE};
use crate::error::NetworkError;
use crate::proto::packet_crafter::peer_cmd::C2S_IDENTITY_CID;
use crate::proto::session::HdpSessionInitMode;
use crate::proto::state_container::StateContainerInner;
use citadel_crypt::ratchets::Ratchet;
use state::OfferedFactors;

/// Whether the adjacent node runs post-quantum sign-in.
pub(crate) fn runs_with(adjacent_version: u32) -> bool {
    protocol_version_at_least(Some(adjacent_version), PQ_SIGN_IN_SINCE)
}

/// Client, at session start: the factors this session's login or registration offers.
pub(crate) fn store_offered<R: Ratchet>(
    state: &mut StateContainerInner<R>,
    mode: &HdpSessionInitMode,
) {
    match mode {
        HdpSessionInitMode::Connect(AuthenticationRequest::Credentialed { password, .. }) => {
            state.connect_state.pq.offered = Some(OfferedFactors {
                password: Some(password.clone()),
            });
        }
        HdpSessionInitMode::Register(_, _, _, password) => {
            state.register_state.pq.password = password.clone();
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
