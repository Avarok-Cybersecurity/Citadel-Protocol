//! The server's check of connect STAGE0: a post-quantum proof against the challenge it issued, or
//! a passwordless login that ran no exchange.

use super::without_factors::refuse_unless_passwordless;
use crate::error::NetworkError;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::packet_crafter::do_connect::DoConnectStage0Packet;
use crate::proto::session::CitadelSession;
use crate::proto::session_resume;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::{error, ErrorCode};
use citadel_types::auth::SessionScope;
use citadel_user::auth::pq::messages::LoginProof;
use citadel_user::client_account::ClientNetworkAccount;
use citadel_user::serialization::SyncIO;
use zeroize::Zeroizing;

/// What a STAGE0 that passed admits.
pub(crate) struct Admission {
    pub scope: SessionScope,
    /// From a post-quantum login: joins the session's pre-shared keys on both sides.
    pub session_key: Option<Zeroizing<[u8; 32]>>,
}

/// Every failure of a post-quantum proof reads the same to the client.
fn failed() -> NetworkError {
    error!(ErrorCode::PqSignInFailed)
}

pub(crate) async fn validate_stage0<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    cnac: &ClientNetworkAccount<R, R>,
    payload: &[u8],
    adjacent_version: u32,
) -> Result<(DoConnectStage0Packet, Admission), NetworkError> {
    let stage0 = DoConnectStage0Packet::deserialize_from_vector(payload)
        .map_err(|err| NetworkError::generic(err.into_string()))?;
    let pending = inner_mut_state!(session.state_container)
        .connect_state
        .pq
        .server
        .take();
    let cid = cnac.get_cid();
    let admission = match (pending, stage0.pq_proof.clone()) {
        // No AUTH_START: a passwordless login, or refused before any other work.
        (None, None) => {
            refuse_unless_passwordless(adjacent_version, &stage0.proposed_credentials)?;
            let presented = session_resume::exchanged_with(adjacent_version, stage0.resume_token);
            let username = cnac.get_username();
            let presented = presented.as_ref();
            super::admission::sign_in_without_factors(
                session,
                cid,
                &username,
                presented,
                adjacent_version,
            )
            .await?;
            cnac.admits_without_factors(&stage0.proposed_credentials)
                .map_err(|err| NetworkError::generic(err.into_string()))?;
            Admission {
                scope: SessionScope::Full,
                session_key: None,
            }
        }
        (Some(pending), Some(LoginProof::Factors(finish))) => {
            if !stage0
                .proposed_credentials
                .compare_username(cnac.get_username().as_bytes())
            {
                return Err(failed());
            }
            let verified = pending.verify(&finish)?;
            // Spends a recovery code, and runs the auth-migration hook, under the record lock: of
            // two logins that both verified the same code, only the first gets here without an
            // error.
            session
                .account_manager
                .record_pq_sign_in(cid, &verified.used)
                .await
                .map_err(|_| failed())?;
            Admission {
                scope: verified.scope,
                session_key: Some(verified.session_key),
            }
        }
        _ => return Err(error!(ErrorCode::PqSignInMalformed, "a STAGE0 proof")),
    };
    Ok((stage0, admission))
}
