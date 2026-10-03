//! The server's check of connect STAGE0: a post-quantum proof against the challenge it issued, or
//! the legacy Argon2 credentials, with the upgrade a legacy login may carry.

use super::state::ServerPending;
use crate::error::NetworkError;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::packet_crafter::do_connect::DoConnectStage0Packet;
use crate::proto::session::CitadelSession;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::{error, ErrorCode};
use citadel_types::auth::SessionScope;
use citadel_user::auth::pq::messages::LoginProof;
use citadel_user::client_account::ClientNetworkAccount;
use citadel_user::misc::now_ms;
use citadel_user::serialization::SyncIO;
use zeroize::Zeroizing;

/// What a STAGE0 that passed admits.
pub(crate) struct Admission {
    pub scope: SessionScope,
    /// From a post-quantum login: joins the session's pre-shared keys on both sides.
    pub session_key: Option<Zeroizing<[u8; 32]>>,
}

impl Admission {
    fn legacy() -> Self {
        Self {
            scope: SessionScope::Full,
            session_key: None,
        }
    }
}

/// Every failure of a post-quantum proof reads the same to the client.
fn failed() -> NetworkError {
    error!(ErrorCode::PqSignInFailed)
}

pub(crate) async fn validate_stage0<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    cnac: &ClientNetworkAccount<R, R>,
    payload: &[u8],
) -> Result<(DoConnectStage0Packet, Admission), NetworkError> {
    let stage0 = DoConnectStage0Packet::deserialize_from_vector(payload)
        .map_err(|err| NetworkError::generic(err.into_string()))?;
    let pending = inner_mut_state!(session.state_container)
        .connect_state
        .pq
        .server
        .take();
    let cid = cnac.get_cid();
    let account_manager = &session.account_manager;
    let admission = match (pending, stage0.pq_proof.clone()) {
        // The legacy login, as before 0.12. An account that has upgraded refuses it.
        (None, None) => {
            legacy_credentials(cnac, &stage0).await?;
            Admission::legacy()
        }
        (Some(ServerPending::Factors(pending)), Some(LoginProof::Factors(finish))) => {
            if !stage0
                .proposed_credentials
                .compare_username(cnac.get_username().as_bytes())
            {
                return Err(failed());
            }
            let verified = pending.verify(&finish)?;
            // Spends a recovery code under the record lock: of two logins that both verified the
            // same code, only the first gets here without an error.
            account_manager
                .record_pq_sign_in(cid, &verified.used)
                .await
                .map_err(|_| failed())?;
            Admission {
                scope: verified.scope,
                session_key: Some(verified.session_key),
            }
        }
        (Some(ServerPending::Legacy(upgrade)), proof) => {
            legacy_credentials(cnac, &stage0).await?;
            if let (Some(pending), Some(LoginProof::Upgrade(finish))) = (upgrade, proof) {
                let record = pending.finish(finish, now_ms())?;
                account_manager.upgrade_to_pq(cid, record).await?;
                log::info!(target: "citadel", "Account {cid} upgraded to post-quantum sign-in");
            }
            Admission::legacy()
        }
        _ => return Err(error!(ErrorCode::PqSignInMalformed, "a STAGE0 proof")),
    };
    Ok((stage0, admission))
}

async fn legacy_credentials<R: Ratchet>(
    cnac: &ClientNetworkAccount<R, R>,
    stage0: &DoConnectStage0Packet,
) -> Result<(), NetworkError> {
    cnac.validate_credentials(stage0.proposed_credentials.clone())
        .await
        .map_err(|err| NetworkError::generic(err.into_string()))?;
    log::trace!(target: "citadel", "Success validating credentials!");
    Ok(())
}
