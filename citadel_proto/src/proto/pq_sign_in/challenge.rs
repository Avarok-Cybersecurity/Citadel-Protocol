//! The `AUTH_CHALLENGE` an `AUTH_START` is answered with, and the client's reading of it.

use super::packets;
use super::state::ServerPending;
use crate::error::NetworkError;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::session::CitadelSession;
use citadel_crypt::ratchets::Ratchet;
use citadel_user::auth::pq::client::{ClientLogin, RelyingParty};
use citadel_user::auth::pq::login_transcript;
use citadel_user::auth::pq::messages::{
    AuthChallenge, ChallengeBody, ChallengeCeremony, LoginChallenge, LoginStart,
};
use citadel_user::auth::pq::server::{build_login_challenge, Expectation, PqAuthServerSettings};
use citadel_user::client_account::{ClientNetworkAccount, PqAccountState};

pub(super) fn issue<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    cnac: &ClientNetworkAccount<R, R>,
    cid: u64,
    start: &LoginStart,
) -> Result<(AuthChallenge, ServerPending), NetworkError> {
    let account = cnac.pq_account_state(&start.username);
    let settings = session.account_manager.pq_settings();
    let sent = |challenge: LoginChallenge| AuthChallenge {
        challenge,
        ceremony: ceremony(settings),
    };
    match settings {
        Some(settings) => {
            let (challenge, expectation) =
                build_login_challenge(settings, account.as_account_auth(), start)?;
            let challenge = sent(challenge);
            let relying_party = RelyingParty::of_sign_in(&challenge);
            let asks_key = ClientLogin::security_key_request(&challenge.challenge, relying_party);
            if matches!(asks_key, Ok(Some(_))) {
                super::presence::open(session);
            }
            let pending = match expectation {
                Expectation::Factors(expected) => {
                    ServerPending::Factors(expected.bind(login_transcript(cid, start, &challenge)))
                }
                Expectation::Legacy { upgrade } => ServerPending::Legacy(upgrade),
            };
            Ok((challenge, pending))
        }
        None if matches!(account, PqAccountState::PostQuantum(_)) => Err(citadel_io::error!(
            citadel_io::ErrorCode::PqSignInUnavailable,
            "this server has no post-quantum sign-in settings"
        )),
        None => {
            let legacy = LoginChallenge {
                server_nonce: [0u8; 32],
                body: ChallengeBody::Legacy { upgrade: None },
            };
            Ok((sent(legacy), ServerPending::Legacy(None)))
        }
    }
}

/// What a challenge tells the client about its security keys.
pub(super) fn ceremony(settings: Option<&PqAuthServerSettings>) -> ChallengeCeremony {
    ChallengeCeremony {
        rp_id: settings
            .and_then(PqAuthServerSettings::security_key_rp_id)
            .map(str::to_owned),
    }
}

/// Client: the challenge its server sent.
pub(super) fn read(payload: &[u8]) -> Result<AuthChallenge, NetworkError> {
    packets::read(payload)
}
