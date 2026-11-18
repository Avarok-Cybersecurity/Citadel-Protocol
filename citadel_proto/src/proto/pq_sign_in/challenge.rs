//! The `AUTH_CHALLENGE` an `AUTH_START` is answered with, in the layout its client reads, and the
//! client's reading of it in the layout its server sends.

use super::layout_of;
use super::packets;
use super::state::ServerPending;
use crate::error::NetworkError;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::session::CitadelSession;
use citadel_crypt::ratchets::Ratchet;
use citadel_user::auth::pq::client::{ClientLogin, RelyingParty};
use citadel_user::auth::pq::login_transcript;
use citadel_user::auth::pq::messages::{
    AuthChallenge, ChallengeBody, ChallengeCeremony, LoginChallenge, LoginStart, SignInLayout,
};
use citadel_user::auth::pq::server::{build_login_challenge, Expectation, PqAuthServerSettings};
use citadel_user::client_account::{ClientNetworkAccount, PqAccountState};

pub(super) fn issue<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    cnac: &ClientNetworkAccount<R, R>,
    cid: u64,
    start: &LoginStart,
    client_version: u32,
) -> Result<(AuthChallenge, ServerPending), NetworkError> {
    let account = cnac.pq_account_state(&start.username);
    let settings = session.account_manager.pq_settings();
    let sent = |challenge: LoginChallenge| AuthChallenge {
        challenge,
        ceremony: ceremony(settings, layout_of(Some(client_version))),
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

/// What a challenge appends for a client in `layout`: nothing for a 0.12.2 client.
pub(super) fn ceremony(
    settings: Option<&PqAuthServerSettings>,
    layout: SignInLayout,
) -> Option<ChallengeCeremony> {
    match layout {
        SignInLayout::V0_12_2 => None,
        SignInLayout::SecurityKeyCeremony => Some(ChallengeCeremony {
            rp_id: settings
                .and_then(PqAuthServerSettings::security_key_rp_id)
                .map(str::to_owned),
        }),
    }
}

/// Client: the challenge from a server at `server_version`, which must be in that version's
/// layout.
pub(super) fn read(payload: &[u8], server_version: u32) -> Result<AuthChallenge, NetworkError> {
    let sent: AuthChallenge = packets::read(payload)?;
    let ceremony_expected = layout_of(Some(server_version)) == SignInLayout::SecurityKeyCeremony;
    if sent.ceremony.is_some() != ceremony_expected {
        return Err(citadel_io::error!(
            citadel_io::ErrorCode::PqSignInMalformed,
            "a challenge in another layout than the server's version"
        ));
    }
    Ok(sent)
}
