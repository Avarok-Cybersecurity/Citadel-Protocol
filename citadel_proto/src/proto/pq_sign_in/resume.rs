//! Resume credentials in the connect exchange (`citadel_user::auth::pq::resume` holds the rules).
//!
//! A full sign-in asks for one in STAGE0, once the challenge has told it the server's maximum,
//! and is handed the grant in SUCCESS. A later sign-in presents the credential in `AUTH_START` in
//! place of the account's factors, and proves the device key it names.

use super::challenge::ceremony;
use super::state::ServerPending;
use crate::error::NetworkError;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::session::CitadelSession;
use citadel_crypt::ratchets::Ratchet;
use citadel_user::auth::pq::login_transcript;
use citadel_user::auth::pq::messages::{AuthChallenge, LoginStart};
use citadel_user::auth::pq::resume::{DeviceKey, ResumeCredential, ResumeGrant, ResumeRequest};
use citadel_user::auth::pq::server::{build_resume_challenge, grant_after, VerifiedLogin};
use citadel_user::client_account::ClientNetworkAccount;
use citadel_user::misc::now_ms;

/// Client: what this sign-in knows about a resume credential.
#[derive(Default)]
pub(crate) struct ClientResume {
    /// The lifetime the application asked a full sign-in for, in seconds.
    pub wanted_s: Option<u64>,
    /// The server's maximum, as its challenge told it.
    pub max_lifetime_s: Option<u64>,
    /// What STAGE0 asked for, and the key it asked with, until SUCCESS brings the grant.
    asked: Option<(DeviceKey, ResumeRequest)>,
}

impl ClientResume {
    /// The request to send with a full sign-in's proof: the lifetime the application wants, cut
    /// to the server's maximum. `None` when either is missing.
    pub(crate) fn ask(&mut self) -> Result<Option<ResumeRequest>, NetworkError> {
        let (Some(wanted_s), Some(max_s)) = (self.wanted_s, self.max_lifetime_s) else {
            return Ok(None);
        };
        let device = DeviceKey::generate();
        let request = device.request(wanted_s.min(max_s))?;
        self.asked = Some((device, request.clone()));
        Ok(Some(request))
    }

    /// The credential to keep, when SUCCESS brought the grant that was asked for.
    pub(crate) fn granted(
        &mut self,
        cid: u64,
        grant: Option<ResumeGrant>,
    ) -> Option<ResumeCredential> {
        let (device, request) = self.asked.take()?;
        match ResumeCredential::accept(grant?, device, cid, &request) {
            Ok(credential) => Some(credential),
            Err(err) => {
                log::warn!(target: "citadel", "Discarding a resume grant that was not asked for: {err}");
                None
            }
        }
    }
}

/// Server: the challenge for an `AUTH_START` that presents a resume credential. A credential
/// that passes is its own admission: only a sign-in this server admitted was ever given one.
pub(super) fn issue<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    cnac: &ClientNetworkAccount<R, R>,
    cid: u64,
    start: &LoginStart,
) -> Result<(AuthChallenge, ServerPending), NetworkError> {
    let settings = session.account_manager.pq_settings();
    let settings =
        settings.ok_or_else(|| citadel_io::error!(citadel_io::ErrorCode::PqSignInFailed))?;
    let account = cnac.pq_account_state(&start.username);
    let (challenge, expected) =
        build_resume_challenge(settings, cid, account.as_account_auth(), start, now_ms())?;
    let challenge = AuthChallenge {
        challenge,
        ceremony: ceremony(Some(settings)),
    };
    let transcript = login_transcript(cid, start, &challenge);
    Ok((challenge, ServerPending::Factors(expected.bind(transcript))))
}

/// Server: the grant a verified sign-in is given, when it earned one and its STAGE0 asked.
pub(super) fn grant<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    cnac: &ClientNetworkAccount<R, R>,
    verified: &VerifiedLogin,
    request: Option<&ResumeRequest>,
) -> Option<ResumeGrant> {
    let settings = session.account_manager.pq_settings()?;
    let record = cnac.auth_store().pq_record().cloned()?;
    grant_after(
        settings,
        cnac.get_cid(),
        &record,
        verified,
        request?,
        now_ms(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY_S: u64 = 86_400;

    fn asking(wanted_s: Option<u64>, max_lifetime_s: Option<u64>) -> Option<u64> {
        let mut resume = ClientResume {
            wanted_s,
            max_lifetime_s,
            asked: None,
        };
        resume.ask().unwrap().map(|request| request.lifetime_s)
    }

    /// Control: ask for `wanted_s` as it is.
    #[test]
    fn the_client_asks_for_no_more_than_the_server_said_it_allows() {
        assert_eq!(asking(Some(7 * DAY_S), Some(DAY_S)), Some(DAY_S));
        assert_eq!(asking(Some(3_600), Some(DAY_S)), Some(3_600));
        assert_eq!(asking(None, Some(DAY_S)), None, "nothing was wanted");
        assert_eq!(asking(Some(3_600), None), None, "the server issues none");
    }
}
