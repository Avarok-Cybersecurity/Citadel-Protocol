use super::ksf::{password_input, password_keypair};
use crate::auth::pq::kem::FactorKeypair;
use crate::auth::pq::messages::{RegFinish, RegReply, RegStart};
use crate::auth::pq::oprf::{self, OprfClientState};
use crate::auth::pq::phrase::{RecoveryPhrase, RecoverySeed};
use crate::auth::pq::recovery::RecoveryCode;
use crate::auth::pq::seed::recovery_seed;
use crate::misc::AccountError;
use citadel_types::crypto::SecBuffer;
use zeroize::Zeroizing;

/// A registration (or a legacy account's upgrade) between [`RegStart`] and [`RegFinish`].
pub struct ClientRegistration {
    input: Zeroizing<[u8; 32]>,
    oprf: OprfClientState,
}

impl ClientRegistration {
    /// The password factor's keypair, from the server's evaluation and salt.
    pub async fn password_keypair(&self, reply: &RegReply) -> Result<FactorKeypair, AccountError> {
        password_keypair(
            &self.input,
            &self.oprf,
            &reply.oprf_evaluated,
            &reply.salt_user,
            reply.ksf,
        )
        .await
    }

    pub fn start(username: &str, password: &SecBuffer) -> Result<(RegStart, Self), AccountError> {
        let input = password_input(password);
        let (oprf, oprf_blinded) = oprf::client_blind(input.as_ref())?;
        let start = RegStart {
            username: username.to_string(),
            oprf_blinded,
            // Set by the registration that sends this.
            admission: None,
            reads_challenge: true,
        };
        Ok((start, Self { input, oprf }))
    }

    /// Resumes from a blinding the client already sent, as the `oprf_blinded` of a legacy login.
    pub(crate) fn resume(input: Zeroizing<[u8; 32]>, oprf: OprfClientState) -> Self {
        Self { input, oprf }
    }

    /// The factors' keys, and the recovery secret behind them, which must be shown to the user
    /// now: nothing else ever holds it.
    pub async fn finish(
        self,
        reply: &RegReply,
        recovery: NewRecovery<'_>,
    ) -> Result<(RegFinish, IssuedRecovery), AccountError> {
        let password = self.password_keypair(reply).await?;
        let mut issued = IssuedRecovery::default();
        let mut recovery_eks = Vec::new();
        let mut recovery_phrase_ek = None;
        match recovery {
            NewRecovery::None => {}
            NewRecovery::Codes => {
                issued.codes = RecoveryCode::generate_set();
                for code in &issued.codes {
                    let keypair = FactorKeypair::derive(&recovery_seed(code))?;
                    recovery_eks.push(keypair.encapsulation_key().clone());
                }
            }
            NewRecovery::Phrase {
                username,
                canonical_domain,
            } => {
                let phrase = RecoveryPhrase::new(RecoverySeed::generate(), canonical_domain)?;
                let keypair = phrase.keypair(username)?;
                recovery_phrase_ek = Some(keypair.encapsulation_key().clone());
                issued.phrase = Some(phrase.seed().clone());
            }
        }
        let finish = RegFinish {
            password_ek: password.encapsulation_key().clone(),
            recovery_eks,
            recovery_phrase_ek,
        };
        Ok((finish, issued))
    }
}

/// What recovery credential a new account is given.
#[derive(Clone, Copy, Debug)]
pub enum NewRecovery<'a> {
    /// None: an account upgrading from a legacy record.
    None,
    /// Ten single-use codes, for a server below the recovery release.
    Codes,
    /// The recovery phrase, bound to the server's canonical domain and the username.
    Phrase {
        username: &'a str,
        canonical_domain: &'a str,
    },
}

/// The recovery secret a registration generated, to show the user once.
#[derive(Default)]
pub struct IssuedRecovery {
    pub codes: Vec<RecoveryCode>,
    pub phrase: Option<RecoverySeed>,
}

impl std::fmt::Debug for IssuedRecovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedRecovery")
            .field("codes", &self.codes.len())
            .field("phrase", &self.phrase.as_ref().map(|_| "***"))
            .finish()
    }
}
