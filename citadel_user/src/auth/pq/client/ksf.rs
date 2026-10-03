//! The password factor's seed: `Argon2id(rwd, salt_user)`, computed on the client only.

use crate::auth::pq::kem::{FactorKeypair, FactorSeed, SEED_LEN};
use crate::auth::pq::oprf::{OprfClientState, RWD_LEN};
use crate::auth::pq::record::KsfParams;
use crate::auth::proposed_credentials::ProposedCredentials;
use crate::misc::AccountError;
use citadel_crypt::argon::argon_container::{ArgonSettings, ArgonStatus, AsyncArgon};
use citadel_io::{error, ErrorCode};
use citadel_types::crypto::SecBuffer;
use zeroize::Zeroizing;

const KSF_AD: &[u8] = b"citadel-pq-password-factor-v1";

/// What the OPRF is run on: `SHA3-256(password)`, the same pre-hash the legacy path uses.
pub fn password_input(password: &SecBuffer) -> Zeroizing<[u8; 32]> {
    let digest = ProposedCredentials::password_transform(password.as_ref());
    let mut input = Zeroizing::new([0u8; 32]);
    input.copy_from_slice(digest.as_ref());
    input
}

/// Argon2id over `rwd`. Refuses parameters below [`KsfParams::FLOOR`], so a server cannot make a
/// client stretch less than that.
pub async fn password_seed(
    rwd: &[u8; RWD_LEN],
    salt_user: &[u8; 32],
    ksf: KsfParams,
) -> Result<FactorSeed, AccountError> {
    if !ksf.meets_floor() {
        return Err(error!(
            ErrorCode::PqSignInUnavailable,
            "the server asked for Argon2id parameters below the floor"
        ));
    }
    let settings = ArgonSettings::new(
        KSF_AD.to_vec(),
        salt_user.to_vec(),
        ksf.lanes,
        SEED_LEN as u32,
        ksf.mem_kib,
        ksf.iterations,
        Vec::new(),
    );
    let stretched = AsyncArgon::hash(SecBuffer::from(rwd.to_vec()), settings)
        .await
        .map_err(|err| error!(ErrorCode::ArgonHashFailed, err.to_string()))?;
    match stretched {
        ArgonStatus::HashSuccess(hash) => {
            let seed: [u8; SEED_LEN] = hash
                .as_ref()
                .try_into()
                .map_err(|_| error!(ErrorCode::PqSignInCrypto, "Argon2id output length"))?;
            Ok(FactorSeed::new(seed))
        }
        other => Err(error!(
            ErrorCode::ArgonHashUnexpected,
            citadel_io::Dbg(other)
        )),
    }
}

/// The password factor's keypair from the OPRF evaluation: unblind, stretch, derive.
pub async fn password_keypair(
    input: &[u8; 32],
    oprf: &OprfClientState,
    evaluated: &[u8],
    salt_user: &[u8; 32],
    ksf: KsfParams,
) -> Result<FactorKeypair, AccountError> {
    let rwd = oprf.finalize(input, evaluated)?;
    FactorKeypair::derive(&password_seed(&rwd, salt_user, ksf).await?)
}
