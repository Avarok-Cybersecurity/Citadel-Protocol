//! The reattach proof: the existing AEAD under the existing ratchet, over a transcript that binds
//! the claim. No new primitive (post-quantum only, §5.2).

use super::ReattachBinding;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::NetworkError;

/// Separates this transcript from every other use of the session's keys.
const DOMAIN: &[u8] = b"citadel/link/reattach/1";

/// The bytes the proof seals: the domain tag, the binding, and the ratchet version sealed under,
/// so a proof made under one version does not open as another's.
fn transcript(binding: &ReattachBinding, ratchet_version: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 16 + 8 + 8 + 4);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&binding.connection_id.0.to_be_bytes());
    bytes.extend_from_slice(&binding.incarnation.to_be_bytes());
    bytes.extend_from_slice(&binding.attempt.to_be_bytes());
    bytes.extend_from_slice(&ratchet_version.to_be_bytes());
    bytes
}

/// The client seals `binding` under its live ratchet.
pub(crate) fn seal_proof<R: Ratchet>(
    ratchet: &R,
    binding: &ReattachBinding,
) -> Result<Vec<u8>, NetworkError> {
    ratchet
        .encrypt(transcript(binding, ratchet.version()))
        .map_err(|err| NetworkError::msg(format!("reattach proof: {err}")))
}

/// The server opens `proof` under the held session's ratchet: true only when it decrypts and is
/// exactly the transcript of `binding` at that ratchet's version.
pub(crate) fn proof_opens<R: Ratchet>(
    ratchet: &R,
    binding: &ReattachBinding,
    proof: &[u8],
) -> bool {
    let Ok(opened) = ratchet.decrypt(proof) else {
        return false;
    };
    let expected = transcript(binding, ratchet.version());
    opened.len() == expected.len()
        && opened
            .iter()
            .zip(expected.iter())
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            == 0
}
