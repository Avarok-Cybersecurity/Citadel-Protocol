//! Each leaf signs what it sends with an ML-DSA-65 key of its own.
//!
//! The key is reproduced from the leaf secret the member drew for its KeyPackage, so nothing new is
//! stored, and its verifying key travels in the leaf (`LeafNode::sig_public`), where every member
//! reads it. The epoch's encryption secret is shared by every member; this key is not, so a frame
//! verifies only for the member whose leaf it names.
//!
//! ```text
//! seed = BLAKE3-derive-key("citadel-treekem-leaf-signature-v1", leaf_secret)
//! sig  = ML-DSA-65.Sign(sk, "citadel-treekem-frame-v1" ‖ 0x00 ‖ u64be(epoch) ‖ u32be(sender)
//!                           ‖ u64be(incarnation) ‖ u32be(generation) ‖ body)
//! ```

use crate::crypto::Secret;
use citadel_types::crypto::SigAlgorithm;
use citadel_types::errors::Error;
use zeroize::Zeroizing;

const FRAME_DOMAIN: &[u8] = b"citadel-treekem-frame-v1";

/// A leaf's signing key (expanded ML-DSA-65 encoding), wiped on drop.
pub type LeafSigningKey = Zeroizing<Vec<u8>>;

/// The verifying and signing key of the leaf whose secret is `leaf_secret`.
pub fn leaf_signature_keys(leaf_secret: &Secret) -> (Vec<u8>, LeafSigningKey) {
    let mut seed = blake3::derive_key("citadel-treekem-leaf-signature-v1", leaf_secret);
    let keys = citadel_pqcrypto::ml_dsa65_keypair_from_seed(&seed);
    zeroize::Zeroize::zeroize(&mut seed);
    keys
}

/// Where a frame sits in its sender's stream: unique per frame a sender ever signs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FrameId {
    pub epoch: u64,
    pub sender: u32,
    pub incarnation: u64,
    pub generation: u32,
}

fn frame_message(frame: FrameId, body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(FRAME_DOMAIN.len() + 1 + 24 + body.len());
    message.extend_from_slice(FRAME_DOMAIN);
    message.push(0);
    message.extend_from_slice(&frame.epoch.to_be_bytes());
    message.extend_from_slice(&frame.sender.to_be_bytes());
    message.extend_from_slice(&frame.incarnation.to_be_bytes());
    message.extend_from_slice(&frame.generation.to_be_bytes());
    message.extend_from_slice(body);
    message
}

pub(crate) fn sign_frame(
    key: &LeafSigningKey,
    frame: FrameId,
    body: &[u8],
) -> Result<Vec<u8>, Error> {
    citadel_pqcrypto::signature_sign(
        frame_message(frame, body),
        key.as_slice(),
        SigAlgorithm::MlDsa65,
    )
}

pub(crate) fn verify_frame(
    sig_public: &[u8],
    frame: FrameId,
    body: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    citadel_pqcrypto::signature_verify(
        frame_message(frame, body),
        signature,
        sig_public,
        SigAlgorithm::MlDsa65,
    )
    .map_err(|_| Error::generic("treekem: the frame is not signed by its sender's leaf"))
}
