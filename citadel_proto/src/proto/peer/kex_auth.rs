//! A P2P key exchange is authenticated end to end by each account's identity key.
//!
//! Each side signs its own stage with its account's ML-DSA-65 identity key: the initiator its
//! Stage0, the responder its Stage1. The signature covers a transcript naming both CIDs, the
//! connection's id, the digest of the Stage0 and, for the responder, of its Stage1, and the
//! signer's role. The other side checks the signature under the key the stage names, then that
//! key against the one pinned for the peer. The server relays both stages unchanged and cannot
//! answer either with keys of its own: a stage it alters no longer verifies, and a stage it signs
//! itself carries a key other than the pinned one.
//!
//! ```text
//! body = u64be(initiator_cid) ‖ u64be(responder_cid) ‖ u128be(connection_id)
//!      ‖ SHA3-256(stage0) ‖ [responder only] SHA3-256(stage1) ‖ u8(role)
//! sig  = ML-DSA-65.Sign(sk_identity, "citadel-p2p-kex-v1" ‖ 0x00 ‖ body)
//! ```
//!
//! The digests cover what the sender wrote, never what the server adds: Stage0's KEM transfer,
//! security settings, UDP mode and connection id; Stage1's KEM transfer, file-transfer flag and
//! echoed connection id (the server fills in Stage1's NAT info).
//!
//! The keys and the pins are the application's, behind [`P2pKexIdentity`]; this module only
//! decides. A peer with no pin that sends no signature (an account with no identity key) still
//! connects, as [`PeerKexIdentity::Unsigned`]. A peer with a pin must sign with the pinned key.

use crate::proto::peer::p2p_seal_binding::P2pSealContext;
use crate::proto::remote::Ticket;
use citadel_io::ErrorCode;
use citadel_types::crypto::SigAlgorithm;
use citadel_types::proto::{SessionSecuritySettings, UdpMode};
use citadel_user::serialization::SyncIO;
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::sync::Arc;

/// The domain every transcript signature is made under.
pub const KEX_TRANSCRIPT_DOMAIN: &[u8] = b"citadel-p2p-kex-v1";

/// One stage's signature and the identity key that made it.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct KexAuth {
    /// The signer's encoded ML-DSA-65 identity public key.
    pub identity_key: Vec<u8>,
    /// ML-DSA-65 (pure, empty context) over `KEX_TRANSCRIPT_DOMAIN ‖ 0x00 ‖ body`.
    pub signature: Vec<u8>,
}

/// The stage a signature is for, with the digests its transcript covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KexStage {
    /// The initiator's Stage0.
    Initiator { stage0: [u8; 32] },
    /// The responder's Stage1, which answers that Stage0.
    Responder { stage0: [u8; 32], stage1: [u8; 32] },
}

impl KexStage {
    fn role(&self) -> u8 {
        match self {
            KexStage::Initiator { .. } => 0,
            KexStage::Responder { .. } => 1,
        }
    }
}

/// The application's identity keys and its pins of its peers' keys. The node never calls it
/// while it holds its own state: a pin may be awaited on storage.
pub trait P2pKexIdentity: Send + Sync {
    /// `local_cid`'s signature over `KEX_TRANSCRIPT_DOMAIN ‖ 0x00 ‖ body`, with its identity key;
    /// `None` when the account has no identity key, and its stage goes unsigned.
    fn sign(&self, local_cid: u64, body: &[u8]) -> Option<KexAuth>;
    /// The identity key `local_cid` pinned for `peer_cid`, if any.
    fn pinned_key(&self, local_cid: u64, peer_cid: u64) -> Option<Vec<u8>>;
    /// `peer_cid` signed with a verified key and had no pin: pin it, durably. The exchange goes
    /// on, and is reported verified, only once this resolves `Ok`; an `Err` refuses it.
    fn pin_first_key(
        &self,
        local_cid: u64,
        peer_cid: u64,
        identity_key: &[u8],
    ) -> BoxFuture<'static, Result<(), String>>;
    /// `peer_cid` signed with a verified key other than its pin. The exchange is refused; the
    /// pin stays until the person accepts the presented key.
    fn peer_key_changed(&self, local_cid: u64, peer_cid: u64, presented: &[u8]);
}

/// How a node holds its [`P2pKexIdentity`].
pub type P2pKexIdentities = Arc<dyn P2pKexIdentity>;

/// What a P2P channel's key exchange proved about the peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerKexIdentity {
    /// The peer's stage was signed by this identity key, which is the one pinned for it.
    Signed { identity_key: Vec<u8> },
    /// The peer sent no signature and has no pin, or this node holds no identity port.
    Unsigned,
}

/// `SHA3-256` of the Stage0 fields the initiator wrote.
pub(crate) fn stage0_digest(
    transfer: &[u8],
    settings: SessionSecuritySettings,
    udp_mode: UdpMode,
    connection: Ticket,
) -> Option<[u8; 32]> {
    digest((transfer, settings, udp_mode, connection))
}

/// `SHA3-256` of the Stage1 fields the responder wrote.
pub(crate) fn stage1_digest(
    transfer: &[u8],
    file_transfer_compat: bool,
    connection: Ticket,
) -> Option<[u8; 32]> {
    digest((transfer, file_transfer_compat, connection))
}

fn digest<'a, F: Serialize + Deserialize<'a>>(fields: F) -> Option<[u8; 32]> {
    Some(Sha3_256::digest(fields.serialize_to_vector().ok()?).into())
}

/// The transcript body a stage's signature covers (see the module docs).
pub(crate) fn transcript_body(context: &P2pSealContext, stage: &KexStage) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + 8 + 16 + 32 + 32 + 1);
    body.extend_from_slice(&context.initiator.to_be_bytes());
    body.extend_from_slice(&context.responder.to_be_bytes());
    body.extend_from_slice(&context.connection.0.to_be_bytes());
    match stage {
        KexStage::Initiator { stage0 } => body.extend_from_slice(stage0),
        KexStage::Responder { stage0, stage1 } => {
            body.extend_from_slice(stage0);
            body.extend_from_slice(stage1);
        }
    }
    body.push(stage.role());
    body
}

/// `KEX_TRANSCRIPT_DOMAIN ‖ 0x00 ‖ body`: the bytes the identity key signs.
pub fn transcript_message(body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(KEX_TRANSCRIPT_DOMAIN.len() + 1 + body.len());
    message.extend_from_slice(KEX_TRANSCRIPT_DOMAIN);
    message.push(0);
    message.extend_from_slice(body);
    message
}

/// Whether `auth` is a valid signature over `body` by the key it names.
pub fn verify(auth: &KexAuth, body: &[u8]) -> Result<(), String> {
    citadel_pqcrypto::signature_verify(
        transcript_message(body),
        &auth.signature,
        &auth.identity_key,
        SigAlgorithm::MlDsa65,
    )
    .map_err(|err| err.into_string())
}

/// What [`judge`] found, before the port records anything.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Judged {
    /// Signed by the pinned key.
    Pinned(Vec<u8>),
    /// Signed by a valid key, and nothing was pinned.
    FirstSeen(Vec<u8>),
    /// Signed by a valid key other than the pinned one.
    Changed(Vec<u8>),
    /// Unsigned, with nothing pinned.
    Unsigned,
}

/// A stage that may not build a link.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    BadSignature(String),
    MissingSignature,
}

/// The decision, pure: a signature is checked before any pin is consulted, so a stage that does
/// not verify can neither pin a key nor report a changed one.
pub(crate) fn judge(
    pinned: Option<&[u8]>,
    auth: Option<&KexAuth>,
    body: &[u8],
) -> Result<Judged, Refused> {
    let Some(auth) = auth else {
        return match pinned {
            Some(_) => Err(Refused::MissingSignature),
            None => Ok(Judged::Unsigned),
        };
    };
    verify(auth, body).map_err(Refused::BadSignature)?;
    let presented = auth.identity_key.clone();
    Ok(match pinned {
        None => Judged::FirstSeen(presented),
        Some(pin) if pin == presented.as_slice() => Judged::Pinned(presented),
        Some(_) => Judged::Changed(presented),
    })
}

/// The peer's stage, checked and recorded through the port. `Err` is the refusal's error text
/// for the kernel and the peer. Awaits the port, so it is called with no state held.
pub(crate) async fn authenticate(
    port: Option<&P2pKexIdentities>,
    local_cid: u64,
    peer_cid: u64,
    auth: Option<&KexAuth>,
    body: &[u8],
) -> Result<PeerKexIdentity, String> {
    let Some(port) = port else {
        return Ok(PeerKexIdentity::Unsigned);
    };
    let pinned = port.pinned_key(local_cid, peer_cid);
    match judge(pinned.as_deref(), auth, body) {
        Ok(Judged::Pinned(identity_key)) => Ok(PeerKexIdentity::Signed { identity_key }),
        Ok(Judged::FirstSeen(identity_key)) => {
            match port.pin_first_key(local_cid, peer_cid, &identity_key).await {
                Ok(()) => Ok(PeerKexIdentity::Signed { identity_key }),
                Err(why) => Err(
                    citadel_io::error!(ErrorCode::P2pKexPinNotSaved, peer_cid, why).into_string(),
                ),
            }
        }
        Ok(Judged::Unsigned) => Ok(PeerKexIdentity::Unsigned),
        Ok(Judged::Changed(presented)) => {
            port.peer_key_changed(local_cid, peer_cid, &presented);
            Err(citadel_io::error!(ErrorCode::P2pKexPeerKeyChanged, peer_cid).into_string())
        }
        Err(Refused::MissingSignature) => {
            Err(citadel_io::error!(ErrorCode::P2pKexSignatureMissing, peer_cid).into_string())
        }
        Err(Refused::BadSignature(why)) => {
            Err(citadel_io::error!(ErrorCode::P2pKexSignatureInvalid, peer_cid, why).into_string())
        }
    }
}

/// This side's signature for its stage: every stage is signed when this account has an
/// identity key, whichever side it is.
pub(crate) fn sign_stage(
    port: Option<&P2pKexIdentities>,
    local_cid: u64,
    context: &P2pSealContext,
    stage: &KexStage,
) -> Option<KexAuth> {
    port?.sign(local_cid, &transcript_body(context, stage))
}

#[cfg(test)]
#[path = "kex_auth_tests.rs"]
mod tests;
