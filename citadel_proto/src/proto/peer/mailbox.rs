//! What a server holds for an offline peer, routed to it on its behalf.
//!
//! A connect request is never held: it lives only as long as its posting's short timeout, so the
//! sender is told at once that the peer is offline instead.
//! An invitation is held until the peer next connects, and any account may invite any other, but
//! one sender holds at most [`MAX_MAILED_SIGNALS_PER_SENDER`] in one peer's mailbox.
//!
//! Each held signal's key names its sender (`<sender cid>/<uuid>`), so the count needs no second
//! index. The count and the store are not one transaction: every caller routes under the peer
//! layer's write lock, which serializes them.

use crate::error::NetworkError;
use crate::proto::peer::peer_layer::{PeerSignal, PEER_MAILBOX_MAP};
use citadel_crypt::ratchets::Ratchet;
use citadel_io::{error, ErrorCode};
use citadel_user::backend::PersistenceHandler;
use citadel_user::serialization::SyncIO;
use uuid::Uuid;

/// The most signals one sender holds in one offline peer's mailbox. An invitation is answered
/// once; a sender re-inviting a peer that has not yet come online has no use for more than a
/// few pending, and each one is replayed to the peer at its next login.
pub(crate) const MAX_MAILED_SIGNALS_PER_SENDER: usize = 8;

/// What becomes of a signal routed to an offline peer.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Mailing {
    Mail,
    /// Answered now or never: the peer is offline.
    NeverMailed,
    /// The sender already holds [`MAX_MAILED_SIGNALS_PER_SENDER`] in this mailbox.
    SenderAtCap,
}

pub(crate) fn mailing(signal: &PeerSignal, held_from_sender: usize) -> Mailing {
    match signal {
        PeerSignal::PostConnect { .. } => Mailing::NeverMailed,
        _ if held_from_sender >= MAX_MAILED_SIGNALS_PER_SENDER => Mailing::SenderAtCap,
        _ => Mailing::Mail,
    }
}

fn sub_key(sender_cid: u64) -> String {
    format!("{sender_cid}/{}", Uuid::new_v4())
}

fn is_from(sub_key: &str, sender_cid: u64) -> bool {
    sub_key
        .split_once('/')
        .is_some_and(|(sender, _)| sender.parse() == Ok(sender_cid))
}

/// Holds `signal` from `sender_cid` for the offline `target_cid`, if [`mailing`] allows it.
pub(crate) async fn mail_from<R: Ratchet>(
    pers: &PersistenceHandler<R, R>,
    target_cid: u64,
    sender_cid: u64,
    signal: PeerSignal,
) -> Result<(), NetworkError> {
    let held_from_sender = pers
        .get_byte_map_values_by_key(target_cid, 0, PEER_MAILBOX_MAP)
        .await?
        .keys()
        .filter(|key| is_from(key, sender_cid))
        .count();
    match mailing(&signal, held_from_sender) {
        Mailing::NeverMailed => Err(error!(ErrorCode::PeerConnectTargetOffline, target_cid)),
        Mailing::SenderAtCap => Err(error!(
            ErrorCode::MailboxSenderAtCap,
            sender_cid, MAX_MAILED_SIGNALS_PER_SENDER, target_cid
        )),
        Mailing::Mail => {
            let serialized = signal
                .serialize_to_vector()
                .map_err(|err| NetworkError::generic(err.into_string()))?;
            let _ = pers
                .store_byte_map_value(
                    target_cid,
                    0,
                    PEER_MAILBOX_MAP,
                    &sub_key(sender_cid),
                    serialized,
                )
                .await?;
            Ok(())
        }
    }
}

#[cfg(all(test, not(target_family = "wasm")))]
#[path = "mailbox_tests.rs"]
pub(crate) mod tests;
