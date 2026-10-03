//! The four packets post-quantum sign-in adds: connect `AUTH_START` / `AUTH_CHALLENGE` and
//! register `PQ_START` / `PQ_REPLY`. Each carries one serialized message, sealed with the ratchet
//! of the key exchange that preceded it, exactly as connect STAGE0 and register STAGE2 are.

use crate::constants::HDP_HEADER_BYTE_LEN;
use crate::error::NetworkError;
use crate::prelude::Ticket;
use crate::proto::packet::HdpHeader;
use bytes::BytesMut;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::crypto::SecurityLevel;
use citadel_user::serialization::SyncIO;
use serde::Serialize;
use zerocopy::{I64, U128, U32, U64};

/// Which packet, and the header fields that differ between them.
pub(crate) struct Kind {
    pub primary: u8,
    pub aux: u8,
    pub algorithm: u8,
}

pub(crate) fn craft<R: Ratchet, T: Serialize + for<'de> serde::Deserialize<'de>>(
    ratchet: &R,
    kind: Kind,
    message: &T,
    timestamp: i64,
    security_level: SecurityLevel,
    ticket: Ticket,
) -> Result<BytesMut, NetworkError> {
    let header = HdpHeader {
        protocol_version: (*crate::constants::PROTOCOL_VERSION).into(),
        cmd_primary: kind.primary,
        cmd_aux: kind.aux,
        algorithm: kind.algorithm,
        security_level: security_level.value(),
        context_info: U128::new(ticket.0),
        group: U64::new(0),
        wave_id: U32::new(0),
        session_cid: U64::new(ratchet.get_cid()),
        entropy_bank_version: U32::new(ratchet.version()),
        timestamp: I64::new(timestamp),
        target_cid: U64::new(0),
    };
    let body = message
        .serialize_to_vector()
        .map_err(|err| NetworkError::generic(err.into_string()))?;
    let mut packet = BytesMut::with_capacity(HDP_HEADER_BYTE_LEN + body.len());
    header.inscribe_into(&mut packet);
    packet.extend_from_slice(&body);
    ratchet.protect_message_packet(Some(security_level), HDP_HEADER_BYTE_LEN, &mut packet)?;
    Ok(packet)
}

/// Reads one message from an already-decrypted payload.
pub(crate) fn read<T: serde::de::DeserializeOwned + Serialize>(
    payload: &[u8],
) -> Result<T, NetworkError> {
    T::deserialize_from_vector(payload).map_err(|_| {
        citadel_io::error!(
            citadel_io::ErrorCode::PqSignInMalformed,
            std::any::type_name::<T>()
        )
    })
}
