//! These crafters return a base64 string representation of the packets, meant to be sent outbound to FCM services
use hyxe_crypt::hyper_ratchet::Ratchet;
use crate::external_services::fcm::data_structures::{FcmHeader, FCMPayloadType, FCM_HEADER_BYTES, RawExternalPacket};
use zerocopy::{U64, U32, U128};
use bytes::BytesMut;
use hyxe_fs::io::SyncIO;
use serde::Serialize;
use hyxe_crypt::net::crypt_splitter::AES_GCM_GHASH_OVERHEAD;
use hyxe_crypt::endpoint_crypto_container::KemTransferStatus;
use hyxe_crypt::hyper_ratchet::constructor::AliceToBobTransferType;
use crate::external_services::fcm::kem::FcmPostRegister;
use hyxe_crypt::prelude::SecBuffer;

pub fn craft_group_header<Fcm: Ratchet>(fcm_ratchet: &Fcm, object_id: u32, group_id: u64, target_cid: u64, ticket: u128, message: SecBuffer, alice_to_bob_transfer: Option<AliceToBobTransferType<'_>>) -> Option<RawExternalPacket> {
    let header = FcmHeader {
        session_cid: U64::new(fcm_ratchet.get_cid()),
        target_cid: U64::new(target_cid),
        group_id: U64::new(group_id),
        ticket: U128::new(ticket),
        object_id: U32::new(object_id),
        ratchet_version: U32::new(fcm_ratchet.version())
    };

    let alice_to_bob_transfer = if let Some(val) = alice_to_bob_transfer {
        match val {
            AliceToBobTransferType::Fcm(tx) => Some(tx),
            _ => return None
        }
    } else {
        None
    };

    let payload = FCMPayloadType::GroupHeader { alice_to_bob_transfer, message: message.as_ref() };

    Some(base64_packet(fcm_ratchet, &header, &payload))
}

pub fn craft_group_header_ack<Fcm: Ratchet>(fcm_ratchet: &Fcm, object_id: u32, group_id: u64, target_cid: u64, ticket: u128, bob_to_alice_transfer: KemTransferStatus) -> RawExternalPacket {
    let header = FcmHeader {
        session_cid: U64::new(fcm_ratchet.get_cid()),
        target_cid: U64::new(target_cid),
        group_id: U64::new(group_id),
        ticket: U128::new(ticket),
        object_id: U32::new(object_id),
        ratchet_version: U32::new(fcm_ratchet.version())
    };

    let payload = FCMPayloadType::GroupHeaderAck { bob_to_alice_transfer };

    base64_packet(fcm_ratchet, &header, &payload)
}

pub fn craft_truncate<Fcm: Ratchet>(fcm_ratchet: &Fcm, object_id: u32, group_id: u64, target_cid: u64, ticket: u128, truncate_vers: Option<u32>) -> RawExternalPacket {
    let header = FcmHeader {
        session_cid: U64::new(fcm_ratchet.get_cid()),
        target_cid: U64::new(target_cid),
        group_id: U64::new(group_id),
        ticket: U128::new(ticket),
        object_id: U32::new(object_id),
        ratchet_version: U32::new(fcm_ratchet.version())
    };

    let payload = FCMPayloadType::Truncate { truncate_vers };

    base64_packet(fcm_ratchet, &header, &payload)
}

pub fn craft_truncate_ack<Fcm: Ratchet>(fcm_ratchet: &Fcm, object_id: u32, group_id: u64, target_cid: u64, ticket: u128, truncate_vers: Option<u32>) -> RawExternalPacket {
    let header = FcmHeader {
        session_cid: U64::new(fcm_ratchet.get_cid()),
        target_cid: U64::new(target_cid),
        group_id: U64::new(group_id),
        ticket: U128::new(ticket),
        object_id: U32::new(object_id),
        ratchet_version: U32::new(fcm_ratchet.version())
    };

    let payload = FCMPayloadType::TruncateAck { truncate_vers };

    base64_packet(fcm_ratchet, &header, &payload)
}

pub fn craft_deregistered<Fcm: Ratchet>(fcm_ratchet: &Fcm, target_cid: u64, ticket: u128) -> RawExternalPacket {
    let header = FcmHeader {
        session_cid: U64::new(fcm_ratchet.get_cid()),
        target_cid: U64::new(target_cid),
        group_id: U64::new(0),
        ticket: U128::new(ticket),
        object_id: U32::new(0),
        ratchet_version: U32::new(fcm_ratchet.version())
    };

    let payload = FCMPayloadType::PeerDeregistered;

    base64_packet(fcm_ratchet, &header, &payload)
}

/// Send from the central node to the edge
pub fn craft_post_register<R: Ratchet>(base_static_ratchet: &R, ticket: u128, initial_cid: u64, transfer: FcmPostRegister, username: String) -> RawExternalPacket {
    let header = FcmHeader {
        session_cid: U64::new(base_static_ratchet.get_cid()),
        target_cid: U64::new(0), // required to be 0 b/c we want to use the base ratchet at the endpoints
        group_id: U64::new(initial_cid),
        ticket: U128::new(ticket),
        object_id: U32::new(0),
        ratchet_version: U32::new(base_static_ratchet.version())
    };

    let payload = FCMPayloadType::PeerPostRegister { transfer, username };

    base64_packet(base_static_ratchet, &header, &payload)
}

#[inline]
fn base64_packet<R: Ratchet>(ratchet: &R, header: &FcmHeader, packet_payload: &FCMPayloadType) -> RawExternalPacket {
    let mut packet = packet_buf(packet_payload);
    header.inscribe_into(&mut packet);
    packet_payload.serialize_into_buf(&mut packet).unwrap();

    ratchet.protect_message_packet(None, FCM_HEADER_BYTES, &mut packet).unwrap();

    base64::encode(packet).into()
}

#[inline]
fn packet_buf<T: SyncIO + Serialize>(input: &T) -> BytesMut {
    BytesMut::with_capacity(FCM_HEADER_BYTES + input.serialized_size().unwrap() + AES_GCM_GHASH_OVERHEAD)
}