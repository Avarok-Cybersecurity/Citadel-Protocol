use super::NatPacket;
use crate::udp_traversal::linear::encrypted_config_container::HolePunchConfigContainer;
use bytes::BytesMut;

/// Marks a sealed packet, so the stand-in decryptor accepts only what the sealer produced.
const SEAL_TAG: u8 = 0xC1;

/// A stand-in for the session's packet crypto: it refuses any input the sealer did not
/// produce, as the real decryptor refuses plaintext.
fn sealing_container() -> HolePunchConfigContainer {
    HolePunchConfigContainer::new(
        |plaintext| {
            let mut sealed = BytesMut::from(&[SEAL_TAG][..]);
            sealed.extend(plaintext.iter().map(|byte| byte ^ 0x5A));
            sealed
        },
        |sealed| match sealed.split_first() {
            Some((&SEAL_TAG, body)) => Some(body.iter().map(|byte| byte ^ 0x5A).collect()),
            _ => None,
        },
    )
}

/// The receive path decrypts every packet before reading it, so a `Check` sent outside the
/// encryptor is dropped at the peer as a decryption failure.
#[test]
fn a_check_packet_is_sealed_like_every_other_hole_punch_packet() {
    let container = sealing_container();
    let sent = NatPacket::Check.seal(&container).unwrap();
    let opened = container
        .decrypt_packet(&sent)
        .expect("the peer could not decrypt the Check packet");
    let packet: NatPacket = bincode::deserialize(&opened).unwrap();
    assert!(matches!(packet, NatPacket::Check));
}
