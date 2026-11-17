//! An entropy bank arrives from the counterpart of a key exchange (and from storage). Its scramble
//! mappings drive every packet's position, so a bank whose mappings are not two permutations of
//! the port range is refused when it is decoded, and the packet math only ever sees a full table.
use citadel_crypt::packet_vector::generate_packet_vector;
use citadel_crypt::ratchets::entropy_bank::{EntropyBank, DRILL_RANGE};
use citadel_types::crypto::EncryptionAlgorithm;

/// The genuine encoding of a bank and the byte offset of its mappings' length prefix.
fn encoding() -> (Vec<u8>, usize) {
    let bank = EntropyBank::new(1, 0, EncryptionAlgorithm::AES_GCM_256).unwrap();
    let bytes = bank.serialize_to_vec().unwrap();
    let prefix = (DRILL_RANGE as u64).to_le_bytes();
    let offset = (0..bytes.len().saturating_sub(8))
        .find(|&off| bytes[off..off + 8] == prefix && off + 8 + 4 * DRILL_RANGE <= bytes.len())
        .expect("the mappings' length prefix is in the encoding");
    (bytes, offset)
}

/// The genuine encoding with its mappings replaced by `mappings`.
fn with_mappings(mappings: &[(u16, u16)]) -> Vec<u8> {
    let (bytes, offset) = encoding();
    let mut forged = bytes[..offset].to_vec();
    forged.extend_from_slice(&(mappings.len() as u64).to_le_bytes());
    for (a, b) in mappings {
        forged.extend_from_slice(&a.to_le_bytes());
        forged.extend_from_slice(&b.to_le_bytes());
    }
    forged.extend_from_slice(&bytes[offset + 8 + 4 * DRILL_RANGE..]);
    forged
}

fn identity() -> Vec<(u16, u16)> {
    (0..DRILL_RANGE as u16).map(|i| (i, i)).collect()
}

#[test]
fn a_bank_with_a_full_table_is_accepted_and_positions_packets() {
    let bank = EntropyBank::deserialize_from(with_mappings(&identity())).unwrap();
    assert_eq!(bank.get_multiport_width(), DRILL_RANGE);
    let vector = generate_packet_vector(DRILL_RANGE + 3, 0, &bank);
    assert_eq!(vector.wave_id, 1);
}

#[test]
fn a_bank_with_no_mappings_is_refused() {
    assert!(EntropyBank::deserialize_from(with_mappings(&[])).is_err());
}

#[test]
fn a_bank_with_too_few_or_too_many_mappings_is_refused() {
    let table = identity();
    assert!(EntropyBank::deserialize_from(with_mappings(&table[1..])).is_err());
    let mut long = table;
    long.push((0, 0));
    assert!(EntropyBank::deserialize_from(with_mappings(&long)).is_err());
}

#[test]
fn a_bank_with_a_port_outside_the_range_is_refused() {
    let mut table = identity();
    table[3].1 = u16::MAX;
    assert!(EntropyBank::deserialize_from(with_mappings(&table)).is_err());
}

#[test]
fn a_bank_with_a_repeated_port_is_refused() {
    let mut table = identity();
    table[3].0 = table[4].0;
    assert!(EntropyBank::deserialize_from(with_mappings(&table)).is_err());
}
