//! Records written before the Argon2 sunset, as bytes the pre-sunset code (bcfb9390) wrote: the
//! post-quantum and transient ones read back unchanged, a client's Argon2 record reads as the
//! post-quantum client record, and a server's is refused by name.

use super::{POST_QUANTUM_VERSION, TRANSIENT_VERSION};
use crate::auth::pq::kem::{FactorKeypair, FactorSeed, SEED_LEN};
use crate::auth::pq::record::{KsfParams, PqAuthRecord};
use crate::auth::{DeclaredAuthenticationMode, PqAuthSide};
use crate::serialization::SyncIO;
use citadel_io::ErrorCode;
use sha3::Digest;

const ARGON_CLIENT: &str = "000000000500000000000000616c6963650500000000000000416c696365000000000200000000000000010210000000000000000303030303030303030303030303030308000000200000000004000001000000010000000000000004";
const ARGON_SERVER: &str = "000000000500000000000000616c6963650500000000000000416c69636501000000020000000000000001021000000000000000030303030303030303030303030303030800000020000000000400000100000001000000000000000420000000000000000909090909090909090909090909090909090909090909090909090909090909";
const TRANSIENT: &str =
    "010000000300000000000000626f620f00000000000000617574686c6573732e636c69656e74";
const PQ_CLIENT: &str = "0200000005000000000000006361726f6c05000000000000004361726f6c00000000";
/// SHA3-256 of the pre-sunset bytes of [`pq_server`], 3355 bytes long.
const PQ_SERVER_SHA3: &str = "eae6bace534af7b700dd8dd56d57b376cf3ba63b4d3ac3e0f0622cadc5be6424";

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn read(hex: &str) -> Result<DeclaredAuthenticationMode, citadel_io::NetworkError> {
    DeclaredAuthenticationMode::deserialize_from_vector(&bytes(hex))
}

fn pq_server() -> DeclaredAuthenticationMode {
    let ek = |n: u8| {
        FactorKeypair::derive(&FactorSeed::new([n; SEED_LEN]))
            .unwrap()
            .encapsulation_key()
            .clone()
    };
    let record = PqAuthRecord::new([5; 32], [6; 32], KsfParams::FLOOR, ek(1), vec![ek(2)], 7);
    DeclaredAuthenticationMode::PostQuantum {
        username: "carol".into(),
        full_name: "Carol".into(),
        side: PqAuthSide::Server(Box::new(record)),
    }
}

#[test]
fn a_post_quantum_server_record_is_written_byte_for_byte_as_before() {
    let written = pq_server().serialize_to_vector().unwrap();
    assert_eq!(written.len(), 3355);
    assert_eq!(hex(&sha3::Sha3_256::digest(&written)), PQ_SERVER_SHA3);
    let read = DeclaredAuthenticationMode::deserialize_from_vector(&written).unwrap();
    assert_eq!(read, pq_server());
}

#[test]
fn transient_and_post_quantum_client_records_read_and_write_as_before() {
    for (hex_form, expected) in [
        (
            TRANSIENT,
            DeclaredAuthenticationMode::Transient {
                username: "bob".into(),
                full_name: "authless.client".into(),
            },
        ),
        (
            PQ_CLIENT,
            DeclaredAuthenticationMode::PostQuantum {
                username: "carol".into(),
                full_name: "Carol".into(),
                side: PqAuthSide::Client,
            },
        ),
    ] {
        assert_eq!(read(hex_form).unwrap(), expected);
        assert_eq!(hex(&expected.serialize_to_vector().unwrap()), hex_form);
    }
}

#[test]
fn a_clients_argon2_record_reads_as_its_post_quantum_client_record() {
    let read = read(ARGON_CLIENT).unwrap();
    let expected = DeclaredAuthenticationMode::PostQuantum {
        username: "alice".into(),
        full_name: "Alice".into(),
        side: PqAuthSide::Client,
    };
    assert_eq!(read, expected);
}

#[test]
fn a_servers_argon2_record_is_refused_by_name() {
    let err = read(ARGON_SERVER).unwrap_err().into_string();
    let retired = citadel_io::error!(ErrorCode::AuthRecordRetired, "alice").into_string();
    assert!(err.contains(&retired), "{err}");
}

#[test]
fn the_versions_are_the_indices_written() {
    let index = |mode: &DeclaredAuthenticationMode| {
        let written = mode.serialize_to_vector().unwrap();
        u32::from_le_bytes(written[..4].try_into().unwrap())
    };
    assert_eq!(index(&read(TRANSIENT).unwrap()), TRANSIENT_VERSION);
    assert_eq!(index(&pq_server()), POST_QUANTUM_VERSION);
}
