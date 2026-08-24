//! Shared ratchet-pair construction for the `citadel_crypt` criterion benches (SSOT — included by
//! each bench via `#[path = "common/mod.rs"] mod common;`).

use citadel_crypt::endpoint_crypto_container::EndpointRatchetConstructor;
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_crypt::ratchets::Ratchet;
use citadel_pqcrypto::constructor_opts::ConstructorOpts;
use citadel_types::crypto::{CryptoParameters, EncryptionAlgorithm, KemAlgorithm, SecurityLevel};

fn psks() -> Vec<Vec<u8>> {
    vec![b"Hello".to_vec(), b"World".to_vec()]
}

/// Build a connected (alice, bob) ratchet pair for `enc`/MlKem at `sec`.
pub fn make_ratchets(
    enc: EncryptionAlgorithm,
    sec: SecurityLevel,
) -> (StackedRatchet, StackedRatchet) {
    let params: CryptoParameters = KemAlgorithm::MlKem + enc;
    let params = Some(params);
    let psks = psks();

    let mut alice = <StackedRatchet as Ratchet>::Constructor::new_alice(
        ConstructorOpts::new_vec_init(params, sec),
        99,
        0,
    )
    .unwrap();
    let transfer = alice.stage0_alice().unwrap();
    let mut bob = <StackedRatchet as Ratchet>::Constructor::new_bob(
        99,
        ConstructorOpts::new_vec_init(params, sec),
        transfer,
        &psks,
    )
    .unwrap();
    let transfer = bob.stage0_bob().unwrap();
    alice.stage1_alice(transfer, &psks).unwrap();
    (alice.finish().unwrap(), bob.finish().unwrap())
}
