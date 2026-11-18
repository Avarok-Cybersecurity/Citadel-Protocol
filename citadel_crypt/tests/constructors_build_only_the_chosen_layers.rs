//! A security level decides how many ratchet layers, and so how many key exchanges, a constructor
//! builds. A level arrives from the counterpart, so the constructors must turn away a level no
//! ratchet can carry instead of panicking, and Bob builds exactly the layers he chose: never
//! more, never fewer, whatever the transfer names.
use citadel_crypt::endpoint_crypto_container::EndpointRatchetConstructor;
use citadel_crypt::ratchets::stacked::constructor::AliceToBobTransfer;
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_crypt::ratchets::Ratchet;
use citadel_pqcrypto::constructor_opts::ConstructorOpts;
use citadel_types::crypto::{CryptoParameters, SecurityLevel};

type C = <StackedRatchet as Ratchet>::Constructor;
const PSKS: &[&[u8]] = &[b"psk"];

fn opts(level: SecurityLevel) -> Vec<ConstructorOpts> {
    ConstructorOpts::new_vec_init(Some(CryptoParameters::default()), level)
}

/// Alice's transfer at `level`, as bytes.
fn transfer_bytes(level: SecurityLevel) -> Vec<u8> {
    let alice = C::new_alice(opts(level), 7, 0).unwrap();
    bincode::serialize(&alice.stage0_alice().unwrap()).unwrap()
}

/// The same transfer with its stated level replaced by `Custom(stated)`. The level is a unit
/// variant (a 4-byte tag) followed by the cid (8) and the version (4).
fn restated(bytes: &[u8], stated: u8) -> AliceToBobTransfer {
    let level_at = bytes.len() - 16;
    let custom_tag = 5u32.to_le_bytes();
    let mut forged = bytes[..level_at].to_vec();
    forged.extend_from_slice(&custom_tag);
    forged.push(stated);
    forged.extend_from_slice(&bytes[level_at + 4..]);
    bincode::deserialize(&forged).unwrap()
}

#[test]
fn a_level_no_ratchet_can_carry_is_refused_without_a_panic() {
    for level in [SecurityLevel::Custom(254), SecurityLevel::Custom(255)] {
        assert!(C::new_alice(opts(level), 7, 0).is_none(), "{level:?}");
    }
}

#[test]
fn bob_refuses_a_transfer_stating_a_level_no_ratchet_can_carry() {
    let bytes = transfer_bytes(SecurityLevel::Reinforced);
    for stated in [254, 255] {
        let transfer = restated(&bytes, stated);
        let built = C::new_bob(7, opts(SecurityLevel::Reinforced), transfer, PSKS);
        assert!(built.is_none(), "Custom({stated})");
    }
}

#[test]
fn bob_builds_the_layers_he_chose_or_nothing() {
    let honest = transfer_bytes(SecurityLevel::High);
    let transfer: AliceToBobTransfer = bincode::deserialize(&honest).unwrap();
    assert!(C::new_bob(7, opts(SecurityLevel::High), transfer, PSKS).is_some());

    for bob in [SecurityLevel::Standard, SecurityLevel::Extreme] {
        let transfer: AliceToBobTransfer = bincode::deserialize(&honest).unwrap();
        assert!(
            C::new_bob(7, opts(bob), transfer, PSKS).is_none(),
            "{bob:?}"
        );
    }

    // The transfer's stated level must match the layers it carries, too.
    let transfer = restated(&honest, 9);
    assert!(C::new_bob(7, opts(SecurityLevel::Custom(9)), transfer, PSKS).is_none());
}
