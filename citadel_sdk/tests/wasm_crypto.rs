//! WASM Integration Tests — Cryptographic Primitives
//!
//! Verifies that credential creation, SecBuffer, and crypto parameter
//! composition work correctly on wasm32-unknown-unknown.

#![cfg(target_family = "wasm")]

use citadel_sdk::prelude::*;
use wasm_bindgen_test::*;

/// Verify transient credential creation works on WASM.
#[wasm_bindgen_test]
fn test_transient_credentials() {
    let creds = ProposedCredentials::transient("wasm-user-001");
    assert!(creds.username().contains("wasm-user-001"));
}

/// Verify SecBuffer can hold and retrieve data on WASM.
#[wasm_bindgen_test]
fn test_secbuffer_operations() {
    let data = b"secret payload for wasm";
    let buf = SecBuffer::from(&data[..]);
    assert_eq!(buf.as_ref(), data);
}

/// Verify SecBuffer from string works on WASM.
#[wasm_bindgen_test]
fn test_secbuffer_from_string() {
    let buf = SecBuffer::from("password123");
    assert_eq!(buf.len(), 11);
}

/// Verify all CryptoParameters combinations build successfully on WASM.
#[wasm_bindgen_test]
fn test_crypto_params_combinations() {
    let encryptions = [
        EncryptionAlgorithm::AES_GCM_256,
        EncryptionAlgorithm::ChaCha20Poly_1305,
        EncryptionAlgorithm::Ascon80pq,
    ];
    let kems = [KemAlgorithm::MlKem];
    let levels = [
        SecurityLevel::Standard,
        SecurityLevel::Reinforced,
        SecurityLevel::High,
        SecurityLevel::Ultra,
        SecurityLevel::Extreme,
    ];

    for enc in &encryptions {
        for kem in &kems {
            for level in &levels {
                let result = SessionSecuritySettingsBuilder::default()
                    .with_crypto_params(*enc + *kem)
                    .with_security_level(*level)
                    .build();
                assert!(result.is_ok(), "Failed for {enc:?} + {kem:?} @ {level:?}");
            }
        }
    }

    // MlKemHybrid requires a SigAlgorithm — test separately
    let result = SessionSecuritySettingsBuilder::default()
        .with_crypto_params(
            EncryptionAlgorithm::MlKemHybrid + KemAlgorithm::MlKem + SigAlgorithm::MlDsa65,
        )
        .build();
    assert!(result.is_ok(), "Failed for MlKemHybrid + MlKem + MlDsa65");
}

/// Verify ProposedCredentials::transient works with custom names on WASM.
#[wasm_bindgen_test]
fn test_transient_credentials_custom() {
    let creds = ProposedCredentials::transient("custom-user-42");
    assert!(creds.username().contains("custom-user-42"));
}

/// Verify the default SessionSecuritySettings are sound on WASM.
#[wasm_bindgen_test]
fn test_default_session_security() {
    let settings = SessionSecuritySettings::default();
    // Default should use Standard security level
    assert!(matches!(settings.security_level, SecurityLevel::Standard));
}

/// Verify MonoRatchet type alias is available on WASM (used for FCM).
#[wasm_bindgen_test]
fn test_mono_ratchet_availability() {
    // MonoRatchet is available via prelude — verify the type exists
    fn _assert_ratchet<R: Ratchet>() {}
    _assert_ratchet::<MonoRatchet>();
    _assert_ratchet::<StackedRatchet>();
}
