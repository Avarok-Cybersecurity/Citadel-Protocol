//! What each stage's digest, and so its signature, covers: every field its sender wrote, and every
//! field of the agreed `SessionSecuritySettings` -- the level, the secrecy mode, the whole crypto
//! suite (KEM, encryption including the ML-KEM hybrid, signature) and the header obfuscation. A
//! relay that rewrites any of them in flight leaves a Stage0 its signature no longer matches.

use super::super::*;
use citadel_types::crypto::{
    EncryptionAlgorithm, HeaderObfuscatorSettings, KemAlgorithm, SecrecyMode, SecurityLevel,
    SigAlgorithm,
};

fn settings() -> SessionSecuritySettings {
    crate::proto::misc::session_security_settings::default_session_security_settings()
}

/// The default settings with one field changed, for each field there is.
fn each_field_changed() -> Vec<SessionSecuritySettings> {
    let changed = |change: fn(&mut SessionSecuritySettings)| {
        let mut settings = settings();
        change(&mut settings);
        settings
    };
    vec![
        changed(|s| s.security_level = SecurityLevel::High),
        changed(|s| s.secrecy_mode = SecrecyMode::Perfect),
        changed(|s| s.crypto_params.kem_algorithm = KemAlgorithm::MlKem),
        changed(|s| s.crypto_params.encryption_algorithm = EncryptionAlgorithm::MlKemHybrid),
        changed(|s| s.crypto_params.sig_algorithm = SigAlgorithm::FnDsa512),
        changed(|s| s.header_obfuscator_settings = HeaderObfuscatorSettings::Enabled),
    ]
}

#[test]
fn the_stage0_digest_covers_every_field_of_the_agreed_settings() {
    let base = stage0_digest(b"kem", settings(), UdpMode::Disabled, Ticket(1));
    for changed in each_field_changed() {
        let other = stage0_digest(b"kem", changed, UdpMode::Disabled, Ticket(1));
        assert_ne!(base, other, "{changed:?} leaves the digest unchanged");
    }
    for other in [
        stage0_digest(b"keM", settings(), UdpMode::Disabled, Ticket(1)),
        stage0_digest(b"kem", settings(), UdpMode::Enabled, Ticket(1)),
        stage0_digest(b"kem", settings(), UdpMode::Disabled, Ticket(2)),
    ] {
        assert_ne!(base, other);
    }
}

#[test]
fn the_stage1_digest_covers_what_the_responder_wrote() {
    let base = stage1_digest(b"kem", true, Ticket(1));
    for other in [
        stage1_digest(b"keM", true, Ticket(1)),
        stage1_digest(b"kem", false, Ticket(1)),
        stage1_digest(b"kem", true, Ticket(2)),
    ] {
        assert_ne!(base, other);
    }
}
