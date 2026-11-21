//! `decide` (§4.2, §4.3): total, pure, the same on both ends, and every row of the table.

mod common;

use citadel_link::decision::decide;
use citadel_link::{FloorChange, LinkSettings, PeerCaps, ReestablishWhy, SettingsDecision};
use citadel_negotiation::settings::KeyProfile;
use citadel_types::crypto::{
    CryptoParameters, HeaderObfuscatorSettings, SecrecyMode, SecurityLevel,
};
use citadel_types::proto::{SessionSecuritySettings, UdpMode};
use common::*;
use proptest::prelude::*;

fn link_settings() -> impl Strategy<Value = LinkSettings> {
    let suites: Vec<CryptoParameters> = (0..=u8::MAX)
        .filter_map(|b| CryptoParameters::try_from(b).ok())
        .collect();
    let params = prop::sample::select(suites);
    let obfuscator = prop_oneof![
        Just(HeaderObfuscatorSettings::Disabled),
        Just(HeaderObfuscatorSettings::Enabled),
        (0u128..3).prop_map(HeaderObfuscatorSettings::EnabledWithKey),
    ];
    (0u8..=6, any::<bool>(), params, obfuscator, any::<bool>()).prop_map(
        |(level, perfect, crypto_params, header_obfuscator_settings, udp)| LinkSettings {
            security: SessionSecuritySettings {
                security_level: SecurityLevel::from(level),
                secrecy_mode: if perfect {
                    SecrecyMode::Perfect
                } else {
                    SecrecyMode::BestEffort
                },
                crypto_params,
                header_obfuscator_settings,
            },
            udp_mode: if udp {
                UdpMode::Enabled
            } else {
                UdpMode::Disabled
            },
        },
    )
}

fn caps() -> impl Strategy<Value = PeerCaps> {
    (any::<bool>(), any::<bool>(), any::<bool>()).prop_map(|(in_band, reseal, reattach)| PeerCaps {
        in_band,
        reseal,
        reattach,
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 4_096, ..ProptestConfig::default() })]

    /// Both ends hold the same `from` and `agreed` and compute `caps` as an intersection, so
    /// each computes the same decision with no message between them; and it never panics.
    #[test]
    fn decide_is_total_and_agrees_between_both_ends(
        from in link_settings(), agreed in link_settings(), own in caps(), peer in caps(),
    ) {
        let (a, b) = (own.both(peer), peer.both(own));
        prop_assert_eq!(a, b);
        prop_assert_eq!(decide(&from, &agreed, a), decide(&from, &agreed, b));
        let decision = decide(&from, &agreed, a);
        prop_assert_eq!(decision == SettingsDecision::NoAction, from == agreed);
        if from.udp_mode != agreed.udp_mode {
            prop_assert_eq!(decision, SettingsDecision::Reestablish { why: ReestablishWhy::Transport });
        }
    }

    /// The owner's rule: a downgrade never reconnects (§4.2 row 2).
    #[test]
    fn a_downgrade_never_reconnects(
        from in link_settings(),
        (high, low) in (1u8..=6).prop_flat_map(|h| (Just(h), 0..h)),
        all in caps(),
    ) {
        let mut from = from;
        from.security.security_level = SecurityLevel::from(high);
        let mut agreed = from;
        agreed.security.security_level = SecurityLevel::from(low);
        prop_assert_eq!(
            decide(&from, &agreed, all),
            SettingsDecision::LocalOnly { floor: FloorChange::Lower(agreed.security.security_level) }
        );
    }
}

fn with(f: impl FnOnce(&mut LinkSettings)) -> LinkSettings {
    let mut s = settings(SecurityLevel::High);
    f(&mut s);
    s
}

#[test]
fn every_row_of_the_table() {
    let from = settings(SecurityLevel::High);
    let none = PeerCaps {
        in_band: false,
        reseal: false,
        reattach: false,
    };
    let legacy = SettingsDecision::Reestablish {
        why: ReestablishWhy::PeerLegacy,
    };
    let higher = settings(SecurityLevel::Extreme);
    let kem = other_kem(SecurityLevel::High);
    let framing =
        with(|s| s.security.header_obfuscator_settings = HeaderObfuscatorSettings::Enabled);
    let perfect = with(|s| s.security.secrecy_mode = SecrecyMode::Perfect);
    let udp = with(|s| s.udp_mode = UdpMode::Disabled);
    let rows: [(&str, LinkSettings, PeerCaps, SettingsDecision); 11] = [
        ("1 equal", from, ALL, SettingsDecision::NoAction),
        (
            "1 Custom(2) is High",
            with(|s| s.security.security_level = SecurityLevel::Custom(2)),
            ALL,
            SettingsDecision::NoAction,
        ),
        (
            "2 lower",
            settings(SecurityLevel::Standard),
            none,
            SettingsDecision::LocalOnly {
                floor: FloorChange::Lower(SecurityLevel::Standard),
            },
        ),
        (
            "3 higher in band",
            higher,
            ALL,
            SettingsDecision::InBandKeyEpoch(KeyProfile::of(&higher.security)),
        ),
        ("4 higher, legacy peer", higher, none, legacy),
        (
            "5 secrecy",
            perfect,
            none,
            SettingsDecision::LocalOnly {
                floor: FloorChange::None,
            },
        ),
        (
            "6 KEM, reseal",
            kem,
            ALL,
            SettingsDecision::ResealOnPath(citadel_link::SealParams { settings: kem }),
        ),
        ("6 KEM, legacy", kem, none, legacy),
        (
            "7 framing, reseal",
            framing,
            ALL,
            SettingsDecision::ResealOnPath(citadel_link::SealParams { settings: framing }),
        ),
        ("7 framing, legacy", framing, none, legacy),
        (
            "8 transport",
            udp,
            ALL,
            SettingsDecision::Reestablish {
                why: ReestablishWhy::Transport,
            },
        ),
    ];
    for (row, agreed, caps, expected) in rows {
        assert_eq!(decide(&from, &agreed, caps), expected, "row {row}");
    }
}
