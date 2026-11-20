//! R-DIAL (§4.4): the stronger-offer rule is a total order, the level dominates the suite, and the
//! key profile's merge is that rule, not a second copy of it.

mod common;

use citadel_negotiation::merge::stronger_offer;
use citadel_negotiation::settings::KeyProfile;
use citadel_negotiation::Setting;
use citadel_types::crypto::{
    CryptoParameters, HeaderObfuscatorSettings, KemAlgorithm, SecrecyMode, SecurityLevel,
};
use citadel_types::proto::SessionSecuritySettings;
use proptest::prelude::*;

fn pair() -> impl Strategy<Value = (SecurityLevel, CryptoParameters)> {
    (0u8..=8, prop::sample::select(common::suites()))
        .prop_map(|(level, params)| (SecurityLevel::from(level), params))
}

fn framing() -> impl Strategy<Value = (SecrecyMode, HeaderObfuscatorSettings)> {
    let secrecy = prop_oneof![Just(SecrecyMode::BestEffort), Just(SecrecyMode::Perfect)];
    let obfuscator = prop_oneof![
        Just(HeaderObfuscatorSettings::Disabled),
        Just(HeaderObfuscatorSettings::Enabled),
        any::<u128>().prop_map(HeaderObfuscatorSettings::EnabledWithKey),
    ];
    (secrecy, obfuscator)
}

fn offer(
    (level, params): (SecurityLevel, CryptoParameters),
    (secrecy, obfuscator): (SecrecyMode, HeaderObfuscatorSettings),
) -> SessionSecuritySettings {
    SessionSecuritySettings {
        security_level: level,
        secrecy_mode: secrecy,
        crypto_params: params,
        header_obfuscator_settings: obfuscator,
    }
}

/// `a` is at least as strong as `b`: the rule picks `a`'s profile out of the two.
fn at_least(
    a: (SecurityLevel, CryptoParameters),
    b: (SecurityLevel, CryptoParameters),
    f: (SecrecyMode, HeaderObfuscatorSettings),
) -> bool {
    KeyProfile::of(&stronger_offer(offer(a, f), offer(b, f))) == KeyProfile::new(a.0, a.1)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5_000))]

    #[test]
    fn rdial_total_order(a in pair(), b in pair(), c in pair(), f in framing()) {
        let same = |x: (SecurityLevel, CryptoParameters), y: (SecurityLevel, CryptoParameters)| KeyProfile::new(x.0, x.1) == KeyProfile::new(y.0, y.1);
        prop_assert!(at_least(a, b, f) || at_least(b, a, f), "total");
        if at_least(a, b, f) && at_least(b, a, f) {
            prop_assert!(same(a, b), "antisymmetric");
        }
        if at_least(a, b, f) && at_least(b, c, f) {
            prop_assert!(at_least(a, c, f), "transitive");
        }
        if a.0.value() > b.0.value() {
            prop_assert!(at_least(a, b, f), "the level dominates the suite");
        }
    }

    #[test]
    fn key_profile_merge_is_stronger_offer(a in pair(), b in pair(), f in framing()) {
        let rule = KeyProfile::of(&stronger_offer(offer(a, f), offer(b, f)));
        let (pa, pb) = (KeyProfile::new(a.0, a.1), KeyProfile::new(b.0, b.1));
        prop_assert_eq!(KeyProfile::merge(&pa, &pb), rule);
        prop_assert_eq!(KeyProfile::merge(&pb, &pa), rule);
    }
}

#[test]
fn rdial_extreme_with_a_weak_kem_beats_standard_with_a_strong_one() {
    let weak = CryptoParameters {
        kem_algorithm: KemAlgorithm::MlKem,
        ..common::BASE_PARAMS
    };
    let strong = CryptoParameters {
        kem_algorithm: KemAlgorithm::MlKem1024Fips203,
        ..common::BASE_PARAMS
    };
    let extreme = KeyProfile::new(SecurityLevel::Extreme, weak);
    let standard = KeyProfile::new(SecurityLevel::Standard, strong);
    for merged in [
        KeyProfile::merge(&extreme, &standard),
        KeyProfile::merge(&standard, &extreme),
    ] {
        assert_eq!(merged, extreme);
    }
}
