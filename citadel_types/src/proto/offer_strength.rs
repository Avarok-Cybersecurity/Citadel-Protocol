//! Which of two competing connect offers a link takes.
//!
//! When two peers dial each other at the same moment, one link comes up and both dials are
//! answered by it. Whichever offer the protocol happened to process second used to decide the
//! link's security settings, so a side that raised its level could be connected at the other
//! side's lower one. [`stronger_offer`] is the single rule for that choice: the link takes the
//! stronger of the two offers, whichever order they arrive in.

use super::SessionSecuritySettings;
use crate::crypto::{HeaderObfuscatorSettings, SecrecyMode};

/// The settings a link takes when two offers for it cross.
///
/// Every strength-ordered setting takes the stronger of the two offers' values: the security
/// level (by [`SecurityLevel::value`](crate::crypto::SecurityLevel::value)) and the secrecy mode
/// (`Perfect` over `BestEffort`). The crypto parameters and header obfuscation are a suite, not a
/// scale, so they are never mixed: they come whole from the leading offer -- the one with the
/// higher (level, secrecy) -- and a tie is broken by a fixed total order on the suite. The
/// result is therefore the same whichever argument is which.
pub fn stronger_offer(
    a: SessionSecuritySettings,
    b: SessionSecuritySettings,
) -> SessionSecuritySettings {
    let leader = if leading_key(&a) >= leading_key(&b) {
        a
    } else {
        b
    };
    SessionSecuritySettings {
        security_level: a
            .security_level
            .value()
            .max(b.security_level.value())
            .into(),
        secrecy_mode: stronger_secrecy(a.secrecy_mode, b.secrecy_mode),
        crypto_params: leader.crypto_params,
        header_obfuscator_settings: leader.header_obfuscator_settings,
    }
}

fn secrecy_rank(mode: SecrecyMode) -> u8 {
    match mode {
        SecrecyMode::BestEffort => 0,
        SecrecyMode::Perfect => 1,
    }
}

fn stronger_secrecy(a: SecrecyMode, b: SecrecyMode) -> SecrecyMode {
    if secrecy_rank(a) >= secrecy_rank(b) {
        a
    } else {
        b
    }
}

/// A total order over everything [`stronger_offer`] takes from one offer, so that a tie between
/// different suites resolves identically for both argument orders.
fn obfuscator_key(settings: HeaderObfuscatorSettings) -> (u8, u128) {
    match settings {
        HeaderObfuscatorSettings::Disabled => (0, 0),
        HeaderObfuscatorSettings::Enabled => (1, 0),
        HeaderObfuscatorSettings::EnabledWithKey(key) => (2, key),
    }
}

fn leading_key(settings: &SessionSecuritySettings) -> (u8, u8, u8, (u8, u128)) {
    (
        settings.security_level.value(),
        secrecy_rank(settings.secrecy_mode),
        u8::from(settings.crypto_params),
        obfuscator_key(settings.header_obfuscator_settings),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{CryptoParameters, KemAlgorithm, SecurityLevel};

    fn offer(level: SecurityLevel, secrecy: SecrecyMode) -> SessionSecuritySettings {
        SessionSecuritySettings {
            security_level: level,
            secrecy_mode: secrecy,
            crypto_params: CryptoParameters::default(),
            header_obfuscator_settings: HeaderObfuscatorSettings::Disabled,
        }
    }

    fn fingerprint(s: SessionSecuritySettings) -> (u8, u8, u8, (u8, u128)) {
        leading_key(&s)
    }

    fn both_orders(
        a: SessionSecuritySettings,
        b: SessionSecuritySettings,
    ) -> [(u8, u8, u8, (u8, u128)); 2] {
        [
            fingerprint(stronger_offer(a, b)),
            fingerprint(stronger_offer(b, a)),
        ]
    }

    #[test]
    fn the_higher_level_wins_in_either_order() {
        let weak = offer(SecurityLevel::Standard, SecrecyMode::BestEffort);
        let strong = offer(SecurityLevel::Extreme, SecrecyMode::BestEffort);
        for result in both_orders(weak, strong) {
            assert_eq!(result, fingerprint(strong));
        }
    }

    #[test]
    fn a_custom_level_is_ranked_by_its_value() {
        let custom = offer(SecurityLevel::Custom(9), SecrecyMode::BestEffort);
        let extreme = offer(SecurityLevel::Extreme, SecrecyMode::BestEffort);
        for result in both_orders(custom, extreme) {
            assert_eq!(result.0, 9);
        }
    }

    #[test]
    fn perfect_secrecy_wins_in_either_order() {
        let best_effort = offer(SecurityLevel::High, SecrecyMode::BestEffort);
        let perfect = offer(SecurityLevel::High, SecrecyMode::Perfect);
        for result in both_orders(best_effort, perfect) {
            assert_eq!(result, fingerprint(perfect));
        }
    }

    #[test]
    fn each_ordered_setting_takes_its_own_maximum() {
        let high_level = offer(SecurityLevel::Extreme, SecrecyMode::BestEffort);
        let perfect = offer(SecurityLevel::Standard, SecrecyMode::Perfect);
        for (level, secrecy, ..) in both_orders(high_level, perfect) {
            assert_eq!((level, secrecy), (SecurityLevel::Extreme.value(), 1));
        }
    }

    #[test]
    fn the_suite_comes_whole_from_the_leading_offer() {
        let mut strong = offer(SecurityLevel::Ultra, SecrecyMode::BestEffort);
        strong.crypto_params.kem_algorithm = KemAlgorithm::MlKem1024Fips203;
        strong.header_obfuscator_settings = HeaderObfuscatorSettings::EnabledWithKey(7);
        let mut weak = offer(SecurityLevel::Standard, SecrecyMode::BestEffort);
        weak.crypto_params.kem_algorithm = KemAlgorithm::MlKem768Fips203;
        weak.header_obfuscator_settings = HeaderObfuscatorSettings::Enabled;
        for result in both_orders(strong, weak) {
            assert_eq!(result, fingerprint(strong));
        }
    }

    #[test]
    fn a_tie_between_suites_resolves_the_same_in_either_order() {
        let mut a = offer(SecurityLevel::High, SecrecyMode::Perfect);
        a.crypto_params.kem_algorithm = KemAlgorithm::MlKem1024Fips203;
        let mut b = offer(SecurityLevel::High, SecrecyMode::Perfect);
        b.header_obfuscator_settings = HeaderObfuscatorSettings::EnabledWithKey(3);
        let [ab, ba] = both_orders(a, b);
        assert_eq!(ab, ba);
    }
}
