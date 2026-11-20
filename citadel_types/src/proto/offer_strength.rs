//! Which of two competing connect offers a link takes.
//!
//! When two peers dial each other at the same moment, one link comes up and both dials are
//! answered by it. Whichever offer the protocol happened to process second used to decide the
//! link's security settings, so a side that raised its level could be connected at the other
//! side's lower one. [`stronger_offer`] is the single rule for that choice: the link takes the
//! stronger of the two offers, whichever order they arrive in.

use super::SessionSecuritySettings;
use crate::crypto::{HeaderObfuscatorSettings, KemAlgorithm, SecrecyMode};

/// The settings a link takes when two offers for it cross.
///
/// Every strength-ordered setting takes the stronger of the two offers' values: the security
/// level (by [`SecurityLevel::value`](crate::crypto::SecurityLevel::value)) and the secrecy mode
/// (`Perfect` over `BestEffort`). The crypto parameters and header obfuscation are a suite, not a
/// scale, so they are never mixed: they come whole from the leading offer -- the one with the
/// higher (level, secrecy, KEM strength) -- and a tie is broken by a fixed total order on the
/// suite. The result is therefore the same whichever argument is which.
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

/// R-DIAL 3, the client's check: whether `stamped` -- the settings a client is told to build a
/// link with, by the server's merge or the peer's accept -- gives up anything of `own`, the offer
/// the client made for that link. Servers stamp, clients verify: a stamp [`stronger_offer`] could
/// have produced from `own` and any other offer never falls short, so an honest server or peer
/// is never refused, and a client is never connected below its own offer.
pub fn falls_short_of(stamped: SessionSecuritySettings, own: SessionSecuritySettings) -> bool {
    leading_key(&stronger_offer(stamped, own)) != leading_key(&stamped)
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

/// The KEM's strength: the round-3 Kyber scheme below FIPS 203, and ML-KEM-1024 above
/// ML-KEM-768. No catch-all, so a new KEM is ranked when it is added.
fn kem_rank(kem: KemAlgorithm) -> u8 {
    match kem {
        KemAlgorithm::MlKem => 0,
        KemAlgorithm::MlKem768Fips203 => 1,
        KemAlgorithm::MlKem1024Fips203 => 2,
    }
}

/// An offer's place in the order [`stronger_offer`] leads by: level, secrecy, KEM, then the suite.
type LeadingKey = (u8, u8, u8, u8, (u8, u128));

fn leading_key(settings: &SessionSecuritySettings) -> LeadingKey {
    (
        settings.security_level.value(),
        secrecy_rank(settings.secrecy_mode),
        kem_rank(settings.crypto_params.kem_algorithm),
        u8::from(settings.crypto_params),
        obfuscator_key(settings.header_obfuscator_settings),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{CryptoParameters, EncryptionAlgorithm, KemAlgorithm, SecurityLevel};

    fn offer(level: SecurityLevel, secrecy: SecrecyMode) -> SessionSecuritySettings {
        SessionSecuritySettings {
            security_level: level,
            secrecy_mode: secrecy,
            crypto_params: CryptoParameters::from(KemAlgorithm::MlKem1024Fips203),
            header_obfuscator_settings: HeaderObfuscatorSettings::Disabled,
        }
    }

    fn fingerprint(s: SessionSecuritySettings) -> LeadingKey {
        leading_key(&s)
    }

    fn both_orders(a: SessionSecuritySettings, b: SessionSecuritySettings) -> [LeadingKey; 2] {
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
    fn a_merged_or_echoed_stamp_never_falls_short_of_either_offer() {
        let mut strong_suite = offer(SecurityLevel::High, SecrecyMode::BestEffort);
        strong_suite.crypto_params.kem_algorithm = KemAlgorithm::MlKem1024Fips203;
        let offers = [
            offer(SecurityLevel::Standard, SecrecyMode::BestEffort),
            offer(SecurityLevel::Extreme, SecrecyMode::BestEffort),
            offer(SecurityLevel::Standard, SecrecyMode::Perfect),
            offer(SecurityLevel::Custom(9), SecrecyMode::Perfect),
            strong_suite,
        ];
        for a in offers {
            assert!(!falls_short_of(a, a), "an echoed offer is its own stamp");
            for b in offers {
                let merged = stronger_offer(a, b);
                assert!(!falls_short_of(merged, a) && !falls_short_of(merged, b));
            }
        }
    }

    #[test]
    fn a_stamp_below_the_clients_own_offer_falls_short() {
        let extreme = offer(SecurityLevel::Extreme, SecrecyMode::BestEffort);
        let standard = offer(SecurityLevel::Standard, SecrecyMode::BestEffort);
        assert!(falls_short_of(standard, extreme));
        let perfect = offer(SecurityLevel::Standard, SecrecyMode::Perfect);
        assert!(falls_short_of(standard, perfect), "secrecy is ordered too");
        let mut mine = offer(SecurityLevel::High, SecrecyMode::BestEffort);
        mine.header_obfuscator_settings = HeaderObfuscatorSettings::EnabledWithKey(3);
        let other_suite = offer(SecurityLevel::High, SecrecyMode::BestEffort);
        assert!(
            falls_short_of(other_suite, mine),
            "at equal strength the suite is the merge's, and this one loses the tie"
        );
    }

    #[test]
    fn a_stamp_with_a_weaker_kem_falls_short_whatever_else_its_suite_ranks() {
        let mut mine = offer(SecurityLevel::High, SecrecyMode::BestEffort);
        mine.crypto_params.kem_algorithm = KemAlgorithm::MlKem1024Fips203;
        let mut round_three = mine;
        round_three.crypto_params.kem_algorithm = KemAlgorithm::MlKem;
        round_three.crypto_params.encryption_algorithm = EncryptionAlgorithm::Ascon80pq;
        assert!(u8::from(round_three.crypto_params) > u8::from(mine.crypto_params));
        assert!(falls_short_of(round_three, mine));
        for result in both_orders(mine, round_three) {
            assert_eq!(
                result,
                fingerprint(mine),
                "the merge keeps the stronger KEM"
            );
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
