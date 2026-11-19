//! The P2P key profile: security level (stacked ratchet layers) and crypto parameters.

use crate::ids::SettingId;
use crate::merge::stronger_offer;
use crate::setting::{ApplyPath, Setting};
use citadel_types::crypto::{
    CryptoParameters, HeaderObfuscatorSettings, MaxSecurityLevel, SecrecyMode, SecurityLevel,
};
use citadel_types::proto::SessionSecuritySettings;
use citadel_types::utils::validate_crypto_params;
use serde::{Deserialize, Serialize};

/// What a key epoch is built with. The level is held normalised (`Custom(2)` is `High`) so two
/// profiles are equal exactly when they build the same ratchet.
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
#[serde(from = "KeyProfileWire", into = "KeyProfileWire")]
pub struct KeyProfile {
    level: SecurityLevel,
    params: CryptoParameters,
}

#[derive(Serialize, Deserialize)]
struct KeyProfileWire {
    level: SecurityLevel,
    params: CryptoParameters,
}

impl From<KeyProfileWire> for KeyProfile {
    fn from(wire: KeyProfileWire) -> Self {
        KeyProfile::new(wire.level, wire.params)
    }
}

impl From<KeyProfile> for KeyProfileWire {
    fn from(profile: KeyProfile) -> Self {
        KeyProfileWire {
            level: profile.level,
            params: profile.params,
        }
    }
}

impl KeyProfile {
    pub fn new(level: SecurityLevel, params: CryptoParameters) -> Self {
        KeyProfile {
            level: SecurityLevel::from(level.value()),
            params,
        }
    }

    /// The profile part of a session's settings (secrecy and header obfuscation alter packet
    /// framing and are never changed in band).
    pub fn of(settings: &SessionSecuritySettings) -> Self {
        KeyProfile::new(settings.security_level, settings.crypto_params)
    }

    pub fn level(&self) -> SecurityLevel {
        self.level
    }

    pub fn params(&self) -> CryptoParameters {
        self.params
    }

    fn identity(&self) -> (u8, u8) {
        (self.level.value(), u8::from(self.params))
    }

    /// The profile as a session offer whose framing fields are held equal, so that only what a
    /// profile carries can decide R-DIAL. They are a projection constant, not a setting: any one
    /// fixed pair gives the same result, because `stronger_offer` ranks them after level and suite
    /// only to break ties between otherwise identical offers.
    fn as_offer(&self) -> SessionSecuritySettings {
        SessionSecuritySettings {
            security_level: self.level,
            secrecy_mode: SecrecyMode::BestEffort,
            crypto_params: self.params,
            header_obfuscator_settings: HeaderObfuscatorSettings::Disabled,
        }
    }
}

impl PartialEq for KeyProfile {
    fn eq(&self, other: &Self) -> bool {
        self.identity() == other.identity()
    }
}

impl Eq for KeyProfile {}

impl Setting for KeyProfile {
    const ID: SettingId = SettingId::KEY_PROFILE;
    const PERSIST: bool = true;

    /// R-DIAL itself: the stronger offer, whichever side leads.
    fn merge(leader: &Self, loser: &Self) -> Self {
        KeyProfile::of(&stronger_offer(leader.as_offer(), loser.as_offer()))
    }

    fn is_downgrade(from: &Self, to: &Self) -> Option<bool> {
        Some(Self::merge(from, to) == *from && from != to)
    }

    /// A different KEM needs a fresh exchange from the static ratchet (owner decision D3).
    fn path(from: &Self, to: &Self) -> ApplyPath {
        if from.params.kem_algorithm == to.params.kem_algorithm {
            ApplyPath::InBandKeyEpoch
        } else {
            ApplyPath::Handshake
        }
    }

    /// The SDK's own rule for a usable suite. Every KEM the type can name is ML-KEM and every
    /// signature ML-DSA or FN-DSA, so a valid suite is a post-quantum one (P6).
    fn is_supported(&self) -> bool {
        validate_crypto_params(&self.params).is_ok()
    }

    /// Every layer is a key exchange and one more seal on every packet: a profile above the
    /// node's maximum security level is refused, from either side.
    type Bound = MaxSecurityLevel;

    fn exceeds(&self, bound: &MaxSecurityLevel) -> bool {
        !bound.admits(self.level)
    }
}
