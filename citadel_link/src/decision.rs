//! The settings-change decision (§4): given the settings a link holds, the value the negotiator
//! agreed and what both ends support, how the link carries the change out. Pure and total.

use citadel_negotiation::settings::KeyProfile;
use citadel_types::crypto::{HeaderObfuscatorSettings, SecurityLevel};
use citadel_types::proto::{SessionSecuritySettings, UdpMode};

/// Everything about a link a settings change can touch: the session's security settings and the
/// transport facts that are not in them (§4.2 row 8).
#[derive(Copy, Clone, Debug)]
pub struct LinkSettings {
    pub security: SessionSecuritySettings,
    pub udp_mode: UdpMode,
}

/// The parameters of a new seal: the settings it is built with.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SealParams {
    pub settings: LinkSettings,
}

/// What both ends support, from the two `Hello`s: the intersection, so it is symmetric.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct PeerCaps {
    /// `NEGOTIATION_SINCE`: a steered ratchet round can raise the level in band.
    pub in_band: bool,
    /// `LINK_RESEAL_SINCE`: a new handshake can run on the live path.
    pub reseal: bool,
    /// `LINK_REATTACH_SINCE`: a live seal can move to a new path.
    pub reattach: bool,
}

impl PeerCaps {
    /// What two ends can do together.
    pub fn both(self, other: PeerCaps) -> PeerCaps {
        PeerCaps {
            in_band: self.in_band && other.in_band,
            reseal: self.reseal && other.reseal,
            reattach: self.reattach && other.reattach,
        }
    }
}

/// How the per-message floor moves for a change that needs no new keys.
#[derive(Copy, Clone, Debug)]
pub enum FloorChange {
    /// The floor stays: the change is the sender's own behaviour (secrecy mode).
    None,
    /// The floor moves down to this level (a policy-accepted downgrade, D7).
    Lower(SecurityLevel),
}

/// Why a change needs a new path and a new seal.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ReestablishWhy {
    /// The peer cannot do the change in band or on the path (an older SDK).
    PeerLegacy,
    /// The change is to the path itself (UDP mode, transport).
    Transport,
}

/// How a link carries out one agreed change (§4.2).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SettingsDecision {
    /// Identical, or a change already in force.
    NoAction,
    /// No keys change; the message floor moves (or stays).
    LocalOnly { floor: FloorChange },
    /// A steered ratchet round appends layers: same incarnation, same path.
    InBandKeyEpoch(KeyProfile),
    /// A new handshake on the existing path: a new incarnation, no punch.
    ResealOnPath(SealParams),
    /// A new path (a punch) and a new seal.
    Reestablish { why: ReestablishWhy },
}

/// A canonical, comparable form of a header obfuscator setting.
pub(crate) fn obfuscator_key(settings: HeaderObfuscatorSettings) -> (u8, u128) {
    match settings {
        HeaderObfuscatorSettings::Disabled => (0, 0),
        HeaderObfuscatorSettings::Enabled => (1, 0),
        HeaderObfuscatorSettings::EnabledWithKey(key) => (2, key),
    }
}

impl LinkSettings {
    /// Every field in a comparable form; the level normalised (`Custom(2)` is `High`).
    fn key(&self) -> (u8, u8, u8, (u8, u128), u8) {
        let s = &self.security;
        (
            s.security_level.value(),
            s.secrecy_mode as u8,
            u8::from(s.crypto_params),
            obfuscator_key(s.header_obfuscator_settings),
            self.udp_mode as u8,
        )
    }
}

impl PartialEq for LinkSettings {
    fn eq(&self, other: &Self) -> bool {
        self.key() == other.key()
    }
}

impl Eq for LinkSettings {}

impl PartialEq for FloorChange {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (FloorChange::None, FloorChange::None) => true,
            (FloorChange::Lower(a), FloorChange::Lower(b)) => a.value() == b.value(),
            _ => false,
        }
    }
}

impl Eq for FloorChange {}
