//! The shape of a NAT without any address in it, for reporting which NAT pairs a path connects
//! (or fails to connect) without disclosing where either peer is. Defined here, beside the other
//! address-free protocol facts, so the pure link core (`citadel_link`) can name it without the
//! wire crate; `citadel_wire` re-exports it and classifies its `NatType` into it.

use serde::{Deserialize, Serialize};

/// How a NAT translates the IP address, as `IpTranslation` without its addresses.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IpTranslationClass {
    Identity,
    Constant,
    DeltaIndependentOffset,
    Unpredictable,
}

/// How a NAT translates the port, as `PortTranslation` without its ports or deltas.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PortTranslationClass {
    Identity,
    DeltaConstantOffset,
    DeltaIndependentOffset,
    Unpredictable,
}

/// The classification of a `NatType`: its translation models and whether IPv6 is enabled.
/// An unidentified NAT (identification failed) classifies as unpredictable in both.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NatClass {
    pub ip_translation: IpTranslationClass,
    pub port_translation: PortTranslationClass,
    pub ipv6_enabled: bool,
}
