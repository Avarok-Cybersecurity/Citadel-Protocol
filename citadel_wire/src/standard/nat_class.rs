//! The shape of a [`NatType`] without any address in it, for reporting which NAT pairs a path
//! connects (or fails to connect) without disclosing where either peer is.

use super::nat_identification::{IpTranslation, NatType, PortTranslation};
use serde::{Deserialize, Serialize};

/// How a NAT translates the IP address, as [`IpTranslation`] without its addresses.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IpTranslationClass {
    Identity,
    Constant,
    DeltaIndependentOffset,
    Unpredictable,
}

/// How a NAT translates the port, as [`PortTranslation`] without its ports or deltas.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PortTranslationClass {
    Identity,
    DeltaConstantOffset,
    DeltaIndependentOffset,
    Unpredictable,
}

/// The classification of a [`NatType`]: its translation models and whether IPv6 is enabled.
/// An unidentified NAT (identification failed) classifies as unpredictable in both.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NatClass {
    pub ip_translation: IpTranslationClass,
    pub port_translation: PortTranslationClass,
    pub ipv6_enabled: bool,
}

impl NatType {
    /// This NAT's [`NatClass`].
    pub fn class(&self) -> NatClass {
        NatClass {
            ip_translation: match self.ip_translation {
                IpTranslation::Identity => IpTranslationClass::Identity,
                IpTranslation::Constant { .. } => IpTranslationClass::Constant,
                IpTranslation::DeltaIndependentOffset { .. } => {
                    IpTranslationClass::DeltaIndependentOffset
                }
                IpTranslation::Unpredictable => IpTranslationClass::Unpredictable,
            },
            port_translation: match self.port_translation {
                PortTranslation::Identity => PortTranslationClass::Identity,
                PortTranslation::DeltaConstantOffset { .. } => {
                    PortTranslationClass::DeltaConstantOffset
                }
                PortTranslation::DeltaIndependentOffset { .. } => {
                    PortTranslationClass::DeltaIndependentOffset
                }
                PortTranslation::Unpredictable => PortTranslationClass::Unpredictable,
            },
            ipv6_enabled: self.is_ipv6_enabled,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn a_class_carries_the_models_and_no_address() {
        let nat = NatType {
            ip_translation: IpTranslation::Constant {
                external: IpAddr::from([203, 0, 113, 9]),
            },
            port_translation: PortTranslation::DeltaConstantOffset { delta: 2 },
            ip_info: None,
            is_ipv6_enabled: true,
        };
        assert_eq!(
            nat.class(),
            NatClass {
                ip_translation: IpTranslationClass::Constant,
                port_translation: PortTranslationClass::DeltaConstantOffset,
                ipv6_enabled: true,
            }
        );
        assert!(!format!("{:?}", nat.class()).contains("203.0.113.9"));
        let unknown = NatType::default().class();
        assert_eq!(unknown.ip_translation, IpTranslationClass::Unpredictable);
        assert_eq!(
            unknown.port_translation,
            PortTranslationClass::Unpredictable
        );
    }
}
