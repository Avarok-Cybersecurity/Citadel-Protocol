use std::fmt::{Display, Formatter};

/// Linear hole-punching
pub mod linear;

pub mod hole_punched_udp_socket_addr;

#[derive(Copy, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub enum NatTraversalMethod {
    UPnP,
    Method3,
    // none needed
    None
}

impl Display for NatTraversalMethod {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl NatTraversalMethod {
    pub fn into_byte(self) -> u8 {
        match self {
            NatTraversalMethod::UPnP => 0,
            NatTraversalMethod::Method3 => 3,
            NatTraversalMethod::None => 7
        }
    }

    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(NatTraversalMethod::UPnP),
            3 => Some(NatTraversalMethod::Method3),
            7 => Some(NatTraversalMethod::None),
            _ => None
        }
    }
}