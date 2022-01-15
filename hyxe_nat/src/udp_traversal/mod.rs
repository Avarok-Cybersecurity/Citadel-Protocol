use std::fmt::{Display, Formatter};
use serde::{Serialize, Deserialize};

/// Linear hole-punching
pub mod linear;

pub mod hole_punched_udp_socket_addr;

pub mod udp_hole_puncher;

pub mod multi;

#[derive(Copy, Clone, PartialEq, Debug, Serialize, Deserialize)]
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

#[derive(Serialize, Deserialize, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Copy, Clone, Default)]
pub struct HolePunchID(u16);

impl HolePunchID {
    pub(crate) fn next(&mut self) -> HolePunchID {
        *self = Self(self.0.wrapping_add(1));
        Self(self.0)
    }
}