impl HyperNodeType {
    pub fn into_byte(self) -> u8 {
        match self {
            HyperNodeType::GloballyReachable => 0,
            HyperNodeType::BehindResidentialNAT => 1,
            HyperNodeType::BehindSymmetricalNAT => 2
        }
    }

    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(HyperNodeType::GloballyReachable),
            1 => Some(HyperNodeType::BehindResidentialNAT),
            2 => Some(HyperNodeType::BehindSymmetricalNAT),
            _ => None
        }
    }
}

/// Used for determining the proper action when loading the server
#[derive(Copy, Clone, PartialEq)]
pub enum HyperNodeType {
    /// A server with a static IP address will choose this option
    GloballyReachable,
    /// A client/server behind a residential NAT will choose this (will specially will start the UPnP handler, but the method for symmetrical NATs works too; UPnP is just faster)
    BehindResidentialNAT,
    /// A client/server behind a carrier-grade NAT. If user does not know, this should be the default (TODO. UPnP does not work here).
    BehindSymmetricalNAT
}

