//! The outbound mod contains the means necessary for returning [BaseHeaderConfig]'s or [Vec<PacketLayout0D>]'s. These are created under the BridgeHandler
//! before being dispatched outbound. For sake of organization and clarity, both HyperLAN and HyperWAN actions are differentiated

/// Contains the modules and subroutines for creating unique packet types within a HyperLAN
pub mod hyperlan;

/// For crafting packets that can be sent to either the HyperLAN or HyperWAN
pub mod either;

/// Organizes all the subroutines within this submodule
pub mod packet_crafter;