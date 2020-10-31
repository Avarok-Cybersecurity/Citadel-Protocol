/*use std::collections::HashMap;

/// Maps a drill version to a NATMap
pub struct NATHandler {
    versions: HashMap<u32, NATMap>
}

/// A bijective HashMap
pub struct NATMap {
    // This maps a translated port punched through the firewall to the expected source port
    map_nat_to_src: HashMap<u16, u16>,
    map_src_to_nat: HashMap<u16, u16>
}

impl NATMap {
    /// The expected_src_port should be inscribed on WAVE packets on their flight here to preserve their value across the firewall
    pub fn new(multiport_range: usize) -> NATMap {
        Self { map_nat_to_src: HashMap::with_capacity(multiport_range), map_src_to_nat: HashMap::with_capacity(multiport_range) }
    }

    /// Inserts an entry. This should be called during the drill update phase. It updates both maps internally
    #[allow(unused_results)]
    pub fn insert_entry(&mut self, nat_src_port: u16, expected_src_port: u16) {
        self.map_nat_to_src.insert(nat_src_port, expected_src_port);
        self.map_src_to_nat.insert(expected_src_port, nat_src_port);
    }

    /// Map the nat port into the expected source port (for inbound packets)
    pub fn get_src_port_from(&self, nat_port: u16) -> Option<u16> {
        self.map_nat_to_src.get(&nat_port).cloned()
    }

    /// Map the src_port into the nat port (for outbound packets)
    pub fn get_nat_port_from_src(&self, src_port: u16) -> Option<u16> {
        self.map_src_to_nat.get(&src_port).cloned()
    }
}
*/

use hyxe_nat::udp_traversal::NatTraversalMethod;
use hyxe_nat::hypernode_type::HyperNodeType;

pub fn determine_initial_nat_method(local_node_type: HyperNodeType, remote_node_type: HyperNodeType) -> NatTraversalMethod {
    match local_node_type {
        // pure servers
        HyperNodeType::GloballyReachable => {
            match remote_node_type {
                HyperNodeType::GloballyReachable => {
                    NatTraversalMethod::None
                },

                HyperNodeType::BehindResidentialNAT => {
                    NatTraversalMethod::Method3
                },

                HyperNodeType::BehindSymmetricalNAT => {
                    NatTraversalMethod::Method3
                }
            }
        },

        // Home users
        HyperNodeType::BehindResidentialNAT => {
            match remote_node_type {
                HyperNodeType::GloballyReachable => {
                    NatTraversalMethod::UPnP
                },

                HyperNodeType::BehindResidentialNAT => {
                    // TODO: Handle pure distributive. For now, we wont
                    NatTraversalMethod::Method3
                },

                HyperNodeType::BehindSymmetricalNAT => {
                    NatTraversalMethod::Method3
                }
            }
        }

        // Cell-phone users. No UPnP; just use method3
        HyperNodeType::BehindSymmetricalNAT => {
            match remote_node_type {
                HyperNodeType::GloballyReachable => {
                    NatTraversalMethod::Method3
                },

                HyperNodeType::BehindResidentialNAT => {
                    NatTraversalMethod::Method3
                },

                HyperNodeType::BehindSymmetricalNAT => {
                    NatTraversalMethod::Method3
                }
            }
        }
    }
}