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
                    //NatTraversalMethod::UPnP (UPnP lacks ipv6 support)
                    NatTraversalMethod::Method3
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