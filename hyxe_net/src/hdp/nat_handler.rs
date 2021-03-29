use hyxe_nat::udp_traversal::NatTraversalMethod;
use hyxe_nat::hypernode_type::HyperNodeType;

pub fn determine_initial_nat_method(_local_node_type: HyperNodeType, _remote_node_type: HyperNodeType) -> NatTraversalMethod {
    NatTraversalMethod::Method3 // for now, we assume hardest-case scenario
}