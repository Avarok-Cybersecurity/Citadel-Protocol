//! Which code keeps a node's links is required configuration (§12.4): `build` refuses a builder
//! that names no `LinkManagerMode`, and a `Managed` one without a `LinkPolicy`.

use crate::builder::node_builder::DefaultNodeBuilder;
use crate::prefabs::server::empty::EmptyKernel;
use crate::prelude::{LinkManagerConfigError, LinkManagerMode, NodeType};

fn refusal(mode: Option<LinkManagerMode>) -> String {
    let mut builder = DefaultNodeBuilder::default();
    let _ = builder
        .with_node_type(NodeType::Peer)
        .with_stun_servers(crate::test_common::LOCALHOST_STUN_SERVERS);
    if let Some(mode) = mode {
        let _ = builder.with_link_manager(mode);
    }
    match builder.build(EmptyKernel::default()) {
        Ok(_) => panic!("a builder with link manager {mode:?} must be refused"),
        Err(err) => err.to_string(),
    }
}

#[test]
fn a_builder_without_a_link_manager_is_refused() {
    assert!(refusal(None).contains("with_link_manager"));
}

#[test]
fn a_managed_builder_without_a_policy_is_refused() {
    assert_eq!(
        refusal(Some(LinkManagerMode::Managed)),
        LinkManagerConfigError::MissingPolicy.to_string()
    );
}
