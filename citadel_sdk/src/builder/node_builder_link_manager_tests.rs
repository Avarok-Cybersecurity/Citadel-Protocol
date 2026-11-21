//! Which code keeps a node's links is required configuration (§12.4): `build` refuses a builder
//! that names no `LinkManagerMode`, and a `Managed` mode cannot be made without a valid policy.

use crate::builder::node_builder::DefaultNodeBuilder;
use crate::prefabs::server::empty::EmptyKernel;
use crate::prelude::{
    LinkManagerMode, LinkPolicy, ManagedLinks, ManagedLinksError, NodeType, RuntimeClock,
};
use crate::test_common::{localhost_link_policy, localhost_max_security_level};
use citadel_io::ErrorCode;
use std::sync::Arc;
use std::time::Duration;

fn build(mode: Option<LinkManagerMode>) -> anyhow::Result<()> {
    let mut builder = DefaultNodeBuilder::default();
    let _ = builder
        .with_node_type(NodeType::Peer)
        .with_stun_servers(crate::test_common::LOCALHOST_STUN_SERVERS)
        .with_max_security_level(localhost_max_security_level());
    if let Some(mode) = mode {
        let _ = builder.with_link_manager(mode);
    }
    builder.build(EmptyKernel::default()).map(|_| ())
}

#[test]
fn a_builder_without_a_link_manager_is_refused() {
    let err = build(None).expect_err("a builder without a link mode must be refused");
    assert_eq!(
        err.downcast_ref::<citadel_io::NetworkError>()
            .expect("a typed error")
            .code(),
        ErrorCode::NodeLinkManagerMissing
    );
    assert!(build(Some(LinkManagerMode::Legacy)).is_ok());
}

#[test]
fn a_managed_mode_needs_a_valid_policy() {
    let clock = || Arc::new(RuntimeClock::new());
    let zero_grace = LinkPolicy {
        reattach_grace: Duration::ZERO,
        ..localhost_link_policy()
    };
    let err = ManagedLinks::new(clock(), zero_grace).expect_err("a zero grace is refused");
    assert!(matches!(err, ManagedLinksError::Policy(_)));
    let managed = ManagedLinks::new(clock(), localhost_link_policy()).expect("a valid policy");
    assert_eq!(
        managed.reattach_grace(),
        localhost_link_policy().reattach_grace
    );
    assert!(build(Some(LinkManagerMode::Managed(managed))).is_ok());
}
