//! A node's STUN servers are required configuration: `build` refuses a builder without a valid
//! list, for every node type, and there is no default to fall back on.

use crate::builder::node_builder::DefaultNodeBuilder;
use crate::prefabs::server::empty::EmptyKernel;
use crate::prelude::{NodeType, StunServersError};

fn refusal(node_type: NodeType, stun: Option<&[&str]>) -> String {
    let mut builder = DefaultNodeBuilder::default();
    let _ = builder.with_node_type(node_type);
    if let Some(stun) = stun {
        let _ = builder.with_stun_servers(stun.to_vec());
    }
    match builder.build(EmptyKernel::default()) {
        Ok(_) => panic!("a builder with STUN servers {stun:?} must be refused"),
        Err(err) => err.to_string(),
    }
}

fn node_types() -> [NodeType; 2] {
    [NodeType::Peer, NodeType::server("127.0.0.1:0").unwrap()]
}

#[test]
fn a_builder_without_stun_servers_is_refused() {
    for node_type in node_types() {
        assert_eq!(
            refusal(node_type, None),
            StunServersError::Missing.to_string()
        );
    }
}

#[test]
fn a_builder_with_too_few_stun_servers_is_refused() {
    for node_type in node_types() {
        let refused = refusal(node_type, Some(&["a.example:1", "b.example:2"]));
        assert_eq!(
            refused,
            StunServersError::TooFew { distinct: 2 }.to_string()
        );
    }
}

#[test]
fn a_builder_with_a_repeated_stun_server_is_refused() {
    for node_type in node_types() {
        let refused = refusal(
            node_type,
            Some(&["a.example:1", "b.example:2", "a.example:1"]),
        );
        let expected = StunServersError::Duplicate {
            entry: "a.example:1".into(),
        };
        assert_eq!(refused, expected.to_string());
    }
}

#[test]
fn a_builder_with_an_unparseable_stun_server_is_refused() {
    for node_type in node_types() {
        let refused = refusal(node_type, Some(&["dummy1", "b.example:2", "c.example:3"]));
        assert!(
            refused.starts_with("STUN server \"dummy1\" is not a host:port endpoint"),
            "{refused}"
        );
    }
}

#[test]
fn a_builder_with_three_distinct_stun_servers_builds() {
    for node_type in node_types() {
        let mut builder = DefaultNodeBuilder::default();
        let _ = builder
            .with_node_type(node_type)
            .with_stun_servers(crate::test_common::LOCALHOST_STUN_SERVERS);
        drop(builder.build(EmptyKernel::default()).unwrap());
    }
}
