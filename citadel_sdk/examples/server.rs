use citadel_io::tokio;
use citadel_sdk::prelude::*;
use std::net::SocketAddr;
use std::str::FromStr;

#[tokio::main]
async fn main() {
    citadel_logging::setup_log();
    let addr = get_env("CITADEL_SERVER_ADDR");
    let stun0 = get_env("STUN_0_ADDR");
    let stun1 = get_env("STUN_1_ADDR");
    let stun2 = get_env("STUN_2_ADDR");
    let empty_kernel = get_env_opt("EMPTY_KERNEL")
        .map(|r| r == "true")
        .unwrap_or(false);

    let server = if empty_kernel {
        Box::<citadel_sdk::prefabs::server::empty::EmptyKernel<StackedRatchet>>::default()
            as Box<dyn NetKernel<StackedRatchet>>
    } else {
        Box::new(
            citadel_sdk::prefabs::server::client_connect_listener::ClientConnectListenerKernel::new(
                |mut conn| async move {
                    let chan = conn.udp_channel_rx.take();
                    std::mem::forget(conn);
                    citadel_io::tokio::task::spawn(citadel_sdk::test_common::udp_mode_assertions(
                        UdpMode::Enabled,
                        chan,
                    ))
                    .await
                    .map_err(|err| NetworkError::generic(err.to_string()))?;
                    Ok(())
                },
            ),
        )
    };

    let _ = DefaultNodeBuilder::default()
        .with_link_manager(LinkManagerMode::Legacy)
        .with_node_type(NodeType::Server(
            SocketAddr::from_str(addr.as_str()).unwrap(),
        ))
        .with_stun_servers([stun0, stun1, stun2])
        .with_max_security_level(citadel_sdk::test_common::localhost_max_security_level())
        .with_path_policy(every_path_in_order())
        .with_server_limits(lab_limits())
        .build(server)
        .unwrap()
        .await
        .unwrap();
}

fn get_env_opt(key: &'static str) -> Option<String> {
    std::env::var(key).ok()
}

fn get_env(key: &'static str) -> String {
    if let Some(env) = get_env_opt(key) {
        env
    } else {
        panic!("Expected the env_var {key} set")
    }
}

/// The NAT lab's server policy: every path, in the default precedence, for every class.
fn every_path_in_order() -> PathPolicy {
    let rules = PathKind::ALL
        .into_iter()
        .map(|kind| PathRule {
            kind,
            enabled: true,
            attempt_timeout: std::time::Duration::from_secs(30),
            cost_weight: 1,
            classes: PathClasses::ALL,
        })
        .collect();
    PathPolicy::new(rules, PathClasses::NONE).expect("a valid path policy")
}

/// The NAT lab's server limits: a handful of lab clients, which register the legacy way.
fn lab_limits() -> ServerLimits {
    let nonzero = |n: usize| std::num::NonZeroUsize::new(n).expect("a positive limit");
    ServerLimits {
        provisional_per_ip: nonzero(32),
        provisional_total: nonzero(256),
        legacy_registration: LegacyRegistration::Accepted {
            concurrent_hashes: nonzero(4),
        },
        outbound_queued_per_stream: nonzero(256 * 1024 * 1024),
        outbound_queued_total: nonzero(1024 * 1024 * 1024),
        group_mail: GroupMailLimits {
            max_age: std::time::Duration::from_secs(7 * 24 * 3600),
            max_messages: nonzero(1_000),
            max_bytes: nonzero(16 * 1024 * 1024),
        },
    }
}
