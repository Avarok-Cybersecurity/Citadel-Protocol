//! Shared fixtures: a policy, settings, NAT classes, link configs, a network and a world.
#![allow(dead_code)]

use std::time::Duration;

use citadel_link::schedule::{Net, World};
use citadel_link::{
    Backoff, ConnectionId, FlapPolicy, HealPolicy, LinkConfig, LinkKind, LinkPolicy, LinkSettings,
    NatClass, PathPlan, PathStage, PeerCaps, TimedStage,
};
use citadel_types::crypto::{
    CryptoParameters, HeaderObfuscatorSettings, KemAlgorithm, SecrecyMode, SecurityLevel,
};
use citadel_types::proto::{
    IpTranslationClass, PortTranslationClass, SessionSecuritySettings, UdpMode,
};

pub const S: u64 = 1000;

/// Every bound explicit (the type has no defaults). The values are the agent supervisor's
/// orders of magnitude, small enough that a schedule's clock stays readable.
pub fn policy() -> LinkPolicy {
    LinkPolicy {
        heal: HealPolicy {
            backoff: Backoff {
                first_wait: Duration::from_secs(1),
                factor: 2,
                max_wait: Duration::from_secs(30),
            },
            max_attempts: Some(6),
            give_up_after: None,
        },
        reattach_grace: Duration::from_secs(300),
        flap: FlapPolicy {
            window: Duration::from_secs(60),
            max_transitions: 3,
            hold: Duration::from_secs(20),
        },
        direct_rendezvous_budget: Duration::from_secs(5),
        rendezvous_deadline: Duration::from_secs(10),
        seal_deadline: Duration::from_secs(10),
        probe_interval: None,
        settings_deadline: Duration::from_secs(10),
        loser_redial_wait: Duration::from_secs(2),
        rearm: Backoff {
            first_wait: Duration::from_secs(5),
            factor: 2,
            max_wait: Duration::from_secs(300),
        },
    }
}

pub const ALL: PeerCaps = PeerCaps {
    in_band: true,
    reseal: true,
    reattach: true,
};

pub fn nat() -> NatClass {
    NatClass {
        ip_translation: IpTranslationClass::Constant,
        port_translation: PortTranslationClass::Identity,
        ipv6_enabled: false,
    }
}

/// The KEM these tests start from; any one will do, as only a change of KEM matters to them.
const BASE_KEM: KemAlgorithm = KemAlgorithm::MlKem1024Fips203;

pub fn security(level: SecurityLevel, kem: KemAlgorithm) -> SessionSecuritySettings {
    // The SDK's default suite: only the KEM varies in these tests (rationale for a test default).
    let crypto_params = CryptoParameters::from(kem);
    SessionSecuritySettings {
        security_level: level,
        secrecy_mode: SecrecyMode::BestEffort,
        crypto_params,
        header_obfuscator_settings: HeaderObfuscatorSettings::Disabled,
    }
}

pub fn settings(level: SecurityLevel) -> LinkSettings {
    LinkSettings {
        security: security(level, BASE_KEM),
        udp_mode: UdpMode::Enabled,
    }
}

/// The same level on another KEM: a change that needs a new handshake (D3).
pub fn other_kem(level: SecurityLevel) -> LinkSettings {
    use strum::IntoEnumIterator;
    let base = BASE_KEM as u8;
    let kem = KemAlgorithm::iter()
        .find(|k| *k as u8 != base)
        .expect("more than one KEM");
    LinkSettings {
        security: security(level, kem),
        udp_mode: UdpMode::Enabled,
    }
}

pub fn peer(local: u64, remote: u64, caps: PeerCaps) -> LinkConfig {
    LinkConfig {
        kind: LinkKind::Peer {
            local_cid: local,
            peer_cid: remote,
        },
        connection: ConnectionId(7),
        policy: policy(),
        caps,
        settings: settings(SecurityLevel::Standard),
        plan: None,
        local_nat: nat(),
    }
}

pub fn server(caps: PeerCaps) -> LinkConfig {
    LinkConfig {
        kind: LinkKind::Server,
        connection: ConnectionId(9),
        policy: policy(),
        caps,
        settings: settings(SecurityLevel::Standard),
        plan: Some(PathPlan::server(Duration::from_secs(4))),
        local_nat: nat(),
    }
}

pub fn direct_then_relay() -> PathPlan {
    PathPlan {
        stages: vec![
            TimedStage {
                stage: PathStage::Direct,
                timeout: Duration::from_secs(30),
            },
            TimedStage {
                stage: PathStage::Relay,
                timeout: Duration::from_secs(10),
            },
        ],
        turn_configured: false,
        direct_impossible: false,
    }
}

pub fn net() -> Net {
    Net {
        server_up: true,
        direct_works: true,
        turn_works: false,
        rebind_works: true,
        plan: direct_then_relay(),
    }
}

/// A pair with `caps`, A the Leader (CID 1), B the Loser (CID 2).
pub fn world(caps: PeerCaps) -> World {
    World::new(peer(1, 2, caps), peer(2, 1, caps), net())
}

/// A pair that is up: both started and run to rest.
pub fn up(caps: PeerCaps) -> World {
    let mut w = world(caps);
    w.apply(citadel_link::schedule::Action::Start(
        citadel_link::schedule::Side::A,
    ));
    w.apply(citadel_link::schedule::Action::Start(
        citadel_link::schedule::Side::B,
    ));
    w.run_to_quiescence(500).expect("quiescence");
    w.check().expect("both up");
    w
}
