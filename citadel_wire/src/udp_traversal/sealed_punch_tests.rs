//! A hole punch carries its packets through the session's packet crypto in every build.
//!
//! `HolePunchConfigContainer::new` used to replace the provided functions with identity
//! functions under `localhost-testing`, so every CI punch ran in plaintext and the sealed
//! punch production runs was never exercised. These tests punch over loopback with a
//! stand-in seal: matching seals must connect, and seals that differ must not, which only
//! holds while the packets really pass through the container.

use super::UdpHolePuncher;
use crate::udp_traversal::linear::encrypted_config_container::HolePunchConfigContainer;
use bytes::BytesMut;
use citadel_io::tokio;
use netbeam::sync::network_endpoint::NetworkEndpoint;
use netbeam::sync::test_utils::create_streams_with_addrs_and_lag;
use std::time::Duration;

/// Long enough for one loopback punch; a mismatched pair spends three of these failing.
const ATTEMPT: Duration = Duration::from_secs(4);

/// A stand-in for the session's packet crypto, keyed by `key`: it opens only what a seal
/// with the same key produced, as the real decryptor opens only its own peer's packets.
fn sealed_with(key: u8) -> HolePunchConfigContainer {
    HolePunchConfigContainer::new(
        move |plaintext| {
            let mut sealed = BytesMut::from(&[key][..]);
            sealed.extend(plaintext.iter().map(|byte| byte ^ key));
            sealed
        },
        move |sealed| match sealed.split_first() {
            Some((&tag, body)) if tag == key => Some(body.iter().map(|byte| byte ^ key).collect()),
            _ => None,
        },
    )
}

async fn punch(endpoint: &NetworkEndpoint, key: u8) -> Result<(), String> {
    UdpHolePuncher::new_timeout(
        endpoint,
        sealed_with(key),
        crate::stun_servers::unanswered_loopback(),
        ATTEMPT,
    )
    .await
    .map(|_| ())
    .map_err(|e| e.to_string())
}

#[test]
fn the_container_uses_the_functions_it_was_given() {
    let container = sealed_with(0xC1);
    let sealed = container.generate_packet(b"syn");
    assert_ne!(
        &sealed[..],
        b"syn",
        "the punch packet went out in plaintext"
    );
    assert_eq!(
        container.decrypt_packet(&sealed).as_deref(),
        Some(&b"syn"[..])
    );
    assert_eq!(
        container.decrypt_packet(b"syn"),
        None,
        "plaintext was accepted"
    );
}

#[tokio::test]
async fn a_punch_between_matching_seals_connects() {
    citadel_logging::setup_log();
    let (a, b) = create_streams_with_addrs_and_lag(0).await;
    let (res_a, res_b) = tokio::join!(punch(&a, 0xC1), punch(&b, 0xC1));
    res_a.expect("A failed a sealed punch");
    res_b.expect("B failed a sealed punch");
}

#[tokio::test]
async fn a_punch_whose_peer_seals_differently_does_not_connect() {
    citadel_logging::setup_log();
    let (a, b) = create_streams_with_addrs_and_lag(0).await;
    let (res_a, res_b) = tokio::join!(punch(&a, 0xC1), punch(&b, 0x5A));
    assert!(
        res_a.is_err() && res_b.is_err(),
        "a punch connected although neither side could open the other's packets, so they \
         were not sealed: A={res_a:?} B={res_b:?}"
    );
}
