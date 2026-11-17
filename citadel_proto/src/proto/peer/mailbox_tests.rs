//! What an offline peer finds waiting at its next login: no connect request, and at most the cap
//! of invitations from any one sender. Driven through a real in-memory account backend and the
//! peer layer's own login drain.

use super::*;
use crate::proto::peer::peer_layer::{
    CitadelNodePeerLayer, MailboxTransfer, PeerConnectionType, PeerResponse,
};
use crate::proto::udp_packet_tests::connected_pair;
use citadel_crypt::endpoint_crypto_container::PeerSessionCrypto;
use citadel_crypt::ratchets::stacked::StackedRatchet;
use citadel_crypt::toolset::Toolset;
use citadel_io::tokio;
use citadel_types::crypto::SecurityLevel;
use citadel_user::account_manager::AccountManager;
use citadel_user::auth::proposed_credentials::ProposedCredentials;
use citadel_user::backend::BackendType;
use citadel_user::prelude::ConnectionInfo;

type Manager = AccountManager<StackedRatchet, StackedRatchet>;

async fn register(manager: &Manager, username: &str) -> u64 {
    let cid = manager
        .get_persistence_handler()
        .get_cid_by_username(username);
    let (ratchet, _) = connected_pair(SecurityLevel::Standard);
    let crypto = PeerSessionCrypto::new(Toolset::new(cid, ratchet), false);
    manager
        .register_impersonal_hyperlan_client_network_account(
            ConnectionInfo::new("127.0.0.1:25000").unwrap(),
            ProposedCredentials::transient(username),
            crypto,
        )
        .await
        .expect("account registered")
        .get_cid()
}

async fn backend() -> (Manager, u64, u64, u64) {
    let manager = Manager::new(BackendType::InMemory, None, None, None)
        .await
        .unwrap();
    let target = register(&manager, "offline-target").await;
    let sender = register(&manager, "sender").await;
    let other_sender = register(&manager, "other-sender").await;
    (manager, target, sender, other_sender)
}

fn connect_request(sender: u64, target: u64) -> PeerSignal {
    PeerSignal::PostConnect {
        peer_conn_type: PeerConnectionType::LocalGroupPeer {
            session_cid: sender,
            peer_cid: target,
        },
        ticket_opt: None,
        invitee_response: None,
        session_security_settings: Default::default(),
        udp_mode: Default::default(),
        session_password: None,
    }
}

fn invitation(sender: u64, target: u64) -> PeerSignal {
    PeerSignal::PostRegister {
        peer_conn_type: PeerConnectionType::LocalGroupPeer {
            session_cid: sender,
            peer_cid: target,
        },
        inviter_username: "sender".to_string(),
        invitee_username: None,
        ticket_opt: None,
        invitee_response: None::<PeerResponse>,
    }
}

/// What `target` receives when it next connects.
async fn delivered_at_login(manager: &Manager, target: u64) -> Vec<PeerSignal> {
    let peer_layer = CitadelNodePeerLayer::new(manager.get_persistence_handler().clone());
    match peer_layer.register_peer(target).await.unwrap() {
        None => Vec::new(),
        Some(MailboxTransfer::Signals(signals)) => signals,
    }
}

#[tokio::test]
async fn a_connect_request_to_an_offline_peer_is_never_mailed() {
    let (manager, target, sender, _) = backend().await;
    let pers = manager.get_persistence_handler();
    for _ in 0..50 {
        assert!(
            mail_from(pers, target, sender, connect_request(sender, target))
                .await
                .is_err()
        );
    }
    assert!(delivered_at_login(&manager, target).await.is_empty());
}

#[tokio::test]
async fn a_mailbox_refuses_a_sender_beyond_the_cap() {
    let (manager, target, sender, other_sender) = backend().await;
    let pers = manager.get_persistence_handler();
    // One at a time, as the peer layer's write lock serializes them in the server.
    let mut held = 0;
    for _ in 0..1_000 {
        if mail_from(pers, target, sender, invitation(sender, target))
            .await
            .is_ok()
        {
            held += 1;
        }
    }
    assert_eq!(held, MAX_MAILED_SIGNALS_PER_SENDER);

    // The cap is per sender: another sender's invitation is still held.
    mail_from(pers, target, other_sender, invitation(other_sender, target))
        .await
        .expect("another sender's invitation held");

    assert_eq!(
        delivered_at_login(&manager, target).await.len(),
        MAX_MAILED_SIGNALS_PER_SENDER + 1
    );
}

#[test]
fn mailing_never_holds_a_connect_request_and_caps_the_rest() {
    assert_eq!(mailing(&connect_request(1, 2), 0), Mailing::NeverMailed);
    assert_eq!(mailing(&invitation(1, 2), 0), Mailing::Mail);
    assert_eq!(
        mailing(&invitation(1, 2), MAX_MAILED_SIGNALS_PER_SENDER - 1),
        Mailing::Mail
    );
    assert_eq!(
        mailing(&invitation(1, 2), MAX_MAILED_SIGNALS_PER_SENDER),
        Mailing::SenderAtCap
    );
}

#[test]
fn a_key_names_only_its_own_sender() {
    let key = sub_key(42);
    assert!(is_from(&key, 42));
    assert!(!is_from(&key, 4));
    assert!(!is_from(&Uuid::new_v4().to_string(), 42));
}
