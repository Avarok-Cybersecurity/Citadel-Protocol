#![cfg(not(target_family = "wasm"))]
//! A request the node refuses must come back as an error, not as silence.
//!
//! Every `ProtocolRemoteTargetExt` method waits on `send_callback_subscription`,
//! whose stream ends only when the receiver is dropped — and the receiver is
//! what the waiting caller holds. So any refusal that fails to reach the
//! subscription is not a failure, it is a permanent park: one tokio task and one
//! callback-map entry, per request, for the life of the process.
//!
//! Two ways that happened, both fixed here and both exercised below.

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use citadel_io::tokio;
    use citadel_sdk::prefabs::client::single_connection::SingleClientServerConnectionKernel;
    use citadel_sdk::prefabs::client::ServerConnectionSettingsBuilder;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{server_info, server_test_node};
    use std::time::Duration;
    use uuid::Uuid;

    /// Long enough that a slow machine does not fail it, short enough that the
    /// defect (an unbounded wait) cannot pass it.
    const MUST_ANSWER_WITHIN: Duration = Duration::from_secs(20);

    /// A synchronous rejection inside the node's own outbound loop.
    ///
    /// `send_error` reported it as `InternalServerError { cid_opt: None }`, while
    /// the caller's listener was registered under `CallbackKey { ticket,
    /// session_cid: request.session_cid() }` — `Some(cid)` for PeerCommand,
    /// ReKey, SendObject, GroupBroadcastCommand, Deregister and Disconnect.
    /// `search_for_value` refuses to match a cid-less result against a listener
    /// that expects one, so the error went to the kernel's default handler and
    /// the subscription received nothing, ever.
    ///
    /// The zero-CID guard is the one rejection reachable without staging a
    /// broken session, and it takes the same `send_error` path as
    /// `SessionNotConnected` from `register_to_peer` and
    /// `DispatchSessionNotFound` from `create_group`.
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_node_side_rejection_is_returned_rather_than_awaited_forever() {
        citadel_logging::setup_log();
        let (server, server_addr) = server_info::<StackedRatchet>();

        let uuid = Uuid::new_v4();
        let username = format!("rej_{}", &uuid.to_string()[..8]);
        let (tx, rx) = citadel_io::tokio::sync::oneshot::channel();
        let tx = std::sync::Mutex::new(Some(tx));

        let client_kernel = SingleClientServerConnectionKernel::new(
            ServerConnectionSettingsBuilder::<StackedRatchet, _>::credentialed_registration(
                server_addr,
                username.as_str(),
                username.as_str(),
                "password123",
            )
            .with_udp_mode(UdpMode::Disabled)
            .build()
            .unwrap(),
            move |conn| {
                let tx = tx.lock().unwrap().take().unwrap();
                async move {
                    // session_cid 0 is refused by the node's outbound loop
                    // before the request reaches any session.
                    let request = NodeRequest::GroupBroadcastCommand(GroupBroadcastCommand {
                        session_cid: 0,
                        command: GroupBroadcast::ListGroupsFor { cid: 0 },
                    });
                    let mut subscription = conn
                        .remote
                        .remote()
                        .send_callback_subscription(request)
                        .await?;

                    let answered = citadel_io::tokio::time::timeout(
                        MUST_ANSWER_WITHIN,
                        futures::StreamExt::next(&mut subscription),
                    )
                    .await;

                    let _ = tx.send(match answered {
                        Ok(Some(result)) => result.into_result().err().map(|e| e.into_string()),
                        Ok(None) => Some("the subscription closed with no answer".to_string()),
                        Err(_) => None,
                    });
                    Ok(())
                }
            },
        );

        let client = DefaultNodeBuilder::default().build(client_kernel).unwrap();
        let result = citadel_io::tokio::select! {
            _ = server => panic!("the server ended first"),
            _ = client => panic!("the client kernel ended before answering"),
            answer = rx => answer.expect("the kernel dropped without answering"),
        };

        let message = result.expect(
            "the rejection never reached the caller — the subscription was still waiting when the \
             timeout fired, which is the defect",
        );
        assert!(
            message.contains("Zero") || message.contains("zero") || message.contains("cid"),
            "expected the node's own reason, got: {message}",
        );
    }

    /// A peer that hangs up mid-handshake, saying nothing at all.
    ///
    /// The case with no FAILURE packet to deliver: a server restart, a dropped
    /// network, a listener that accepts and closes. A regression guard rather
    /// than a control — it already passed before this branch, because a listener
    /// that closes immediately fails the client earlier, at "Unable to get first
    /// packet", rather than through a clean EOF in its read loop.
    ///
    /// The clean-EOF path IS reachable, just not from here: see
    /// `a_registration_the_server_refuses_returns_its_reason`, which reaches it
    /// whenever the final-reply flush loses its race.
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_peer_that_hangs_up_mid_handshake_is_reported() {
        citadel_logging::setup_log();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let listener = citadel_io::tokio::net::TcpListener::from_std(listener).unwrap();
        let hangup = citadel_io::tokio::spawn(async move {
            // Accept, then drop the socket without writing a byte.
            while let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }
        });

        let uuid = Uuid::new_v4();
        let username = format!("eof_{}", &uuid.to_string()[..8]);
        let client_kernel = SingleClientServerConnectionKernel::new(
            ServerConnectionSettingsBuilder::<StackedRatchet, _>::credentialed_registration(
                addr,
                username.as_str(),
                username.as_str(),
                "password123",
            )
            .with_udp_mode(UdpMode::Disabled)
            .build()
            .unwrap(),
            move |_conn| async move { Ok(()) },
        );

        let client = DefaultNodeBuilder::default().build(client_kernel).unwrap();
        let outcome = citadel_io::tokio::time::timeout(MUST_ANSWER_WITHIN, client).await;
        hangup.abort();

        let Ok(res) = outcome else {
            panic!(
                "the client never gave up on a peer that had already hung up — it was still \
                 waiting when the timeout fired, which is the defect"
            );
        };
        assert!(
            res.is_err(),
            "a handshake against a peer that hung up must not report success",
        );
    }

    /// A registration the SERVER refuses at stage 0.
    ///
    /// The client's FAILURE handler was guarded on `last_stage > STAGE0` — and
    /// `last_stage` is still its default 0 when stage 0 is answered, because only
    /// the STAGE1 handler advances it. So the packet was dropped with no
    /// `RegisterFailure`, the server then closed the stream, and a clean EOF
    /// resolves the client's read loop as `Ok` while emitting nothing.
    /// `remote.register()` waited on a subscription that would never speak again.
    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_registration_the_server_refuses_returns_its_reason() {
        citadel_logging::setup_log();

        let (server, server_addr) = server_test_node::<_, StackedRatchet>(
            citadel_sdk::prefabs::server::empty::EmptyKernel::default(),
            |builder| {
                let _ = builder.with_server_misc_settings(ServerMiscSettings {
                    // The setting the refusal hangs off.
                    allow_transient_connections: false,
                    ..Default::default()
                });
            },
        );

        // A transient registration against a server that forbids them. The
        // callback must never run; if it does, the kernel returns Ok and the
        // assertion below says so.
        let client_kernel = SingleClientServerConnectionKernel::new(
            ServerConnectionSettingsBuilder::<StackedRatchet, _>::transient(server_addr)
                .with_udp_mode(UdpMode::Disabled)
                .build()
                .unwrap(),
            move |_conn| async move { Ok(()) },
        );

        let client = DefaultNodeBuilder::default().build(client_kernel).unwrap();

        // Two layered fixes are under test here, and they fail differently.
        //
        // Returning AT ALL is the hard requirement, and it comes from the
        // provisional-EOF handling in `execute`: whatever happens on the wire,
        // the caller must not park forever. The timeout is its discriminator.
        //
        // Returning the SERVER's reason is the second, and it comes from the
        // final-reply flush plus the stage-0 FAILURE guard. Disabling either of
        // those leaves this test passing the first assertion and failing the
        // second with the generic message — which is how their controls read.
        //
        // Disabling BOTH is what hangs, and that is the combination the original
        // local controls missed: each fix alone looked unmeasurable because the
        // other one covered for it. CI on ubuntu found it, at the full 20s.
        let outcome = citadel_io::tokio::time::timeout(MUST_ANSWER_WITHIN, async {
            citadel_io::tokio::select! {
                _ = server => panic!("the server ended first"),
                res = client => res,
            }
        })
        .await;

        let Ok(res) = outcome else {
            panic!(
                "the refused registration never returned — the client was still waiting when the \
                 timeout fired, which is the defect"
            );
        };
        let Err(err) = res else {
            panic!("a refused registration must not report success — the callback ran");
        };
        let message = err.into_string();
        assert!(
            message.contains("Transient connections are not allowed"),
            "the server's reason must survive to the caller, got: {message}",
        );
    }
}

#[cfg(all(test, feature = "localhost-testing"))]
mod register_status_tests {
    //! A decline is an `Ok`, and every caller treated `Ok` as acceptance.
    //!
    //! `PeerRegisterStatus` derived nothing — no `Debug`, no `PartialEq` — so a
    //! caller could neither compare it nor log it, and all three real ones wrote
    //! `Ok(_)` or `let _ = ...?`. `peer_connection.rs` then issued a PostConnect
    //! to a peer that had just said no and waited out a 60s
    //! RemoteP2pConnectTimeout, reporting a timeout instead of the refusal the
    //! SDK already had in hand.
    //!
    //! These are unit tests of the type, deliberately: the call-site fix is a
    //! `refusal_reason()` check, and the thing worth pinning is that the type
    //! can express the distinction at all. A type with no derives is what made
    //! `Ok(_)` the path of least resistance.
    use citadel_sdk::prelude::results::PeerRegisterStatus;

    #[test]
    fn only_accepted_counts_as_accepted() {
        assert!(PeerRegisterStatus::Accepted.is_accepted());
        assert!(!PeerRegisterStatus::Declined.is_accepted());
        assert!(!PeerRegisterStatus::Failed { reason: None }.is_accepted());
    }

    #[test]
    fn a_refusal_always_carries_a_reason_and_an_acceptance_never_does() {
        assert_eq!(PeerRegisterStatus::Accepted.refusal_reason(), None);

        // Every non-acceptance must produce something a caller can show a user.
        // `Failed { reason: None }` is the case that would otherwise return an
        // empty string and read as "no reason given" to the code above it.
        for refused in [
            PeerRegisterStatus::Declined,
            PeerRegisterStatus::Failed { reason: None },
            PeerRegisterStatus::Failed {
                reason: Some("peer did not answer in time".to_string()),
            },
        ] {
            let reason = refused
                .refusal_reason()
                .expect("a refusal must give a reason");
            assert!(!reason.is_empty(), "empty reason for {refused:?}");
        }
    }

    #[test]
    fn the_protocols_own_reason_survives() {
        // The SDK maps PeerResponse::Timeout to Failed { reason: Some(..) }.
        // Losing that string in favour of a generic one would put the caller
        // back where it started.
        let timeout = PeerRegisterStatus::Failed {
            reason: Some("Timeout on register request. Peer did not accept in time".to_string()),
        };
        assert_eq!(
            timeout.refusal_reason().unwrap(),
            "Timeout on register request. Peer did not accept in time",
        );
    }

    #[test]
    fn the_status_can_be_compared_and_logged() {
        // The derives ARE the fix for the type. Without them a caller cannot
        // write anything but `Ok(_)`, which is exactly what every caller wrote.
        assert_eq!(PeerRegisterStatus::Accepted, PeerRegisterStatus::Accepted);
        assert_ne!(PeerRegisterStatus::Accepted, PeerRegisterStatus::Declined);
        assert!(format!("{:?}", PeerRegisterStatus::Declined).contains("Declined"));
    }
}
