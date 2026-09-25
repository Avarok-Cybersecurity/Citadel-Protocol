//! Shared scaffolding for group tests that disconnect and reconnect a node.
//!
//! Each node runs a [`GroupTestKernel`], which hands its body a receiver of every
//! unsolicited event (invitations, group channels opened by the protocol) so the
//! body can wait on them.

use citadel_io::tokio;
use citadel_io::tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use citadel_io::tokio::sync::Mutex;
use citadel_sdk::async_trait;
use citadel_sdk::prelude::*;
use citadel_sdk::test_common::wait_for_peers;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// How long a node may take, after a reconnect, to be back in the group and
/// receive a message. Generous for CI; each restore is a few relay round trips.
pub const REJOIN_DEADLINE: Duration = Duration::from_secs(30);
pub const PASSWORD: &str = "password123";

pub type Events = UnboundedReceiver<NodeResult<StackedRatchet>>;

pub struct GroupTestKernel<F> {
    handler: Mutex<Option<F>>,
    remote: Option<NodeRemote<StackedRatchet>>,
    events_tx: UnboundedSender<NodeResult<StackedRatchet>>,
    events_rx: Mutex<Option<Events>>,
}

impl<F> GroupTestKernel<F> {
    pub fn new(handler: F) -> Self {
        let (events_tx, events_rx) = unbounded_channel();
        Self {
            handler: Mutex::new(Some(handler)),
            remote: None,
            events_tx,
            events_rx: Mutex::new(Some(events_rx)),
        }
    }
}

#[async_trait]
impl<F, Fut> NetKernel<StackedRatchet> for GroupTestKernel<F>
where
    F: FnOnce(NodeRemote<StackedRatchet>, Events) -> Fut + Send + Sync,
    Fut: std::future::Future<Output = Result<(), NetworkError>> + Send,
{
    fn load_remote(&mut self, node_remote: NodeRemote<StackedRatchet>) -> Result<(), NetworkError> {
        self.remote = Some(node_remote);
        Ok(())
    }

    async fn on_start(&self) -> Result<(), NetworkError> {
        let remote = self.remote.clone().expect("remote loaded before start");
        let handler = self.handler.lock().await.take().expect("started once");
        let events = self.events_rx.lock().await.take().expect("started once");
        handler(remote, events).await
    }

    async fn on_node_event_received(
        &self,
        message: NodeResult<StackedRatchet>,
    ) -> Result<(), NetworkError> {
        let _ = self.events_tx.send(message);
        Ok(())
    }

    async fn on_stop(&mut self) -> Result<(), NetworkError> {
        Ok(())
    }
}

/// Register, connect, and mutually peer-register with `peer`. Both nodes must
/// call this: it synchronises on the test barrier twice.
pub async fn register_connect_and_befriend(
    remote: &NodeRemote<StackedRatchet>,
    server_addr: SocketAddr,
    username: &str,
    peer: &str,
) -> Result<CitadelClientServerConnection<StackedRatchet>, NetworkError> {
    let reg = remote
        .register_with_defaults(server_addr, username, username, PASSWORD)
        .await?;
    let conn = connect(remote, username).await?;
    wait_for_peers().await;
    let status = conn
        .propose_target(reg.cid, peer.to_string())
        .await?
        .register_to_peer()
        .await?;
    assert!(
        status.is_accepted(),
        "{username}'s peer registration refused: {:?}",
        status.refusal_reason()
    );
    wait_for_peers().await;
    Ok(conn)
}

pub async fn connect(
    remote: &NodeRemote<StackedRatchet>,
    username: &str,
) -> Result<CitadelClientServerConnection<StackedRatchet>, NetworkError> {
    remote
        .connect_with_defaults(AuthenticationRequest::credentialed(
            username.to_string(),
            PASSWORD,
        ))
        .await
}

pub async fn next_invitation(events: &mut Events) -> NodeResult<StackedRatchet> {
    tokio::time::timeout(REJOIN_DEADLINE, async {
        loop {
            match events.recv().await {
                Some(
                    evt @ NodeResult::GroupEvent(GroupEvent {
                        event: GroupBroadcast::Invitation { .. },
                        ..
                    }),
                ) => return evt,
                Some(_) => continue,
                None => panic!("event stream ended before the invitation"),
            }
        }
    })
    .await
    .expect("no group invitation arrived")
}

pub async fn next_group_channel(events: &mut Events, who: &str) -> GroupChannel {
    tokio::time::timeout(REJOIN_DEADLINE, async {
        while let Some(evt) = events.recv().await {
            if let NodeResult::GroupChannelCreated(GroupChannelCreated { channel, .. }) = evt {
                return channel;
            }
            log::info!(target: "citadel", "[{who}] event while waiting for a group channel: {evt:?}");
        }
        panic!("[{who}] event stream ended before a group channel opened");
    })
    .await
    .unwrap_or_else(|_| panic!("[{who}] was not back in the group: no group channel opened"))
}

pub async fn next_message_with_prefix(channel: &mut GroupChannel, prefix: &str) -> Vec<u8> {
    tokio::time::timeout(REJOIN_DEADLINE, async {
        loop {
            match channel.recv().await {
                Some(GroupBroadcastPayload::Message { payload, .. })
                    if payload.as_ref().starts_with(prefix.as_bytes()) =>
                {
                    return payload.as_ref().to_vec();
                }
                Some(other) => {
                    log::info!(target: "citadel", "group payload while waiting for {prefix}: {other:?}")
                }
                None => panic!("group channel closed while waiting for {prefix}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no '{prefix}' message arrived within the deadline"))
}

/// Send `prefix-N` every 500ms until `received` is set. A restore completes
/// asynchronously, and a message sent before the reader's Welcome lands cannot
/// be decrypted by it, so a single send would test the timing, not the restore.
pub async fn send_until(
    channel: &GroupChannel,
    prefix: &str,
    received: &AtomicBool,
) -> Result<(), NetworkError> {
    let started = std::time::Instant::now();
    let mut n = 0u32;
    while !received.load(Ordering::SeqCst)
        && started.elapsed() < REJOIN_DEADLINE + Duration::from_secs(5)
    {
        channel
            .send_message(SecBuffer::from(format!("{prefix}-{n}").into_bytes()))
            .await?;
        n += 1;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Ok(())
}

/// Run the server and two client nodes to completion, failing on timeout.
pub async fn run_pair<S, A, B, SX, AX, BX>(server: S, a: A, b: B)
where
    S: std::future::Future<Output = Result<SX, NetworkError>>,
    A: std::future::Future<Output = Result<AX, NetworkError>>,
    B: std::future::Future<Output = Result<BX, NetworkError>>,
{
    let clients = async move { futures::future::try_join(a, b).await.map(|_| ()) };
    let task = async move {
        tokio::select! {
            server_res = server => Err(NetworkError::msg(format!("Server ended prematurely: {:?}", server_res.map(|_| ())))),
            client_res = clients => client_res,
        }
    };
    let result = tokio::time::timeout(Duration::from_secs(150), task)
        .await
        .expect("test timed out");
    assert!(result.is_ok(), "test failed: {result:?}");
}
