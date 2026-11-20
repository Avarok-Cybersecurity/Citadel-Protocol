//! For the C2S link tests (lane L1): a clock the test moves by hand, and a TCP proxy that can
//! hold one connect's bytes, so a connect can be stopped at a stage of the test's choosing.

use super::{NodeState, ReconnectionTestKernel};
use citadel_io::tokio;
use citadel_io::tokio::io::{AsyncReadExt, AsyncWriteExt};
use citadel_io::tokio::net::{TcpListener, TcpStream};
use citadel_io::tokio::sync::{mpsc, oneshot};
use citadel_sdk::prelude::{DefaultNodeBuilder, NetworkError, NodeRemote, StackedRatchet};
use citadel_sdk::test_common::LOCALHOST_STUN_SERVERS;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use citadel_sdk::test_common::{server_on, ManualClock};

/// What the proxy does with one accepted connection, in accept order.
pub enum Plan {
    /// Accepts and says nothing: the client waits for the server's first packet.
    Silent,
    /// Forwards the server's bytes, and holds the client's until `release` fires (or forever).
    Hold {
        release: Option<oneshot::Receiver<()>>,
    },
    /// Forwards both ways.
    Forward,
}

/// What the proxy saw, by connection index.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Seen {
    Accepted(usize),
    /// The client sent its first bytes, which are being held.
    ClientSpoke(usize),
    /// The client closed its end.
    ClientClosed(usize),
}

/// Starts a proxy to `upstream`; one plan per connection it will accept.
pub async fn proxy(
    upstream: SocketAddr,
    plans: Vec<Plan>,
) -> (SocketAddr, mpsc::UnboundedReceiver<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (seen, events) = mpsc::unbounded_channel();
    drop(tokio::spawn(async move {
        for (n, plan) in plans.into_iter().enumerate() {
            let (client, _) = listener.accept().await.unwrap();
            let _ = seen.send(Seen::Accepted(n));
            drop(tokio::spawn(link(n, client, upstream, plan, seen.clone())));
        }
    }));
    (addr, events)
}

async fn link(
    n: usize,
    client: TcpStream,
    upstream: SocketAddr,
    plan: Plan,
    seen: mpsc::UnboundedSender<Seen>,
) {
    let (mut from_client, mut to_client) = client.into_split();
    let hold = match plan {
        Plan::Silent => {
            let mut sink = [0u8; 4096];
            while matches!(from_client.read(&mut sink).await, Ok(len) if len > 0) {}
            let _ = seen.send(Seen::ClientClosed(n));
            return;
        }
        Plan::Hold { release } => Some(release),
        Plan::Forward => None,
    };
    let (mut from_server, mut to_server) = TcpStream::connect(upstream).await.unwrap().into_split();
    drop(tokio::spawn(async move {
        let _ = tokio::io::copy(&mut from_server, &mut to_client).await;
    }));
    if let Some(release) = hold {
        let released = async move {
            match release {
                Some(release) => drop(release.await),
                None => std::future::pending::<()>().await,
            }
        };
        tokio::pin!(released);
        let mut held = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            tokio::select! {
                _ = &mut released => break,
                read = from_client.read(&mut buf) => match read {
                    Ok(len) if len > 0 => {
                        if held.is_empty() {
                            let _ = seen.send(Seen::ClientSpoke(n));
                        }
                        held.extend_from_slice(&buf[..len]);
                    }
                    _ => {
                        let _ = seen.send(Seen::ClientClosed(n));
                        return;
                    }
                },
            }
        }
        if to_server.write_all(&held).await.is_err() {
            return;
        }
    }
    let _ = tokio::io::copy(&mut from_client, &mut to_server).await;
    let _ = seen.send(Seen::ClientClosed(n));
}

/// The next event of the proxy that matches `want`, skipping the others.
pub async fn saw(events: &mut mpsc::UnboundedReceiver<Seen>, want: Seen) {
    while let Some(event) = events.recv().await {
        if event == want {
            return;
        }
    }
    panic!("the proxy ended before {want:?}");
}

/// Runs `handler` on a client node of `mode` beside a test server on a clock nobody moves; a hang
/// guard, not a latency assertion.
pub async fn with_client<F, Fut>(
    mode: citadel_sdk::prelude::LinkManagerMode,
    plans: Vec<Plan>,
    handler: F,
) where
    F: FnOnce(
            NodeRemote<StackedRatchet>,
            SocketAddr,
            tokio::sync::mpsc::UnboundedReceiver<Seen>,
        ) -> Fut
        + Send
        + Sync
        + 'static,
    Fut: Future<Output = Result<(), NetworkError>> + Send + 'static,
{
    citadel_logging::setup_log();
    // A server whose clock never moves: no server deadline can end the test's setup.
    let (server, server_addr) = server_on::<StackedRatchet>(ManualClock::new());
    let (proxy_addr, seen) = proxy(server_addr, plans).await;
    let kernel = ReconnectionTestKernel::new(
        Arc::new(NodeState::default()),
        move |remote: NodeRemote<StackedRatchet>, _| handler(remote, proxy_addr, seen),
    );
    let mut builder = DefaultNodeBuilder::default();
    let client = builder
        .with_link_manager(mode)
        .with_max_security_level(citadel_sdk::test_common::localhost_max_security_level())
        .with_stun_servers(LOCALHOST_STUN_SERVERS)
        .build(kernel)
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(120), async move {
        tokio::select! {
            res = server => Err(NetworkError::msg(format!("the server ended first: {:?}", res.map(|_| ())))),
            res = client => res.map(|_| ()),
        }
    })
    .await
    .expect("the test timed out");
    assert!(result.is_ok(), "{result:?}");
}
