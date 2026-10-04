//! A link the server sees as open after the client's end is gone, and what a test does with it.
//!
//! A proxy stands in for the network: `sever` closes every relayed link on the client's side
//! only, and abandons the server's side without a FIN or RST, so the server holds a session
//! nobody is at the other end of (a laptop changing networks, sleep and wake). `stall` abandons
//! both sides that way: neither end hears anything again, and both still think the link is up.

use citadel_io::tokio::io::{AsyncReadExt, AsyncWriteExt};
use citadel_io::tokio::net::{TcpListener, TcpStream};
use citadel_io::tokio::sync::Notify;
use citadel_sdk::prelude::*;
use citadel_sdk::remote_ext::results::PeerConnectSuccess;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use super::NodeState;

pub const PASSWORD: &str = "password123";
pub const SERVER_REFUSAL: &str = "Session Already Connected";
/// The keep-alive would take up to an hour; a displacement itself waits at most 5s.
pub const DISPLACED_WITHIN: Duration = Duration::from_secs(20);
/// How long a client may take to notice its own link is gone.
pub const LOCAL_TEARDOWN_WITHIN: Duration = Duration::from_secs(30);
/// How the client refuses a login while it still holds the account's session itself.
const LOCAL_SESSION_STILL_UP: &str = "Disconnect first before reconnecting";

/// What the client has sent on one link, up to [`RECORD_AT_MOST`] bytes.
pub type Recording = Arc<citadel_io::Mutex<Vec<u8>>>;

/// Bounds what the proxy records of each link.
pub const RECORD_AT_MOST: usize = 1024 * 1024;

/// Relays TCP to `upstream`, recording the first [`RECORD_AT_MOST`] bytes the client
/// sent on each link: all an on-path observer needs to replay a login.
pub struct SeveringProxy {
    pub addr: SocketAddr,
    sever: Arc<Notify>,
    stall: Arc<Notify>,
    client_streams: Arc<citadel_io::Mutex<Vec<Recording>>>,
}

impl SeveringProxy {
    pub async fn start(upstream: SocketAddr) -> Arc<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = Arc::new(Self {
            addr: listener.local_addr().unwrap(),
            sever: Arc::new(Notify::new()),
            stall: Arc::new(Notify::new()),
            client_streams: Arc::new(citadel_io::Mutex::new(Vec::new())),
        });
        let sever = proxy.sever.clone();
        let stall = proxy.stall.clone();
        let client_streams = proxy.client_streams.clone();
        citadel_io::tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let server = TcpStream::connect(upstream).await.unwrap();
                let recorded = Arc::new(citadel_io::Mutex::new(Vec::new()));
                client_streams.lock().push(recorded.clone());
                let cut = Cut {
                    sever: sever.clone(),
                    stall: stall.clone(),
                };
                citadel_io::tokio::spawn(relay(client, server, cut, recorded));
            }
        });
        proxy
    }

    /// Closes every current link on the client's side and abandons the server's side.
    pub fn sever(&self) {
        self.sever.notify_waiters();
    }

    /// Stops relaying on every current link without closing either side: a path that died
    /// silently. Links made afterwards relay as usual.
    pub fn stall(&self) {
        self.stall.notify_waiters();
    }

    /// What the client has sent so far on the most recent link.
    pub fn last_client_stream(&self) -> Vec<u8> {
        self.client_streams
            .lock()
            .last()
            .expect("no link was relayed")
            .lock()
            .clone()
    }
}

/// How a relayed link can be cut.
pub struct Cut {
    pub sever: Arc<Notify>,
    pub stall: Arc<Notify>,
}

pub async fn relay(client: TcpStream, server: TcpStream, cut: Cut, recorded: Recording) {
    let (mut client_read, mut client_write) = client.into_split();
    let (mut server_read, mut server_write) = server.into_split();
    let severed = cut.sever.notified();
    let stalled = cut.stall.notified();
    let upstream = async {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = client_read.read(&mut buf).await?;
            if n == 0 {
                return Ok::<_, std::io::Error>(());
            }
            {
                let mut recorded = recorded.lock();
                let room = RECORD_AT_MOST.saturating_sub(recorded.len());
                recorded.extend_from_slice(&buf[..n.min(room)]);
            }
            server_write.write_all(&buf[..n]).await?;
        }
    };
    let downstream = async {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = server_read.read(&mut buf).await?;
            if n == 0 {
                return Ok::<_, std::io::Error>(());
            }
            client_write.write_all(&buf[..n]).await?;
        }
    };
    let stall = citadel_io::tokio::select! {
        _ = upstream => return,
        _ = downstream => return,
        _ = severed => false,
        _ = stalled => true,
    };
    if stall {
        // Neither side is closed, read or written again.
        std::mem::forget((client_read, client_write, server_read, server_write));
        return;
    }
    // The client's side closes; the server's side is kept open and never read or
    // written again, so the server sees neither a FIN nor a RST.
    drop((client_read, client_write));
    std::mem::forget((server_read, server_write));
}

pub fn standard(force_login: bool) -> ConnectMode {
    ConnectMode::Standard { force_login }
}

pub async fn connect(
    remote: &NodeRemote<StackedRatchet>,
    username: &str,
    password: &str,
    connect_mode: ConnectMode,
) -> Result<CitadelClientServerConnection<StackedRatchet>, NetworkError> {
    remote
        .connect(
            AuthenticationRequest::credentialed(username.to_string(), password),
            connect_mode,
            Default::default(),
            None,
            Default::default(),
            Default::default(),
        )
        .await
}

/// The first answer to a login once this client has torn down its own side of a severed link.
/// Until then the client itself refuses, without asking the server.
pub async fn login_after_local_teardown(
    remote: &NodeRemote<StackedRatchet>,
    username: &str,
    password: &str,
    connect_mode: ConnectMode,
) -> Result<CitadelClientServerConnection<StackedRatchet>, NetworkError> {
    let deadline = citadel_io::tokio::time::Instant::now() + LOCAL_TEARDOWN_WITHIN;
    loop {
        match connect(remote, username, password, connect_mode).await {
            Err(err) if err.to_string().contains(LOCAL_SESSION_STILL_UP) => {
                assert!(
                    citadel_io::tokio::time::Instant::now() < deadline,
                    "the client never tore its own side down: {err}"
                );
                citadel_io::tokio::time::sleep(Duration::from_millis(250)).await;
            }
            answer => return answer,
        }
    }
}

/// Registers the two peers to each other and connects them.
pub async fn link_peers(
    conn: &CitadelClientServerConnection<StackedRatchet>,
    peer_username: &str,
) -> Result<PeerConnectSuccess<StackedRatchet>, NetworkError> {
    let handle = conn
        .propose_target(conn.cid, peer_username.to_string())
        .await?;
    let _ = handle.register_to_peer().await?;
    handle.connect_to_peer().await
}

pub fn usernames(tag: &str) -> (String, String) {
    let id = &Uuid::new_v4().to_string()[..8];
    (format!("{tag}a_{id}"), format!("{tag}b_{id}"))
}

/// How many times the server told this peer that a session it was linked to was torn
/// down (the notice `execute_session_with_safe_shutdown` sends each linked peer). The
/// peer's own "connection lost", from its P2P link dropping when the subject's client
/// went away, is not counted: the server had no part in it.
pub fn server_teardown_notices(state: &NodeState) -> usize {
    state
        .p2p_disconnect_responses
        .lock()
        .unwrap()
        .iter()
        .filter(|response| {
            matches!(response, Some(PeerResponse::Disconnected(reason)) if reason.ends_with("forcibly"))
        })
        .count()
}
