//! Internal kernel for serverless browser-to-browser connections.
//!
//! Adapts to whichever role (server/client) was assigned during signaling.
//! Used internally by [`BrowserConnection`](crate::net::BrowserConnection).

use crate::prefabs::ClientServerRemote;
use crate::prelude::*;
use crate::remote_ext::CitadelClientServerConnection;
use citadel_io::Mutex;
use citadel_proto::prelude::async_trait;

/// Internal kernel that adapts to the server or client role assigned
/// by the serverless signaling layer.
///
/// - **Client role** (`NodeType::Peer`): `on_start()` calls `remote.connect()`
///   with transient auth to the sentinel address `127.0.0.1:0`.
/// - **Server role** (`NodeType::Server`): `on_start()` returns `Ok(())`.
///   `on_node_event_received()` handles inbound `ConnectSuccess`.
///
/// In both cases, the established connection is sent through a oneshot channel
/// to the caller (typically `BrowserConnection::new()`).
pub(crate) struct ServerlessKernel<R: Ratchet> {
    conn_tx:
        Mutex<Option<citadel_io::tokio::sync::oneshot::Sender<CitadelClientServerConnection<R>>>>,
    node_remote: Option<NodeRemote<R>>,
}

impl<R: Ratchet> ServerlessKernel<R> {
    pub(crate) fn new(
        conn_tx: citadel_io::tokio::sync::oneshot::Sender<CitadelClientServerConnection<R>>,
    ) -> Self {
        Self {
            conn_tx: Mutex::new(Some(conn_tx)),
            node_remote: None,
        }
    }

    fn send_connection(&self, conn: CitadelClientServerConnection<R>) {
        if let Some(tx) = self.conn_tx.lock().take() {
            let _ = tx.send(conn);
        }
    }
}

#[async_trait]
impl<R: Ratchet> NetKernel<R> for ServerlessKernel<R> {
    fn load_remote(&mut self, server_remote: NodeRemote<R>) -> Result<(), NetworkError> {
        self.node_remote = Some(server_remote);
        Ok(())
    }

    async fn on_start(&self) -> Result<(), NetworkError> {
        let remote = self.node_remote.clone().unwrap();

        // Only the client role initiates a connect; the server role waits
        // for inbound connections via on_node_event_received.
        if *remote.local_node_type() == NodeType::Peer {
            let sentinel = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
            let auth = AuthenticationRequest::transient(uuid::Uuid::new_v4(), sentinel);
            let connect_success = remote
                .connect(
                    auth,
                    Default::default(),
                    UdpMode::Disabled,
                    None,
                    Default::default(),
                    None,
                )
                .await?;

            let conn_type = VirtualTargetType::LocalGroupServer {
                session_cid: connect_success.cid,
            };
            let client_server_remote = ClientServerRemote::new(
                conn_type,
                remote,
                connect_success.session_security_settings,
                None,
                None,
            );

            self.send_connection(CitadelClientServerConnection {
                channel: connect_success.channel,
                remote: client_server_remote,
                udp_channel_rx: connect_success.udp_channel_rx,
                services: connect_success.services,
                cid: connect_success.cid,
                session_security_settings: connect_success.session_security_settings,
            });

            // Keep the kernel alive until the caller drops BrowserConnection.
            futures::future::pending::<()>().await;
        }

        Ok(())
    }

    async fn on_node_event_received(&self, message: NodeResult<R>) -> Result<(), NetworkError> {
        // Server role: handle inbound ConnectSuccess from the client peer.
        if let NodeResult::ConnectSuccess(ConnectSuccess {
            ticket: _,
            session_cid: cid,
            remote_addr: _,
            is_personal: _,
            v_conn_type: conn_type,
            services,
            welcome_message: _,
            channel,
            udp_rx_opt: udp_channel_rx,
            session_security_settings,
        }) = message
        {
            let client_server_remote = ClientServerRemote::new(
                conn_type,
                self.node_remote.clone().unwrap(),
                session_security_settings,
                None,
                None,
            );

            self.send_connection(CitadelClientServerConnection {
                remote: client_server_remote,
                channel: Some(*channel),
                udp_channel_rx,
                services,
                cid,
                session_security_settings,
            });
        } else {
            log::trace!(target: "citadel", "[ServerlessKernel] Unhandled event: {message:?}");
        }

        Ok(())
    }

    async fn on_stop(&mut self) -> Result<(), NetworkError> {
        Ok(())
    }
}
