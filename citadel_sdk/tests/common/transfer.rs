//! A client uploading one file to a server that reports what its side of the transfer sees.

use citadel_io::tokio;
use citadel_io::tokio::sync::mpsc;
use citadel_sdk::prefabs::client::single_connection::SingleClientServerConnectionKernel;
use citadel_sdk::prefabs::client::DefaultServerConnectionSettingsBuilder;
use citadel_sdk::prelude::*;
use citadel_sdk::test_common::server_test_node;
use citadel_types::proto::ObjectTransferStatus;
use futures::StreamExt;
use std::future::Future;
use uuid::Uuid;

/// The file every upload here sends.
pub const UPLOADED_FILE: &str = "../resources/TheBridge.pdf";

/// Accepts every object offered to it and reports each status its handle yields.
struct ReportingServer {
    statuses: mpsc::UnboundedSender<ObjectTransferStatus>,
}

#[async_trait]
impl NetKernel<StackedRatchet> for ReportingServer {
    fn load_remote(&mut self, _remote: NodeRemote<StackedRatchet>) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn on_start(&self) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn on_node_event_received(
        &self,
        message: NodeResult<StackedRatchet>,
    ) -> Result<(), NetworkError> {
        if let NodeResult::ObjectTransferHandle(ObjectTransferHandle { mut handle, .. }) =
            message.into_result()?
        {
            handle
                .accept()
                .map_err(|err| NetworkError::msg(err.into_string()))?;
            while let Some(status) = handle.next().await {
                let _ = self.statuses.send(status);
            }
        }
        Ok(())
    }

    async fn on_stop(&mut self) -> Result<(), NetworkError> {
        Ok(())
    }
}

/// What the client's side of an upload is given: its session cid, the sender's handle, and the
/// receiver's statuses as the server reports them.
pub struct Upload {
    pub session_cid: u64,
    pub handle: ObjectTransferHandler,
    pub receiver: mpsc::UnboundedReceiver<ObjectTransferStatus>,
}

/// Connects a client to a fresh server, runs `before_send` with the client's session cid (to
/// place hooks keyed by it), offers [`UPLOADED_FILE`], and hands the upload to `check`. The
/// client's session stays up until `check` returns.
pub async fn upload<B, C, F>(before_send: B, check: C)
where
    B: FnOnce(u64) + Send + 'static,
    C: FnOnce(Upload) -> F + Send + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    let (statuses_tx, statuses_rx) = mpsc::unbounded_channel();
    let (server, server_addr) = server_test_node(
        ReportingServer {
            statuses: statuses_tx,
        },
        |_| {},
    );
    let settings = DefaultServerConnectionSettingsBuilder::transient_with_id(
        server_addr,
        Uuid::new_v4(),
        CertVerification::SelfSignedAccepted,
    )
    .disable_udp()
    .build()
    .unwrap();

    let start = std::sync::Mutex::new(Some((before_send, check, statuses_rx)));
    let client_kernel = SingleClientServerConnectionKernel::new(settings, move |connection| {
        let (before_send, check, receiver) = start.lock().unwrap().take().unwrap();
        async move {
            let remote = &connection.remote;
            let session_cid = remote.user().get_session_cid();
            before_send(session_cid);
            let mut subscription = remote
                .remote()
                .send_callback_subscription(NodeRequest::SendObject(SendObject {
                    source: Box::new(UPLOADED_FILE),
                    chunk_size: None,
                    session_cid,
                    v_conn_type: *remote.user(),
                    transfer_type: TransferType::FileTransfer,
                }))
                .await?;
            let handle = loop {
                match subscription.next().await.map(|e| e.into_result()) {
                    Some(Ok(NodeResult::ObjectTransferHandle(ObjectTransferHandle {
                        handle,
                        ..
                    }))) => break handle,
                    Some(Ok(other)) => log::warn!(target: "citadel", "ignoring {other:?}"),
                    other => panic!("subscription ended before a handle: {other:?}"),
                }
            };
            check(Upload {
                session_cid,
                handle,
                receiver,
            })
            .await;
            connection.shutdown_kernel().await
        }
    });

    let client = citadel_sdk::test_common::node_builder()
        .with_link_manager(LinkManagerMode::Legacy)
        .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
        .with_max_security_level(citadel_sdk::test_common::localhost_max_security_level())
        .build(client_kernel)
        .unwrap();

    tokio::select! {
        res = client => { res.expect("client node failed"); }
        res = server => panic!("server ended first: {:?}", res.map(|_| ())),
    }
}

/// The status that ended the sender's side of the transfer (`None` if its stream ended without
/// one), and every status before it.
pub async fn sender_verdict(
    handle: &mut ObjectTransferHandler,
) -> (Option<ObjectTransferStatus>, Vec<ObjectTransferStatus>) {
    let mut before = Vec::new();
    while let Some(status) = handle.next().await {
        if status.is_finished_type() {
            return (Some(status), before);
        }
        before.push(status);
    }
    (None, before)
}

/// The same for the receiver's side, as the server reports it.
pub async fn receiver_verdict(
    receiver: &mut mpsc::UnboundedReceiver<ObjectTransferStatus>,
) -> (Option<ObjectTransferStatus>, Vec<ObjectTransferStatus>) {
    let mut before = Vec::new();
    while let Some(status) = receiver.recv().await {
        if status.is_finished_type() {
            return (Some(status), before);
        }
        before.push(status);
    }
    (None, before)
}
