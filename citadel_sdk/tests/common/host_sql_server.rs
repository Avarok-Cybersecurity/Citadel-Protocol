//! A real server whose storage is host-provided SQL (a tenant's Durable Object), and a client of
//! it, for the host_sql RE-VFS suites.
#![allow(dead_code)] // each suite uses its own subset

use async_trait::async_trait;
use citadel_io::tokio;
use citadel_sdk::prefabs::client::single_connection::SingleClientServerConnectionKernel;
use citadel_sdk::prefabs::client::DefaultServerConnectionSettingsBuilder;
use citadel_sdk::prelude::*;
use citadel_sdk::test_common::server_test_node;
use futures::StreamExt;
use std::path::PathBuf;
use std::time::Duration;
use uuid::Uuid;

/// Long enough for a slow machine; an uploader left waiting (the defect) cannot pass it.
pub const MUST_FINISH_WITHIN: Duration = Duration::from_secs(60);
pub const SOURCE: &str = "../resources/TheBridge.pdf";
pub const VIRTUAL_PATH: &str = "/home/john.doe/TheBridge.pdf";

/// Accepts every transfer and outlives its failures, as the workspace server's kernel does
/// (the SDK's accept-all prefab ends the node on the first failed transfer).
#[derive(Default)]
pub struct StorageServerKernel;

#[async_trait]
impl NetKernel<StackedRatchet> for StorageServerKernel {
    fn load_remote(&mut self, _: NodeRemote<StackedRatchet>) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn on_start(&self) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn on_node_event_received(
        &self,
        message: NodeResult<StackedRatchet>,
    ) -> Result<(), NetworkError> {
        if let NodeResult::ObjectTransferHandle(ObjectTransferHandle { mut handle, .. }) = message {
            handle.accept()?;
            drop(tokio::spawn(async move {
                while let Some(status) = handle.next().await {
                    log::info!(target: "citadel", "server-side transfer status: {status:?}");
                }
            }));
        }
        Ok(())
    }

    async fn on_stop(&mut self) -> Result<(), NetworkError> {
        Ok(())
    }
}

pub async fn count(host: &HostSqlHandle, sql: &'static str) -> i64 {
    let rows = host
        .0
        .execute(vec![SqlStatement {
            sql,
            params: vec![],
        }])
        .await
        .unwrap();
    match rows[0][0][0] {
        SqlValue::Integer(n) => n,
        ref other => panic!("count was {other:?}"),
    }
}

/// Runs `body` as a client of a server storing into `host`, returning what `body` returned.
pub async fn against_server<F, Fut, T>(host: HostSqlHandle, body: F) -> T
where
    F: FnOnce(CitadelClientServerConnection<StackedRatchet>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = T> + Send,
    T: Send + 'static,
{
    citadel_logging::setup_log();
    let (server, server_addr) = server_test_node(StorageServerKernel, |b| {
        let _ = b.with_backend(BackendType::HostSql(host));
    });
    let (tx, rx) = tokio::sync::oneshot::channel();
    let tx = std::sync::Mutex::new(Some(tx));
    let settings =
        DefaultServerConnectionSettingsBuilder::transient_with_id(server_addr, Uuid::new_v4())
            .disable_udp()
            .build()
            .unwrap();
    let client_kernel = SingleClientServerConnectionKernel::new(settings, move |conn| async move {
        let out = body(conn).await;
        let _ = tx.lock().unwrap().take().unwrap().send(out);
        Ok(())
    });
    let client = DefaultNodeBuilder::default().build(client_kernel).unwrap();
    tokio::spawn(server);
    tokio::spawn(client);
    tokio::time::timeout(MUST_FINISH_WITHIN, rx)
        .await
        .expect("the client never finished: an upload or request was left waiting")
        .expect("the client kernel ended without reporting")
}

pub async fn push(
    conn: &CitadelClientServerConnection<StackedRatchet>,
    chunk_size: usize,
) -> Result<(), NetworkError> {
    push_from(conn, PathBuf::from(SOURCE), chunk_size).await
}

pub async fn push_from(
    conn: &CitadelClientServerConnection<StackedRatchet>,
    source: PathBuf,
    chunk_size: usize,
) -> Result<(), NetworkError> {
    conn.remote
        .remote_encrypted_virtual_filesystem_push_custom_chunking(
            source,
            VIRTUAL_PATH,
            chunk_size,
            SecurityLevel::Standard,
        )
        .await
}
