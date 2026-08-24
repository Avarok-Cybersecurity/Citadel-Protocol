mod http;

use crate::prefabs::client::single_connection::SingleClientServerConnectionKernel;
use crate::prefabs::client::DefaultServerConnectionSettingsBuilder;
use crate::prefabs::server::internal_service::InternalServiceKernel;
use crate::prefabs::shared::internal_service::InternalServerCommunicator;
use crate::prelude::*;
use crate::test_common::TestBarrier;
use citadel_io::tokio;
use citadel_logging::setup_log;
use rstest::rstest;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

#[derive(serde::Serialize, serde::Deserialize)]
struct TestPacket {
    packet: Vec<u8>,
}

fn from_hyper_error(e: hyper::Error) -> NetworkError {
    citadel_io::error!(
        citadel_io::ErrorCode::InternalServiceHyperError,
        e.to_string()
    )
}

async fn test_write_and_read_one_packet(
    barrier: &TestBarrier,
    internal_server_communicator: &mut InternalServerCommunicator,
    message: &Vec<u8>,
    success_count: &AtomicUsize,
) -> Result<(), NetworkError> {
    barrier.wait().await;
    let packet = TestPacket {
        packet: message.clone(),
    }
    .serialize_to_vector()
    .unwrap();
    let internal_server_communicator =
        write_one_packet(internal_server_communicator, packet).await?;
    let (_, response) =
        read_one_packet_as_framed::<_, TestPacket>(internal_server_communicator).await?;
    barrier.wait().await;

    if &response.packet != message {
        return Err(citadel_io::error!(
            citadel_io::ErrorCode::InternalServiceResponseMismatch
        ));
    }

    let _ = success_count.fetch_add(1, Ordering::SeqCst);
    barrier.wait().await;

    Ok(())
}

#[rstest]
#[timeout(Duration::from_secs(60))]
#[citadel_io::tokio::test]
async fn test_internal_service_basic_bytes() {
    setup_log();
    let barrier = &TestBarrier::new(2);
    let success_count = &AtomicUsize::new(0);
    let message = &(0..4096usize)
        .map(|r| (r % u8::MAX as usize) as u8)
        .collect::<Vec<u8>>();
    let server_listener = citadel_wire::socket_helpers::get_tcp_listener("0.0.0.0:0")
        .expect("Failed to get TCP listener");
    let server_bind_addr = server_listener.local_addr().unwrap();
    let server_kernel = InternalServiceKernel::new(|mut internal_server_communicator| async move {
        test_write_and_read_one_packet(
            barrier,
            &mut internal_server_communicator,
            message,
            success_count,
        )
        .await
    });

    let server_connection_settings =
        DefaultServerConnectionSettingsBuilder::transient(server_bind_addr)
            .build()
            .unwrap();

    let client_kernel = SingleClientServerConnectionKernel::new(
        server_connection_settings,
        |connection| async move {
            crate::prefabs::shared::internal_service::internal_service(
                connection,
                |mut internal_server_communicator| async move {
                    test_write_and_read_one_packet(
                        barrier,
                        &mut internal_server_communicator,
                        message,
                        success_count,
                    )
                    .await
                },
            )
            .await
        },
    );

    let client = DefaultNodeBuilder::default()
        .with_node_type(NodeType::Peer)
        .build(client_kernel)
        .unwrap();

    let server = DefaultNodeBuilder::default()
        .with_node_type(NodeType::Server(server_bind_addr))
        .with_underlying_protocol(ServerMode::OrderedReliable(
            NativeOrderedReliableConfig::from_tokio_listener(server_listener).unwrap(),
        ))
        .build(server_kernel)
        .unwrap();

    let res = citadel_io::tokio::select! {
        res0 = server => {
            citadel_logging::info!(target: "citadel", "Server exited");
            res0.map(|_|())
        },

        res1 = client => {
            citadel_logging::info!(target: "citadel", "Client exited");
            res1.map(|_|())
        }
    };

    res.unwrap();

    assert_eq!(success_count.load(Ordering::SeqCst), 2);
}
