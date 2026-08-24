use super::from_hyper_error;
use crate::prefabs::client::single_connection::SingleClientServerConnectionKernel;
use crate::prefabs::client::DefaultServerConnectionSettingsBuilder;
use crate::prefabs::server::internal_service::InternalServiceKernel;
use crate::prelude::*;
use crate::test_common::TestBarrier;
use bytes::Bytes;
use citadel_io::tokio;
use citadel_logging::setup_log;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rstest::rstest;
use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

#[rstest]
#[timeout(Duration::from_secs(60))]
#[citadel_io::tokio::test]
async fn test_internal_service_http() {
    setup_log();
    let barrier = &TestBarrier::new(2);
    let success_count = &AtomicUsize::new(0);
    let server_listener = citadel_wire::socket_helpers::get_tcp_listener("0.0.0.0:0")
        .expect("Failed to get TCP listener");
    let server_bind_addr = server_listener.local_addr().unwrap();

    let server_kernel = InternalServiceKernel::new(|internal_server_communicator| async move {
        barrier.wait().await;

        async fn hello(_req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
            Ok(Response::new(Full::new(Bytes::from("Hello World!"))))
        }

        hyper::server::conn::http1::Builder::new()
            .serve_connection(
                TokioIo::new(internal_server_communicator),
                service_fn(hello),
            )
            .await
            .map_err(from_hyper_error)?;

        Ok(())
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
                |internal_server_communicator| async move {
                    barrier.wait().await;
                    // wait for the server
                    citadel_io::time::sleep(Duration::from_millis(500)).await;
                    let (mut request_sender, connection) =
                        hyper::client::conn::http1::handshake::<_, Full<Bytes>>(TokioIo::new(
                            internal_server_communicator,
                        ))
                        .await
                        .map_err(from_hyper_error)?;

                    // spawn a task to poll the connection and drive the HTTP state
                    drop(citadel_io::tokio::spawn(async move {
                        if let Err(e) = connection.await {
                            citadel_logging::error!(target: "citadel", "Error in connection: {e}");
                            std::process::exit(-1);
                        }
                    }));

                    // give time for task to spawn
                    citadel_io::time::sleep(Duration::from_millis(100)).await;
                    let request = Request::builder()
                        // We need to manually add the host header because SendRequest does not
                        .header("Host", "example.com")
                        .method("GET")
                        .body(Full::new(Bytes::new()))
                        .map_err(|err| {
                            citadel_io::error!(
                                citadel_io::ErrorCode::InternalServiceHyperError,
                                err.to_string()
                            )
                        })?;
                    let response = request_sender
                        .send_request(request)
                        .await
                        .map_err(from_hyper_error)?;
                    assert_eq!(response.status(), StatusCode::OK);

                    let body_bytes = response
                        .into_body()
                        .collect()
                        .await
                        .map_err(from_hyper_error)?
                        .to_bytes();
                    assert_eq!(&body_bytes, b"Hello World!" as &[u8]);
                    let _ = success_count.fetch_add(1, Ordering::SeqCst);

                    // To send via the same connection again, it may not work as it may not be ready,
                    // so we have to wait until the request_sender becomes ready. (requires tower)
                    // request_sender.ready().await.map_err(from_hyper_error)?;
                    Ok(())
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

    assert_eq!(success_count.load(Ordering::SeqCst), 1);
}
