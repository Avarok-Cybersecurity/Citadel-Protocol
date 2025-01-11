//! Internal Service Integration
//!
//! This module provides a network kernel that enables integration of internal services,
//! such as HTTP servers, within the Citadel Protocol network. It's particularly useful
//! for implementing web services that need to communicate over secure Citadel channels.
//!
//! # Features
//! - Internal service integration
//! - HTTP server support
//! - Custom service handlers
//! - Asynchronous processing
//! - Type-safe communication
//! - Automatic channel management
//! - Service lifecycle handling
//!
//! # Example
//! ```rust
//! use std::convert::Infallible;
//! use std::net::SocketAddr;
//! use citadel_sdk::prelude::*;
//! use hyper::{Response, Body, Server, Request};
//! use hyper::server::conn::AddrStream;
//! use hyper::service::{make_service_fn, service_fn};
//! use citadel_sdk::prefabs::server::internal_service::InternalServiceKernel;
//!
//! // Create a kernel with an HTTP server
//! let kernel = InternalServiceKernel::<_, _, StackedRatchet>::new(|comm| async move {
//!
//!     let make_svc = make_service_fn(|socket: &AddrStream| {
//!         let remote_addr = socket.remote_addr();
//!         async move {
//!             Ok::<_, Infallible>(service_fn(move |_: Request<Body>| async move {
//!                 Ok::<_, Infallible>(
//!                     Response::new(Body::from(format!("Hello, {}!", remote_addr)))
//!                 )
//!             }))
//!         }
//!     });
//!     
//!     // Start the HTTP server
//!     let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
//!     let server = Server::bind(&addr).serve(make_svc);
//!     // Run this server indefinitely
//!     if let Err(e) = server.await {
//!         eprintln!("server error: {}", e);
//!     }
//!
//!    Ok(())
//! });
//! ```
//!
//! # Important Notes
//! - Services run in isolated contexts
//! - Communication is bidirectional
//! - Supports HTTP/1.1 and HTTP/2
//! - Automatic error handling
//! - Resource cleanup on shutdown
//!
//! # Related Components
//! - [`NetKernel`]: Base trait for network kernels
//! - [`InternalServerCommunicator`]: Service communication
//! - [`ClientConnectListenerKernel`]: Connection handling
//! - [`NodeResult`]: Network event handling
//!

use crate::prefabs::shared::internal_service::InternalServerCommunicator;
use crate::prelude::*;
use std::future::Future;
use std::marker::PhantomData;

pub struct InternalServiceKernel<'a, F, Fut, R: Ratchet = StackedRatchet> {
    inner_kernel: Box<dyn NetKernel<R> + 'a>,
    _pd: PhantomData<fn() -> (&'a F, Fut)>,
}

impl<F, Fut, R: Ratchet> InternalServiceKernel<'_, F, Fut, R>
where
    F: Send + Copy + Sync + FnOnce(InternalServerCommunicator) -> Fut,
    Fut: Send + Sync + Future<Output = Result<(), NetworkError>>,
{
    pub fn new(on_create_webserver: F) -> Self {
        Self {
            _pd: Default::default(),
            inner_kernel: Box::new(
                super::client_connect_listener::ClientConnectListenerKernel::new(
                    move |connect_success| async move {
                        crate::prefabs::shared::internal_service::internal_service(
                            connect_success,
                            on_create_webserver,
                        )
                        .await
                    },
                ),
            ),
        }
    }
}

#[async_trait]
impl<F, Fut, R: Ratchet> NetKernel<R> for InternalServiceKernel<'_, F, Fut, R> {
    fn load_remote(&mut self, node_remote: NodeRemote<R>) -> Result<(), NetworkError> {
        self.inner_kernel.load_remote(node_remote)
    }

    async fn on_start(&self) -> Result<(), NetworkError> {
        self.inner_kernel.on_start().await
    }

    async fn on_node_event_received(&self, message: NodeResult<R>) -> Result<(), NetworkError> {
        self.inner_kernel.on_node_event_received(message).await
    }

    async fn on_stop(&mut self) -> Result<(), NetworkError> {
        self.inner_kernel.on_stop().await
    }
}

#[cfg(test)]
mod test {
    use crate::prefabs::client::single_connection::SingleClientServerConnectionKernel;
    use crate::prefabs::client::DefaultServerConnectionSettingsBuilder;
    use crate::prefabs::server::internal_service::InternalServiceKernel;
    use crate::prefabs::shared::internal_service::InternalServerCommunicator;
    use crate::prelude::*;
    use crate::test_common::TestBarrier;
    use citadel_io::tokio;
    use citadel_logging::setup_log;
    use hyper::client::conn::Builder;
    use hyper::server::conn::Http;
    use hyper::service::service_fn;
    use hyper::{Body, Error, Request, Response, StatusCode};
    use rstest::rstest;
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[derive(serde::Serialize, serde::Deserialize)]
    struct TestPacket {
        packet: Vec<u8>,
    }

    fn from_hyper_error(e: Error) -> NetworkError {
        NetworkError::msg(format!("Hyper error: {e}"))
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
            return Err(NetworkError::msg("Response did not match request"));
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
        let server_kernel =
            InternalServiceKernel::new(|mut internal_server_communicator| async move {
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
            .with_underlying_protocol(
                ServerUnderlyingProtocol::from_tokio_tcp_listener(server_listener).unwrap(),
            )
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

            async fn hello(_req: Request<Body>) -> Result<Response<Body>, Infallible> {
                Ok(Response::new(Body::from("Hello World!")))
            }

            Http::new()
                .serve_connection(internal_server_communicator, service_fn(hello))
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
                        citadel_io::tokio::time::sleep(Duration::from_millis(500)).await;
                        let (mut request_sender, connection) = Builder::new()
                            .handshake(internal_server_communicator)
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
                        citadel_io::tokio::time::sleep(Duration::from_millis(100)).await;
                        let request = Request::builder()
                            // We need to manually add the host header because SendRequest does not
                            .header("Host", "example.com")
                            .method("GET")
                            .body(Body::from(""))
                            .map_err(|err| NetworkError::msg(format!("hyper error: {err}")))?;
                        let response = request_sender.send_request(request).await.map_err(from_hyper_error)?;
                        assert_eq!(response.status(), StatusCode::OK);

                        let body_bytes = hyper::body::to_bytes(response.into_body()).await.map_err(from_hyper_error)?;
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
            .with_underlying_protocol(
                ServerUnderlyingProtocol::from_tokio_tcp_listener(server_listener).unwrap(),
            )
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
}
