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
//! use bytes::Bytes;
//! use citadel_sdk::prelude::*;
//! use http_body_util::Full;
//! use hyper::body::Incoming;
//! use hyper::service::service_fn;
//! use hyper::{Request, Response};
//! use hyper_util::rt::TokioIo;
//! use citadel_sdk::prefabs::server::internal_service::InternalServiceKernel;
//!
//! // Create a kernel with an HTTP server bridged over the secure channel
//! let kernel = InternalServiceKernel::<_, _, StackedRatchet>::new(|comm| async move {
//!
//!     let service = service_fn(|_: Request<Incoming>| async move {
//!         Ok::<_, Infallible>(
//!             Response::new(Full::new(Bytes::from("Hello!")))
//!         )
//!     });
//!
//!     // Serve HTTP/1.1 over the internal service communicator
//!     hyper::server::conn::http1::Builder::new()
//!         .serve_connection(TokioIo::new(comm), service)
//!         .await
//!         .map_err(|e| citadel_io::error!(
//!             citadel_io::ErrorCode::InternalServiceHyperError,
//!             e.to_string()
//!         ))?;
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
//! [`NetKernel`]: crate::prelude::NetKernel
//! [`InternalServerCommunicator`]: crate::prefabs::shared::internal_service::InternalServerCommunicator
//! [`ClientConnectListenerKernel`]: crate::prefabs::server::client_connect_listener::ClientConnectListenerKernel
//! [`NodeResult`]: crate::prelude::NodeResult

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

#[cfg(all(test, feature = "localhost-testing"))]
mod tests;
