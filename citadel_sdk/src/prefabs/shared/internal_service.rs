//! Internal Service Communication Layer
//!
//! This module provides the core functionality for integrating internal services
//! within the Citadel Protocol network. It enables bidirectional communication
//! between network services and the protocol layer.
//!
//! # Features
//! - Asynchronous communication channels
//! - Bidirectional message passing
//! - Automatic protocol conversion
//! - Error propagation
//! - Resource cleanup on shutdown
//! - Stream-based I/O interface
//!
//! # Example
//! ```rust,no_run
//! use citadel_sdk::prelude::*;
//! use citadel_sdk::prefabs::shared::internal_service::InternalServerCommunicator;
//! use futures::Future;
//!
//! async fn my_service(comm: InternalServerCommunicator) -> Result<(), NetworkError> {
//!     // Service implementation
//!     Ok(())
//! }
//! ```
//!
//! # Important Notes
//! - Services run in isolated contexts
//! - Communication is fully asynchronous
//! - Implements AsyncRead and AsyncWrite
//! - Automatic cleanup on drop
//! - Thread-safe message passing
//!
//! # Related Components
//! - [`CitadelClientServerConnection`]: Connection event data
//! - [`TargetLockedRemote`]: Remote target interface
//! - [`NetworkError`]: Error handling
//! - [`SecBuffer`]: Secure data handling
//!
//! [`CitadelClientServerConnection`]: crate::prelude::CitadelClientServerConnection
//! [`TargetLockedRemote`]: crate::prelude::TargetLockedRemote
//! [`NetworkError`]: crate::prelude::NetworkError
//! [`SecBuffer`]: crate::prelude::SecBuffer

use crate::prelude::{CitadelClientServerConnection, TargetLockedRemote};
use bytes::Bytes;
use citadel_io::tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use citadel_proto::prelude::NetworkError;
use citadel_proto::prelude::*;
use citadel_proto::re_imports::{StreamReader, UnboundedReceiverStream};
use citadel_types::crypto::SecBuffer;
use futures::StreamExt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

pub async fn internal_service<F, Fut, R: Ratchet>(
    connection: CitadelClientServerConnection<R>,
    service: F,
) -> Result<(), NetworkError>
where
    F: Send + Copy + Sync + FnOnce(InternalServerCommunicator) -> Fut,
    Fut: Send + Sync + Future<Output = Result<(), NetworkError>>,
{
    let remote = connection.remote.clone();
    let (tx_to_service, rx_from_kernel) = citadel_io::tokio::sync::mpsc::unbounded_channel();
    let (tx_to_kernel, mut rx_from_service) = citadel_io::tokio::sync::mpsc::unbounded_channel();

    let internal_server_communicator = InternalServerCommunicator {
        tx_to_kernel,
        rx_from_kernel: StreamReader::new(rx_from_kernel.into()),
    };

    let internal_server = service(internal_server_communicator);

    // each time a client connects, we will begin listening for messages.
    let (mut sink, mut stream) = connection.split();
    // from_proto forwards packets from the proto to the http server
    let from_proto = async move {
        while let Some(packet) = stream.next().await {
            // we receive a Citadel Protocol Packet. Now, we need to forward it to the webserver
            // the response below is the response of the internal server
            tx_to_service.send(Ok(packet.into_buffer().freeze()))?;
        }

        Ok(())
    };

    // from_webserver forwards packets from the internal server to the proto
    let from_webserver = async move {
        while let Some(packet) = rx_from_service.recv().await {
            sink.send(packet).await?;
        }

        Ok(())
    };

    let res = citadel_io::tokio::select! {
        res0 = from_proto => {
            res0
        },
        res1 = from_webserver => {
            res1
        },
        res2 = internal_server => {
            res2
        }
    };

    citadel_logging::warn!(target: "citadel", "Internal Server Stopped: {res:?}");

    remote.remote().shutdown().await?;
    res
}

pub struct InternalServerCommunicator {
    pub(crate) tx_to_kernel: citadel_io::tokio::sync::mpsc::UnboundedSender<SecBuffer>,
    pub(crate) rx_from_kernel:
        StreamReader<UnboundedReceiverStream<Result<Bytes, std::io::Error>>, Bytes>,
}

impl AsyncWrite for InternalServerCommunicator {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let len = buf.len();
        match self.tx_to_kernel.send(buf.into()) {
            Ok(_) => Poll::Ready(Ok(len)),
            Err(err) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                err.to_string(),
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for InternalServerCommunicator {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.rx_from_kernel).poll_read(cx, buf)
    }
}

impl Unpin for InternalServerCommunicator {}
