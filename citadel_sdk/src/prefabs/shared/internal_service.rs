use crate::prelude::{ConnectionSuccess, TargetLockedRemote};
use bytes::Bytes;
use citadel_io::tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use citadel_proto::prelude::NetworkError;
use citadel_proto::re_imports::{StreamReader, UnboundedReceiverStream};
use citadel_types::crypto::SecBuffer;
use futures::StreamExt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

pub async fn internal_service<F, Fut, R>(
    remote: R,
    connect_success: ConnectionSuccess,
    service: F,
) -> Result<(), NetworkError>
where
    F: Send + Copy + Sync + FnOnce(InternalServerCommunicator) -> Fut,
    Fut: Send + Sync + Future<Output = Result<(), NetworkError>>,
    R: TargetLockedRemote,
{
    let (tx_to_service, rx_from_kernel) = citadel_io::tokio::sync::mpsc::unbounded_channel();
    let (tx_to_kernel, mut rx_from_service) = citadel_io::tokio::sync::mpsc::unbounded_channel();

    let internal_server_communicator = InternalServerCommunicator {
        tx_to_kernel,
        rx_from_kernel: StreamReader::new(rx_from_kernel.into()),
    };

    let internal_server = service(internal_server_communicator);

    // each time a client connects, we will begin listening for messages.
    let (sink, mut stream) = connect_success.channel.split();
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
            sink.send_message(packet.into()).await?;
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
