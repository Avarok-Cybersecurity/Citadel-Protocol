use crate::hdp::hdp_server::{HdpServerRemote, Ticket, HdpServerRequest, MessageType};
use hyxe_crypt::drill::SecurityLevel;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use crate::error::NetworkError;
use crate::hdp::state_container::VirtualConnectionType;
use crate::hdp::outbound_sender::UnboundedReceiver;
use futures::{Sink, Stream};
use futures::task::{Context, Poll};
use tokio::macros::support::Pin;
use std::fmt::Debug;
use crate::hdp::peer::peer_layer::PeerConnectionType;
use tokio::io::{AsyncWrite, AsyncRead, ReadBuf};
use futures::io::Error;
use std::ops::Deref;
use hyxe_crypt::sec_bytes::SecBuffer;
use bytes::{BufMut, BytesMut};

// 1 peer channel per virtual connection. This enables high-level communication between the [HdpServer] and the API-layer.
// This thus bypasses the kernel.
#[derive(Debug)]
pub struct PeerChannel {
    send_half: PeerChannelSendHalf,
    recv_half: PeerChannelRecvHalf
}

impl PeerChannel {
    pub(crate) fn new(server_remote: HdpServerRemote, target_cid: u64, vconn_type: VirtualConnectionType, channel_id: Ticket, security_level: SecurityLevel, is_alive: Arc<AtomicBool>, receiver: UnboundedReceiver<MessageType>) -> Self {
        let implicated_cid = vconn_type.get_implicated_cid();
        let overflow = BytesMut::new();
        let send_half = PeerChannelSendHalf {
            server_remote,
            target_cid,
            vconn_type,
            implicated_cid,
            channel_id,
            security_level,
            is_alive: is_alive.clone()
        };

        let recv_half = PeerChannelRecvHalf {
            receiver,
            target_cid,
            vconn_type,
            channel_id,
            is_alive,
            overflow
        };

        PeerChannel { send_half, recv_half }
    }

    /// Gets the CID of the endpoint
    pub fn get_peer_cid(&self) -> u64 {
        self.send_half.target_cid
    }

    /// Gets the CID of the local user
    pub fn get_implicated_cid(&self) -> u64 {
        self.send_half.vconn_type.get_implicated_cid()
    }

    /// Gets the metadata of the virtual connection
    pub fn get_peer_conn_type(&self) -> Option<PeerConnectionType> {
        self.send_half.vconn_type.try_as_peer_connection()
    }

    /// In order to use the [PeerChannel] properly, split must be called in order to receive
    /// an asynchronous interface. The SendHalf implements Sink, whereas the RecvHalf implements
    /// Stream
    pub fn split(self) -> (PeerChannelSendHalf, PeerChannelRecvHalf) {
        (self.send_half, self.recv_half)
    }
}

#[derive(Debug, Clone)]
pub struct PeerChannelSendHalf {
    server_remote: HdpServerRemote,
    target_cid: u64,
    implicated_cid: u64,
    vconn_type: VirtualConnectionType,
    channel_id: Ticket,
    security_level: SecurityLevel,
    // When the associated virtual conn drops, this gets flipped off, and hence, data won't be sent anymore
    is_alive: Arc<AtomicBool>
}

impl PeerChannelSendHalf {
    // TODO: multithreaded mode instant send
    fn send_unchecked(&self, data: MessageType) -> Result<(), NetworkError> {
        let request = HdpServerRequest::SendMessage(data, self.implicated_cid, self.vconn_type, self.security_level);
        self.server_remote.send_with_custom_ticket(self.channel_id, request)
    }

    pub fn send_unbounded(&self, data: MessageType) -> Result<(), NetworkError> {
        if self.is_alive.load(Ordering::SeqCst) {
            self.send_unchecked(data)
        } else {
            Err(NetworkError::InternalError("Server closed"))
        }
    }

    pub fn set_security_level(&mut self, security_level: SecurityLevel) {
        self.security_level = security_level;
    }

    fn close(&self) {
        self.is_alive.store(false, Ordering::SeqCst);
    }
}

impl Sink<MessageType> for PeerChannelSendHalf {
    type Error = NetworkError;

    fn poll_ready(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.is_alive.load(Ordering::SeqCst) {
            futures::Sink::<HdpServerRequest>::poll_ready(Pin::new(&mut self.server_remote), _cx)
        } else {
            Poll::Ready(Err(NetworkError::InternalError("Server closed")))
        }
    }

    fn start_send(self: Pin<&mut Self>, item: MessageType) -> Result<(), Self::Error> {
        self.send_unchecked(item)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.close();
        Poll::Ready(Ok(()))
    }
}

impl Unpin for PeerChannelRecvHalf {}

#[derive(Debug)]
pub struct PeerChannelRecvHalf {
    // when the state container removes the vconn, this will get closed
    receiver: UnboundedReceiver<MessageType>,
    target_cid: u64,
    vconn_type: VirtualConnectionType,
    channel_id: Ticket,
    is_alive: Arc<AtomicBool>,
    overflow: BytesMut
}

impl Stream for PeerChannelRecvHalf {
    type Item = SecBuffer;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if !self.is_alive.load(Ordering::SeqCst) {
            // close the stream
            log::info!("[POLL] closing PeerChannel RecvHalf");
            Poll::Ready(None)
        } else {
            match futures::ready!(self.receiver.poll_recv(cx)) {
                Some(data) => Poll::Ready(Some(data.into_buffer())),
                _ => {
                    log::info!("[PeerChannelRecvHalf] ending?");
                    Poll::Ready(None)
                }
            }
        }
    }
}

impl AsyncWrite for PeerChannelSendHalf {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        self.deref().send_unbounded(MessageType::Default(SecBuffer::from(buf)))
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::BrokenPipe, err.to_string()))?;

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        futures::Sink::poll_flush(self, cx)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::BrokenPipe, err.to_string()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.close();
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for PeerChannelRecvHalf {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if self.overflow.len() != 0 {
            let amt =  std::cmp::min(buf.remaining(), self.overflow.len());
            let bytes = self.overflow.split_to(amt);
            buf.put_slice(&bytes[..]);
            if self.overflow.len() != 0 {
                //return early, so that we can poll some more bytes immediately after. Otherwise, move-on to potentially pend for new bytes
                return Poll::Ready(Ok(()))
            }
        }

        match futures::ready!(self.as_mut().poll_next(cx)) {
            Some(secbuf) => {
                let secbuf_vec = secbuf.into_buffer();
                let bytes = secbuf_vec.as_slice();
                let amt = std::cmp::min(buf.remaining(), bytes.len());
                let (left, right) = bytes.split_at(amt);
                buf.put_slice(left);

                if right.len() != 0 {
                    // place into overflow
                    self.overflow.put_slice(right);
                }

                Poll::Ready(Ok(()))
            }

            None => {
                // EOF
                Poll::Ready(Ok(()))
            }
        }
    }
}