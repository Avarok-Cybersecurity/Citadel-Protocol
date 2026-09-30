use super::config::MediaTransportConfig;
use super::error::MediaResultExt;
use super::receiver::MediaReceiver;
use super::sender::MediaSender;
use super::transport::{
    BoxedSink, BoxedSource, MediaDatagramSink, MediaTransportKind, ReliableSink,
};
use crate::prelude::{CitadelClientServerConnection, PeerChannel, UdpChannel};
use crate::remote_ext::remote_specialization::PeerRemote;
use crate::remote_ext::results::PeerConnectSuccess;
use bytes::BytesMut;
use citadel_io::time::{timeout, Instant};
use citadel_io::tokio::sync::oneshot::Receiver;
use citadel_io::ErrorCode;
use citadel_media::wire::{self, encode_control, WireMessage};
use citadel_media::ControlMessage;
use citadel_proto::prelude::{NetworkError, OutboundUdpSender, PeerChannelRecvHalf, Ratchet};
use futures::StreamExt;

/// A media session bound to one connection. Build with
/// [`MediaEndpoint::from_peer_connection`] or [`MediaEndpoint::from_c2s`],
/// then [`MediaEndpoint::split`].
pub struct MediaEndpoint {
    kind: MediaTransportKind,
    sender: MediaSender,
    receiver: MediaReceiver,
}

impl std::fmt::Debug for MediaEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediaEndpoint")
            .field("kind", &self.kind)
            .finish()
    }
}

/// The two halves of a [`MediaEndpoint`].
#[derive(Debug)]
pub struct MediaEndpointParts {
    pub kind: MediaTransportKind,
    pub sender: MediaSender,
    pub receiver: MediaReceiver,
}

impl MediaEndpoint {
    /// Consumes a P2P connection's channels and returns the endpoint together
    /// with the connection's [`PeerRemote`] (take any file-transfer handle
    /// receiver with `get_incoming_file_transfer_handle` beforehand).
    /// Waits `cfg.udp_wait` for UDP, then exchanges transport offers with the
    /// peer over the reliable channel: UDP is used only if both sides hold
    /// it, otherwise both fall back to reliable mode. The peer must build its
    /// endpoint too; this returns once its offer arrives.
    pub async fn from_peer_connection<R: Ratchet>(
        conn: PeerConnectSuccess<R>,
        cfg: MediaTransportConfig,
    ) -> Result<(Self, PeerRemote<R>), NetworkError> {
        let endpoint = Self::from_channels(conn.channel, conn.udp_channel_rx, cfg).await?;
        Ok((endpoint, conn.remote))
    }

    /// Builds directly from a reliable channel and the optional pending UDP
    /// channel receiver (as found on every connection-success type).
    pub async fn from_channels<R: Ratchet>(
        channel: PeerChannel<R>,
        udp_channel_rx: Option<Receiver<UdpChannel<R>>>,
        cfg: MediaTransportConfig,
    ) -> Result<Self, NetworkError> {
        Self::build(channel, udp_channel_rx, cfg).await
    }

    /// Same as [`Self::from_peer_connection`] for a client↔server connection.
    pub async fn from_c2s<R: Ratchet>(
        conn: &mut CitadelClientServerConnection<R>,
        cfg: MediaTransportConfig,
    ) -> Result<Self, NetworkError> {
        let channel = conn.take_channel().ok_or_else(|| {
            citadel_io::error!(
                ErrorCode::MediaTransportClosed,
                "reliable channel already taken"
            )
        })?;
        Self::from_channels(channel, conn.udp_channel_rx.take(), cfg).await
    }

    async fn build<R: Ratchet>(
        channel: PeerChannel<R>,
        udp_rx: Option<Receiver<UdpChannel<R>>>,
        cfg: MediaTransportConfig,
    ) -> Result<Self, NetworkError> {
        cfg.validate()?;
        let start = Instant::now();
        let (reliable_tx, reliable_rx) = channel.split();
        let mut control_sink = ReliableSink::spawn(reliable_tx);
        let mut control_src: BoxedSource = Box::pin(reliable_rx);

        let local_udp = await_udp(udp_rx, &cfg).await;
        if let Some((udp_tx, _)) = &local_udp {
            if cfg.udp_payload_budget > udp_tx.max_payload_len() {
                return Err(citadel_io::error!(
                    ErrorCode::MediaConfigInvalid,
                    format!(
                        "udp_payload_budget {} exceeds the UDP channel's max payload {}",
                        cfg.udp_payload_budget,
                        udp_tx.max_payload_len()
                    )
                ));
            }
        }
        let peer_udp =
            exchange_transport_offer(&mut control_sink, &mut control_src, local_udp.is_some())
                .await?;

        match local_udp.filter(|_| peer_udp) {
            Some((udp_tx, udp_rx)) => Self::assemble(
                MediaTransportKind::Unreliable,
                Box::new(udp_tx),
                Box::new(control_sink),
                Box::pin(udp_rx),
                Some(control_src),
                cfg,
                start,
            ),
            None => Self::assemble(
                MediaTransportKind::Reliable,
                Box::new(control_sink.clone()),
                Box::new(control_sink),
                control_src,
                None,
                cfg,
                start,
            ),
        }
    }

    pub(crate) fn assemble(
        kind: MediaTransportKind,
        media_sink: BoxedSink,
        control_sink: BoxedSink,
        media_src: BoxedSource,
        control_src: Option<BoxedSource>,
        cfg: MediaTransportConfig,
        start: Instant,
    ) -> Result<Self, NetworkError> {
        Ok(Self {
            kind,
            sender: MediaSender::new(
                kind,
                media_sink,
                control_sink,
                cfg.media,
                cfg.send_queue_frames,
            )?,
            receiver: MediaReceiver::new(kind, media_src, control_src, cfg.media, start)?,
        })
    }

    pub fn kind(&self) -> MediaTransportKind {
        self.kind
    }

    /// Splits into independent send/receive halves. Dropping the receiver in
    /// unreliable mode drops the UDP receive half (⇒ `DisconnectUDP`).
    pub fn split(self) -> (MediaSender, MediaReceiver) {
        (self.sender, self.receiver)
    }

    pub fn into_parts(self) -> MediaEndpointParts {
        MediaEndpointParts {
            kind: self.kind,
            sender: self.sender,
            receiver: self.receiver,
        }
    }
}

/// Sends this side's transport offer as the first reliable message and reads
/// the peer's, which is likewise the first message on the ordered lane.
/// Returns whether the peer holds UDP. Each side's own UDP decision is local
/// and timer-bound, so only the pair of offers yields an agreed transport.
async fn exchange_transport_offer(
    sink: &mut ReliableSink,
    src: &mut BoxedSource,
    local_udp: bool,
) -> Result<bool, NetworkError> {
    let body = ControlMessage::TransportOffer { udp: local_udp }
        .encode()
        .net()?;
    sink.send_datagram(BytesMut::from(encode_control(&body).as_slice()))?;
    let reply = src.next().await.ok_or_else(|| {
        citadel_io::error!(
            ErrorCode::MediaTransportClosed,
            "reliable channel closed before the peer's transport offer"
        )
    })?;
    let malformed = |err| citadel_io::error!(ErrorCode::MediaControlDecode, err);
    match wire::parse(reply.as_ref()).map_err(malformed)? {
        WireMessage::Control(body) => match ControlMessage::decode(body).map_err(malformed)? {
            ControlMessage::TransportOffer { udp } => Ok(udp),
            other => Err(citadel_io::error!(
                ErrorCode::MediaControlDecode,
                format!("expected the peer's transport offer, got {other:?}")
            )),
        },
        WireMessage::Fragment { .. } => Err(citadel_io::error!(
            ErrorCode::MediaControlDecode,
            "expected the peer's transport offer, got a media fragment"
        )),
    }
}

/// Resolves the UDP channel within `cfg.udp_wait`, or `None` to fall back.
/// A missing receiver (`UdpMode::Disabled`), a timeout, or a dropped sender
/// all mean "no UDP" — logged, never fatal.
async fn await_udp<R: Ratchet>(
    udp_rx: Option<Receiver<UdpChannel<R>>>,
    cfg: &MediaTransportConfig,
) -> Option<(OutboundUdpSender, PeerChannelRecvHalf<R>)> {
    let rx = udp_rx?;
    match timeout(cfg.udp_wait, rx).await {
        Ok(Ok(chan)) => Some(chan.split()),
        Ok(Err(_)) => {
            log::warn!(target: "citadel", "media: UDP channel sender dropped; using reliable transport");
            None
        }
        Err(_) => {
            log::warn!(target: "citadel", "media: UDP channel not ready within {:?}; using reliable transport", cfg.udp_wait);
            None
        }
    }
}
