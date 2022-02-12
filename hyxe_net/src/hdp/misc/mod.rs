use tokio::io::{AsyncRead, AsyncWrite};
use serde::de::DeserializeOwned;
use crate::error::NetworkError;
use tokio_util::codec::LengthDelimitedCodec;
use tokio_stream::StreamExt;
use futures::SinkExt;
use bytes::Bytes;
use serde::Serialize;

pub mod clean_shutdown;
pub mod net;
pub mod panic_future;
pub mod dual_rwlock;
pub mod dual_cell;
pub mod dual_late_init;
pub mod lock_holder;
pub mod ordered_channel;
pub mod session_security_settings;
pub mod underlying_proto;
pub mod udp_internal_interface;
pub mod sync_future;

pub async fn read_one_packet_as_framed<S: AsyncRead + Unpin, D: DeserializeOwned + Serialize>(io: S) -> Result<(S, D), NetworkError> {
    let mut framed = LengthDelimitedCodec::builder().new_read(io);
    let _packet = framed.next().await.ok_or_else(||NetworkError::msg("Unable to get first packet"))??;
    let packet = framed.next().await.ok_or_else(||NetworkError::msg("Unable to get first packet"))??;
    let deser = hyxe_fs::io::SyncIO::deserialize_from_vector(&packet)
        .map_err(|err| NetworkError::Generic(err.to_string()))?;
    Ok((framed.into_inner(), deser))
}

pub async fn write_one_packet<S: AsyncWrite + Unpin, R: Into<Bytes>>(io: S, packet: R) -> Result<S, NetworkError> {
    let packet = packet.into();
    let mut framed = LengthDelimitedCodec::builder().new_write(io);
    framed.send(packet.clone()).await.map_err(|err| NetworkError::Generic(err.to_string()))?;
    framed.send(packet.clone()).await.map_err(|err| NetworkError::Generic(err.to_string()))?;

    Ok(framed.into_inner())
}