use crate::error::NetworkError;
use bytes::Bytes;
use futures::SinkExt;
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_stream::StreamExt;
use tokio_util::codec::LengthDelimitedCodec;

pub mod clean_shutdown;
pub mod dual_cell;
pub mod dual_late_init;
pub mod dual_rwlock;
pub mod lock_holder;
pub mod net;
pub mod ordered_channel;
pub mod panic_future;
pub mod session_security_settings;
pub mod udp_internal_interface;
pub mod underlying_proto;

pub async fn read_one_packet_as_framed<S: AsyncRead + Unpin, D: DeserializeOwned + Serialize>(
    io: S,
) -> Result<(S, D), NetworkError> {
    let mut framed = LengthDelimitedCodec::builder().new_read(io);
    let packet = framed
        .next()
        .await
        .ok_or_else(|| NetworkError::msg("Unable to get first packet"))??;
    let deser = citadel_user::serialization::SyncIO::deserialize_from_vector(&packet)
        .map_err(|err| NetworkError::Generic(err.into_string()))?;
    Ok((framed.into_inner(), deser))
}

pub async fn write_one_packet<S: AsyncWrite + Unpin, R: Into<Bytes>>(
    io: S,
    packet: R,
) -> Result<S, NetworkError> {
    let packet = packet.into();
    let mut framed = LengthDelimitedCodec::builder().new_write(io);
    framed
        .send(packet.clone())
        .await
        .map_err(|err| NetworkError::Generic(err.to_string()))?;
    framed
        .flush()
        .await
        .map_err(|err| NetworkError::Generic(err.to_string()))?;
    Ok(framed.into_inner())
}
