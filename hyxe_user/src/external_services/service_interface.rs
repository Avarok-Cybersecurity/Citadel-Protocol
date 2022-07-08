use crate::misc::AccountError;
use async_trait::async_trait;

/// The default type for transmitting data
pub type RawExternalPacket = Vec<u8>;

#[async_trait]
/// An interface for unifying interaction with underlying services
pub trait ExternalServiceChannel {
    /// Sends a payload from `implicated_cid` to `peer_cid`
    async fn send(
        &mut self,
        data: RawExternalPacket,
        implicated_cid: u64,
        peer_cid: u64,
    ) -> Result<(), AccountError>;
}
