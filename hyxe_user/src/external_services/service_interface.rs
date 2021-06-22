use async_trait::async_trait;
use crate::misc::AccountError;
use crate::external_services::fcm::fcm_instance::FCMInstance;
use crate::external_services::fcm::data_structures::RawExternalPacket;

#[async_trait]
/// An interface for unifying interaction with underlying services
pub trait ExternalServiceChannel {
    /// Sends a payload from `implicated_cid` to `peer_cid`
    async fn send(&mut self, data: RawExternalPacket, implicated_cid: u64, peer_cid: u64) -> Result<(), AccountError<String>>;
}

#[async_trait]
impl ExternalServiceChannel for FCMInstance {
    async fn send(&mut self, data: RawExternalPacket, _implicated_cid: u64, _peer_cid: u64) -> Result<(), AccountError> {
        self.send_to_fcm_user(data).await.map(|_| ())
    }
}