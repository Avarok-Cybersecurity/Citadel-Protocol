use serde::{Serialize, Deserialize};
use firebase_rtdb::FirebaseRTDB;
use std::ops::Deref;
use crate::external_services::service_interface::ExternalServiceChannel;
use async_trait::async_trait;
use crate::misc::AccountError;
use crate::external_services::fcm::data_structures::RawExternalPacket;

/// This should be updated each time the client logs-in to the server
#[derive(Serialize, Deserialize, Debug)]
pub struct RtdbClientConfig {
    /// The URL to the rtdb instance
    pub url: String,
    /// The secret authentication token
    pub token: String
}

/// A thin wrapper around the underling rtdb
#[derive(Clone)]
pub struct RtdbInstance {
    inner: FirebaseRTDB
}

impl RtdbInstance {
    /// Creates a new instance. Assumes authentication already occurred
    pub fn new(config: &RtdbClientConfig) -> Result<Self, AccountError> {
        FirebaseRTDB::new_from_token(&config.url, &config.token).map_err(|err| AccountError::Generic(err.inner)).map(|r| r.into())
    }

    /// Useful for devices which may shutdown background processes. Resets the inner reqwest client
    pub fn refresh(&mut self) -> Result<(), AccountError> {
        let token = self.inner.token.clone();
        let url = self.inner.base_url.clone();
        let _ = std::mem::replace(&mut self.inner, FirebaseRTDB::new_from_token(url, token).map_err(|err| AccountError::Generic(err.inner))?);
        Ok(())
    }
}

impl Deref for RtdbInstance {
    type Target = FirebaseRTDB;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl From<FirebaseRTDB> for RtdbInstance {
    fn from(inner: FirebaseRTDB) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl ExternalServiceChannel for RtdbInstance {
    async fn send(&self, data: RawExternalPacket, implicated_cid: u64, peer_cid: u64) -> Result<(), AccountError> {
        // implicated CID is sending to peer CID. Thus, access the peer CID's node, and push/post/append message under implicated CID's peer node
        Ok(self.root().child("users").child(peer_cid.to_string()).child("peers").child(implicated_cid.to_string()).child("packets").post(data).await.map(|_| ()).map_err(|err| AccountError::Generic(err.inner))?)
    }
}