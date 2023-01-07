use crate::external_services::service_interface::{ExternalServiceChannel, RawExternalPacket};
use crate::external_services::JsonWebToken;
use crate::misc::AccountError;
use async_trait::async_trait;
use firebase_rtdb::{AuthResponsePayload, FirebaseRTDB, DEFAULT_EXPIRE_BUFFER_SECS};
use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};
use std::time::Instant;

/// This should be updated each time the client logs-in to the server
#[derive(Serialize, Deserialize, Debug)]
pub struct RtdbClientConfig {
    /// The URL to the rtdb instance
    pub url: String,
    /// api key
    pub api_key: String,
    /// auth payload from authentication process
    pub auth_payload: AuthResponsePayload,
    /// for determining expire time
    #[serde(with = "serde_millis")]
    pub expire_time: Instant,
    /// The original jsonwebtoken used for authentication
    pub jwt: JsonWebToken,
}

impl RtdbClientConfig {
    /// Used to determine if the auth key expired
    pub fn expired(&self) -> bool {
        Instant::now() + DEFAULT_EXPIRE_BUFFER_SECS > self.expire_time
    }
}

/// A thin wrapper around the underling rtdb
#[derive(Clone)]
pub struct RtdbInstance {
    inner: FirebaseRTDB,
}

impl RtdbInstance {
    /// Creates a new instance given the previous config
    pub fn new(config: &RtdbClientConfig) -> Result<Self, AccountError> {
        FirebaseRTDB::new_from_token(
            &config.url,
            config.api_key.clone(),
            config.jwt.clone(),
            config.auth_payload.clone(),
            config.expire_time,
        )
        .map_err(|err| AccountError::Generic(err.inner))
        .map(|r| r.into())
    }

    /// Useful for devices which may shutdown background processes. Resets the inner reqwest client
    pub fn refresh(&mut self) -> Result<(), AccountError> {
        let token = self.inner.auth.idToken.clone();
        let url = self.inner.base_url.clone();
        let auth = self.inner.auth.clone();
        let expire_time = self.expire_time;
        let api_key = self.api_key.clone();

        let _ = std::mem::replace(
            &mut self.inner,
            FirebaseRTDB::new_from_token(url, api_key, token, auth, expire_time)
                .map_err(|err| AccountError::Generic(err.inner))?,
        );

        Ok(())
    }
}

impl Deref for RtdbInstance {
    type Target = FirebaseRTDB;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for RtdbInstance {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl From<FirebaseRTDB> for RtdbInstance {
    fn from(inner: FirebaseRTDB) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl ExternalServiceChannel for RtdbInstance {
    async fn send(
        &mut self,
        data: RawExternalPacket,
        implicated_cid: u64,
        peer_cid: u64,
    ) -> Result<(), AccountError> {
        // implicated CID is sending to peer CID. Thus, access the peer CID's node, and push/post/append message under implicated CID's peer node
        Ok(self
            .root()
            .await
            .map_err(|err| AccountError::Generic(err.inner))?
            .child("users")
            .child(peer_cid.to_string())
            .child("peers")
            .child(implicated_cid.to_string())
            .final_node("packets")
            .post(data)
            .await
            .map(|_| ())
            .map_err(|err| AccountError::Generic(err.inner))?)
    }
}
