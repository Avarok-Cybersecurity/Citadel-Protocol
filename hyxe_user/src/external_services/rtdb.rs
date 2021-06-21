use serde::{Serialize, Deserialize};
use firebase_rtdb::{FirebaseRTDB, AuthResponsePayload, DEFAULT_EXPIRE_BUFFER_SECS};
use std::ops::Deref;
use crate::external_services::service_interface::ExternalServiceChannel;
use async_trait::async_trait;
use crate::misc::AccountError;
use crate::external_services::fcm::data_structures::RawExternalPacket;
use std::time::Instant;
use crate::external_services::google_auth::JsonWebToken;

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
    pub jwt: JsonWebToken
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
    inner: FirebaseRTDB
}

impl RtdbInstance {
    /// Creates a new instance. May re-authenticate if a refresh is needed
    pub async fn new_maybe_refresh(config: &RtdbClientConfig) -> Result<Self, AccountError> {
        if config.expired() {
            FirebaseRTDB::new_from_jwt(config.url.as_str(), &config.jwt, &config.api_key).await.map(|r| r.into()).map_err(|err| AccountError::Generic(err.inner))
        } else {
            FirebaseRTDB::new_from_token(&config.url, config.api_key.clone(), config.jwt.clone(), config.auth_payload.clone(), config.expire_time).map_err(|err| AccountError::Generic(err.inner)).map(|r| r.into())
        }
    }

    /// Useful for devices which may shutdown background processes. Resets the inner reqwest client
    pub async fn refresh(&mut self) -> Result<(), AccountError> {
        let token = self.inner.auth.idToken.clone();
        let url = self.inner.base_url.clone();
        let auth = self.inner.auth.clone();
        let expire_time = self.expire_time;
        let api_key = self.api_key.clone();

        if self.token_expired() {
            self.inner.renew_token().await.map_err(|err| AccountError::Generic(err.inner))?;
        } else {
            let _ = std::mem::replace(&mut self.inner, FirebaseRTDB::new_from_token(url, api_key,token, auth, expire_time).map_err(|err| AccountError::Generic(err.inner))?);
        }

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
        Ok(self.root().child("users").child(peer_cid.to_string()).child("peers").child(implicated_cid.to_string()).final_node("packets").post(data).await.map(|_| ()).map_err(|err| AccountError::Generic(err.inner))?)
    }
}