use std::sync::Arc;
use crate::fcm::fcm_client::FCMClientInstance;
use fcm::{FcmResponse, MessageBuilder, Client};
use crate::error::NetworkError;
use serde::Serialize;

#[derive(Clone)]
pub struct FCMServerInstance {
    api_key: Arc<String>,
    client: Arc<Client>
}

impl FCMServerInstance {
    pub fn new<T: Into<String>>(api_key: T) -> Self {
        Self { api_key: Arc::new(api_key.into()), client: Arc::new(Client::new()) }
    }

    pub fn derive_client<T: Into<String>>(&self, client_reg_id: T) -> FCMClientInstance {
        FCMClientInstance::new(self.clone(), client_reg_id)
    }

    /// Places information in a data field, NOT a notification field because the notifications can't appear until decryption on the client end occurs. Everything google sees is encrypted
    ///
    /// Gets sent to the FCM client(s). Useful for group functionality (However, will require a shared multiparty symmetric key)
    #[allow(unused_results)]
    pub async fn broadcast_to_users<T: Serialize, V: AsRef<[FCMClientInstance]>>(&self, data: T, users: V) -> Result<FcmResponse, NetworkError> {
        let users = users.as_ref().iter().map(|client| client.registration_id()).collect::<Vec<&str>>();
        let mut builder = MessageBuilder::new_multi(self.api_key(), users.as_slice());
        builder.data(&data).map_err(|err| NetworkError::Generic(err.to_string()))?;
        self.client.send(builder.finalize()).await.map_err(|err| NetworkError::Generic(err.to_string()))
    }

    pub fn api_key(&self) -> &str {
        self.api_key.as_str()
    }

    pub fn client(&self) -> &Arc<Client> {
        &self.client
    }
}