use crate::fcm::fcm_client::FCMClientInstance;
use fcm::{FcmResponse, MessageBuilder, Client};
use crate::error::NetworkError;
use serde::Serialize;

#[cfg(feature = "multi-threaded")]
#[derive(Clone)]
pub struct FCMServerInstance {
    api_key: std::sync::Arc<String>,
    client: std::sync::Arc<Client>
}

#[cfg(not(feature = "multi-threaded"))]
#[derive(Clone)]
pub struct FCMServerInstance {
    api_key: std::rc::Rc<String>,
    client: std::rc::Rc<Client>
}

impl FCMServerInstance {
    #[cfg(feature = "multi-threaded")]
    pub fn new<T: Into<String>>(api_key: T) -> Self {
        Self { api_key: std::sync::Arc::new(api_key.into()), client: std::sync::Arc::new(Client::new()) }
    }

    #[cfg(not(feature = "multi-threaded"))]
    pub fn new<T: Into<String>>(api_key: T) -> Self {
        Self { api_key: std::rc::Rc::new(api_key.into()), client: std::rc::Rc::new(Client::new()) }
    }

    pub fn derive_client<T: Into<String>>(&self, client_reg_id: T) -> FCMClientInstance {
        FCMClientInstance::new(self.clone(), client_reg_id)
    }

    pub async fn send_message<T: AsRef<str>, Z: Serialize>(&self, target_reg_id: T, data: Z) -> Result<FcmResponse, NetworkError> {
        FCMClientInstance::send_to_fcm_user_inner(self.api_key(), target_reg_id.as_ref(), self.client(), data).await
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

    #[cfg(feature = "multi-threaded")]
    pub fn client(&self) -> &std::sync::Arc<Client> {
        &self.client
    }

    #[cfg(not(feature = "multi-threaded"))]
    pub fn client(&self) -> &std::rc::Rc<Client> {
        &self.client
    }
}