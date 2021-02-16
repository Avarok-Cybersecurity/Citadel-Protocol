use crate::fcm::fcm_server::FCMServerInstance;
use serde::Serialize;
use crate::error::NetworkError;
use fcm::{MessageBuilder, FcmResponse, Client, Priority};

/// Each impersonal CNAC that opts-in for using FCM at connection init will get this. The server will handle this, not the client, as the server is expected to keep running, while the client may be powered off in the background due to android/ios limitations
#[cfg(feature = "multi-threaded")]
pub struct FCMClientInstance {
    server_instance: FCMServerInstance,
    // Obtained uniquely when the user registers their device with Google
    registration_id: std::sync::Arc<String>
}

#[cfg(not(feature = "multi-threaded"))]
pub struct FCMClientInstance {
    server_instance: FCMServerInstance,
    // Obtained uniquely when the user registers their device with Google
    registration_id: std::rc::Rc<String>
}

impl FCMClientInstance {
    #[cfg(feature = "multi-threaded")]
    pub fn new<T: Into<String>>(server_instance: FCMServerInstance, registration_id: T) -> Self {
        Self { server_instance, registration_id: std::sync::Arc::new(registration_id.into()) }
    }

    #[cfg(not(feature = "multi-threaded"))]
    pub fn new<T: Into<String>>(server_instance: FCMServerInstance, registration_id: T) -> Self {
        Self { server_instance, registration_id: std::rc::Rc::new(registration_id.into()) }
    }

    /// Places information in a data field, NOT a notification field because the notifications can't appear until decryption on the client end occurs. Everything google sees is encrypted
    ///
    /// Gets sent to the FCM client
    pub async fn send_to_fcm_user<T: Serialize>(&self, data: T) -> Result<FcmResponse, NetworkError> {
        Self::send_to_fcm_user_inner(self.server_instance.api_key(), self.registration_id(), self.server_instance.client(), data).await
    }

    #[allow(unused_results)]
    pub async fn send_to_fcm_user_inner<T: Serialize>(server_api_key: &str, target_reg_id: &str, client: &Client, data: T) -> Result<FcmResponse, NetworkError> {
        let mut builder = MessageBuilder::new(server_api_key, target_reg_id);
        builder.data(&data).map_err(|err| NetworkError::Generic(err.to_string()))?;
        builder.priority(Priority::High);
        client.send(builder.finalize()).await.map_err(|err| NetworkError::Generic(err.to_string()))
    }

    pub fn registration_id(&self) -> &str {
        self.registration_id.as_str()
    }
}