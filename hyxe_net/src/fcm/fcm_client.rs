use crate::fcm::fcm_server::FCMServerInstance;
use std::sync::Arc;
use serde::Serialize;
use crate::error::NetworkError;
use fcm::{MessageBuilder, FcmResponse};

/// Each impersonal CNAC that opts-in for using FCM at connection init will get this. The server will handle this, not the client, as the server is expected to keep running, while the client may be powered off in the background due to android/ios limitations
pub struct FCMClientInstance {
    server_instance: FCMServerInstance,
    // Obtained uniquely when the user registers their device with Google
    registration_id: Arc<String>
}

impl FCMClientInstance {
    pub fn new<T: Into<String>>(server_instance: FCMServerInstance, registration_id: T) -> Self {
        Self { server_instance, registration_id: Arc::new(registration_id.into()) }
    }

    /// Places information in a data field, NOT a notification field because the notifications can't appear until decryption on the client end occurs. Everything google sees is encrypted
    ///
    /// Gets sent to the FCM client
    #[allow(unused_results)]
    pub async fn send_to_fcm_user<T: Serialize>(&self, data: T) -> Result<FcmResponse, NetworkError> {
        let mut builder = MessageBuilder::new(self.server_instance.api_key(), self.registration_id.as_str());
        builder.data(&data).map_err(|err| NetworkError::Generic(err.to_string()))?;
        self.server_instance.client().send(builder.finalize()).await.map_err(|err| NetworkError::Generic(err.to_string()))
    }

    pub fn registration_id(&self) -> &str {
        self.registration_id.as_str()
    }
}