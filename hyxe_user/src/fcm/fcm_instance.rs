use fcm::{FcmResponse, MessageBuilder, Client, Priority, FcmError};
use serde::Serialize;
use hyxe_crypt::fcm::keys::FcmKeys;
use crate::misc::AccountError;
use std::sync::Arc;
use std::fmt::Debug;
use crate::re_imports::__private::Formatter;
use tokio::time::Duration;

pub struct FCMInstance {
    fcm_keys: FcmKeys,
    client: Arc<Client>
}


impl FCMInstance {
    pub fn new(fcm_keys: FcmKeys, client: Arc<Client>) -> Self {
        Self { fcm_keys, client }
    }

    /// Allows the user to specify custom options ontop of the default options. Note:
    /// By default, the "data", "priority" (high), and "content_available" (true) are set. Setting
    /// the notification field will cause the message to fail since processing at the endpoints is required
    /// before showing a notification
    pub async fn send_message_to_with_opts<T: AsRef<str>, Z: Serialize>(&self, target_reg_id: T, data: Z, cfg: impl FnOnce(&mut MessageBuilder<'_>)) -> Result<FcmResponse, AccountError<String>> {
        Self::send_to_fcm_user_inner(self.api_key(), target_reg_id.as_ref(), self.client(), data, cfg).await
    }

    pub async fn send_message_to<T: AsRef<str>, Z: Serialize>(&self, target_reg_id: T, data: Z) -> Result<FcmResponse, AccountError<String>> {
        Self::send_to_fcm_user_inner(self.api_key(), target_reg_id.as_ref(), self.client(), data, |_| {}).await
    }

    /// Places information in a data field, NOT a notification field because the notifications can't appear until decryption on the client end occurs. Everything google sees is encrypted
    ///
    /// Gets sent to the FCM client
    pub async fn send_to_fcm_user<T: Serialize>(&self, data: T) -> Result<FcmResponse, AccountError<String>> {
        self.send_message_to(self.client_id(), data).await
    }

    pub async fn send_to_fcm_user_by_value<T: Serialize>(self, data: T) -> Result<FcmResponse, AccountError<String>> {
        self.send_message_to(self.client_id(), data).await
    }

    #[allow(unused_results)]
    async fn send_to_fcm_user_inner<T: Serialize>(server_api_key: &str, target_reg_id: &str, client: &Client, data: T, cfg: impl FnOnce(&mut MessageBuilder<'_>)) -> Result<FcmResponse, AccountError<String>> {
        log::info!("[FCM] sending to: {}", target_reg_id);
        let mut builder = MessageBuilder::new(server_api_key, target_reg_id);
        builder.data(&data)?;
        builder.content_available(true); // for IOS only: awakens app if required using APN
        builder.priority(Priority::High);

        (cfg)(&mut builder);

        // TODO: include ttl option. When ttl = 0, delivery will be instant, but not guaranteed. Good for "video calls"
        Self::map_fcm_resp(tokio::time::timeout(Duration::from_millis(3000), client.send(builder.finalize())).await.map_err(|err| AccountError::Generic(err.to_string()))?)
    }

    pub(crate) fn map_fcm_resp(resp: Result<FcmResponse, FcmError>) -> Result<FcmResponse, AccountError<String>> {
        resp.map_err(|err| AccountError::Generic(err.to_string())).and_then(|res| {
            if let Some(err) = res.error {
                Err(AccountError::Generic(format!("{:?}", err)))
            } else {
                Ok(res)
            }
        })
    }

    /// Places information in a data field, NOT a notification field because the notifications can't appear until decryption on the client end occurs. Everything google sees is encrypted
    ///
    /// Gets sent to the FCM client(s). Useful for group functionality (However, will require a shared multiparty symmetric key)
    #[allow(unused_results)]
    pub async fn broadcast_to_users<T: Serialize, V: AsRef<[String]>>(&self, data: T, users: V) -> Result<FcmResponse, AccountError<String>> {
        let mut builder = MessageBuilder::new_multi(self.api_key(), users.as_ref());
        builder.data(&data).map_err(|err| AccountError::Generic(err.to_string()))?;
        Self::map_fcm_resp(self.client.send(builder.finalize()).await)
    }

    pub fn api_key(&self) -> &str {
        self.fcm_keys.api_key.as_str()
    }

    pub fn client_id(&self) -> &str {
        self.fcm_keys.client_id.as_str()
    }

    pub fn client(&self) -> &std::sync::Arc<Client> {
        &self.client
    }
}

impl Debug for FCMInstance {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Client ID: {}", &self.fcm_keys.client_id)
    }
}