use std::sync::Arc;
use ::fcm::Client;
use serde::{Deserialize, Serialize};
use crate::misc::AccountError;
use std::path::Path;
use crate::external_services::google_auth::JsonWebToken;

/// For handling FCM related communications
#[allow(missing_docs)]
pub mod fcm;
/// For services
pub mod google_auth;

/// A container for handling external services
#[derive(Clone)]
pub struct ServicesHandler {
    /// The FCM client
    pub fcm_client: Arc<Client>,
    /// Serverside only
    pub google_auth: Option<crate::external_services::google_auth::GoogleAuth>
}

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
/// Passed to the services handler post-login at the server. Intended to be passed to the client afterwards
pub struct PostLoginObject {
    /// Returns the JWebToken
    pub google_auth_jwt: Option<JsonWebToken>
}

impl ServicesHandler {
    /// This should be called after the server validates a login [marked async for now to allow room for future async processes)
    pub async fn on_post_login_serverside(&self, implicated_cid: u64) -> Result<PostLoginObject, AccountError> {
        let mut ret: PostLoginObject = Default::default();

        if let Some(auth) = self.google_auth.as_ref() {
            ret.google_auth_jwt = Some(auth.sign_new_custom_jwt_auth(implicated_cid)?)
        }

        Ok(ret)
    }
}

#[derive(Deserialize, Debug, Default, Clone)]
/// An object used to determine the settings for the external services
pub struct ServicesConfig {
    google_services_json_path: Option<String>
}

impl ServicesConfig {
    /// Creates a [ServicesHandler] from the given internal configuration
    pub async fn to_services_handler(self) -> Result<ServicesHandler, AccountError> {
        let fcm_client = Arc::new(Client::new());

        let google_auth = if let Some(path) = self.google_services_json_path {
            let path = Path::new(&path);
            Some(crate::external_services::google_auth::GoogleAuth::load_from_google_services_file(path).await?)
        } else {
            None
        };

        Ok(ServicesHandler { fcm_client, google_auth })
    }
}