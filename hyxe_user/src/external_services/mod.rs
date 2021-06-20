use std::sync::Arc;
use ::fcm::Client;
use serde::{Deserialize, Serialize};
use crate::misc::AccountError;
use std::path::Path;
use crate::external_services::google_auth::JsonWebToken;
use crate::external_services::rtdb::RtdbInstance;
use firebase_rtdb::FirebaseRTDB;

/// For handling FCM related communications
#[allow(missing_docs)]
pub mod fcm;
/// For services
pub mod google_auth;
/// for traits
pub mod service_interface;
/// For rtdb
pub mod rtdb;

/// For denoting a type
pub enum ExternalService {
    /// Denotes use of Firebase Cloud Messenger
    Fcm,
    /// Denotes use of Google's Realtime Database
    Rtdb
}

/// A container for handling external services
#[derive(Clone)]
pub struct ServicesHandler {
    /// The FCM client
    pub fcm_client: Arc<Client>,
    /// Serverside only
    pub google_auth: Option<crate::external_services::google_auth::GoogleAuth>,
    /// serverside only
    pub rtdb_root_instance: Option<RtdbInstance>,
    /// Serverside only
    pub rtdb_config: Option<RtdbConfig>
}

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
/// Passed to the services handler post-login at the server. Intended to be passed to the client afterwards
pub struct PostLoginObject {
    /// Returns the JWebToken
    pub google_auth_jwt: Option<JsonWebToken>,
    /// Google's real time database config
    pub rtdb: Option<RtdbConfig>
}

impl ServicesHandler {
    /// This should be called after the server validates a login [marked async for now to allow room for future async processes)
    pub async fn on_post_login_serverside(&self, implicated_cid: u64) -> Result<PostLoginObject, AccountError> {
        let mut ret: PostLoginObject = Default::default();

        if let Some(auth) = self.google_auth.as_ref() {
            ret.google_auth_jwt = Some(auth.sign_new_custom_jwt_auth(implicated_cid)?)
        }

        ret.rtdb = self.rtdb_config.clone();

        Ok(ret)
    }
}

#[derive(Deserialize, Debug, Default, Clone)]
/// An object used to determine the settings for the external services
pub struct ServicesConfig {
    google_services_json_path: Option<String>,
    google_rtdb: Option<RtdbConfig>
}

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
/// For use in the TOML config as well as for during the Post-login phase
pub struct RtdbConfig {
    /// The URL to the rtdb instance
    pub url: String,
    /// The API key for identification
    pub api_key: String
}

impl ServicesConfig {
    /// Creates a [ServicesHandler] from the given internal configuration
    pub async fn to_services_handler(self) -> Result<ServicesHandler, AccountError> {
        let fcm_client = Arc::new(Client::new());

        let (google_auth, rtdb_root_instance) = if let Some(path) = self.google_services_json_path {
            let path = Path::new(&path);
            let auth = crate::external_services::google_auth::GoogleAuth::load_from_google_services_file(path).await?;

            let rtdb_root_instance = if let Some(rtdb_config) = self.google_rtdb.as_ref() {
                let root_jwt = auth.sign_new_custom_jwt_auth("root")?;
                let rtdb_root_instance = FirebaseRTDB::new_from_jwt(&rtdb_config.url, root_jwt, &rtdb_config.api_key).await.map_err(|err| AccountError::Generic(err.inner))?;
                Some(rtdb_root_instance.into())
            } else {
                None
            };

            (Some(auth), rtdb_root_instance)
        } else {
            (None, None)
        };

        let rtdb_config = self.google_rtdb;

        Ok(ServicesHandler { fcm_client, google_auth, rtdb_config, rtdb_root_instance })
    }
}