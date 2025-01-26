//! # Google Authentication Service
//!
//! Provides functionality for generating custom JWT tokens for Google Firebase authentication.
//! This module enables server-side authentication token generation using Google service account
//! credentials.
//!
//! ## Features
//!
//! * Load Google service account credentials from JSON file
//! * Generate custom JWT tokens for Firebase authentication
//! * RSA private key management with SHA-256 signing
//! * Configurable token expiration
//!
//! ## Usage Example
//!
//! ```rust,no_run
//! use citadel_user::external_services::google_auth::GoogleAuth;
//!
//! async fn authenticate_user(user_id: &str) -> Result<String, Box<dyn std::error::Error>> {
//!     // Load service account credentials
//!     let auth = GoogleAuth::load_from_google_services_file("path/to/service-account.json").await?;
//!     
//!     // Generate custom JWT token
//!     let token = auth.sign_new_custom_jwt_auth(user_id)?;
//!     
//!     Ok(token.to_string())
//! }
//! ```
//!
//! ## Important Notes
//!
//! * Requires a valid Google service account JSON file with private key
//! * Service account must have appropriate Firebase permissions
//! * JWT tokens are signed using RSA SHA-256
//! * Default token expiration is 1 hour
//!
//! ## Related Components
//!
//! * `JsonWebToken`: Type representing a signed JWT token
//! * `AccountError`: Error type for authentication operations
//! * Firebase Admin SDK: External service for token verification
//!

use crate::external_services::JsonWebToken;
use crate::misc::AccountError;
use jwt::{PKeyWithDigest, SignWithKey};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

/// Used to sign custom JWTs for authentication purposes. The server is expected to have a single instance
#[derive(Clone)]
pub struct GoogleAuth {
    key: Arc<PKeyWithDigest<Private>>,
    email: Arc<String>,
}

impl GoogleAuth {
    /// Must contain the private key and services email. Can be obtained from the firebase console
    pub async fn load_from_google_services_file<P: AsRef<Path>>(
        path: P,
    ) -> Result<Self, AccountError> {
        let string = citadel_io::tokio::fs::read_to_string(path)
            .await
            .map_err(|err| AccountError::Generic(err.to_string()))?;
        let mut map: HashMap<String, String> = serde_json::from_str(string.as_str())
            .map_err(|err| AccountError::Generic(err.to_string()))?;

        let priv_key = map
            .remove("private_key")
            .ok_or_else(|| AccountError::Generic("Private key does not exist".to_string()))?;

        let key = PKey::from_rsa(
            Rsa::private_key_from_pem(priv_key.as_bytes())
                .map_err(|err| AccountError::Generic(err.to_string()))?,
        )
        .map_err(|err| AccountError::Generic(err.to_string()))?;
        let digest = MessageDigest::sha256();

        let key = PKeyWithDigest { key, digest };

        let service_email = map
            .remove("client_email")
            .ok_or_else(|| AccountError::Generic("Service email not present".to_string()))?;

        Ok(Self {
            key: Arc::new(key),
            email: Arc::new(service_email),
        })
    }

    /// Creates a new JWT for the given user, allowing the user to login to google services
    #[allow(unused_results)]
    pub fn sign_new_custom_jwt_auth<T: ToString>(
        &self,
        uid: T,
    ) -> Result<JsonWebToken, AccountError> {
        let key = &self.key;
        let service_email = &self.email;

        let iat = SystemTime::UNIX_EPOCH
            .elapsed()
            .map_err(|err| AccountError::Generic(err.to_string()))?
            .as_secs();
        let exp = iat + 1800;

        let iat = iat.to_string();
        let exp = exp.to_string();
        let session_cid = uid.to_string();

        //let final_claim = format!("array(\"cid\" => ${})", &session_cid);

        let mut claims = HashMap::new();
        claims.insert("alg", "RS256");
        claims.insert("iss", service_email.as_str());
        claims.insert("sub", service_email.as_str());
        claims.insert("aud", "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit");
        claims.insert("iat", iat.as_str());
        claims.insert("exp", exp.as_str());
        claims.insert("uid", &session_cid);
        //claims.insert("claims", final_claim.as_str());

        log::trace!(target: "citadel", "{:?}", &claims);

        claims
            .sign_with_key(key as &PKeyWithDigest<Private>)
            .map_err(|err| AccountError::Generic(err.to_string()))
    }
}
