use std::path::Path;
use crate::misc::AccountError;
use std::sync::Arc;
use std::collections::HashMap;
use std::time::SystemTime;
use jwt::{SignWithKey, PKeyWithDigest};
use openssl::rsa::Rsa;
use openssl::pkey::{PKey, Private};
use openssl::hash::MessageDigest;

/// Used to sign custom JWTs for authentication purposes. The server is expected to have a single instance
///
/// Sign with attributes:
/// alg	Algorithm	"RS256"
// iss	Issuer	Your project's service account email address
// sub	Subject	Your project's service account email address
// aud	Audience	"https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit"
// iat	Issued-at time	The current time, in seconds since the UNIX epoch
// exp	Expiration time	The time, in seconds since the UNIX epoch, at which the token expires. It can be a maximum of 3600 seconds later than the iat.
// Note: this only controls the time when the custom token itself expires. But once you sign a user in using signInWithCustomToken(), they will remain signed in into the device until their session is invalidated or the user signs out.
// uid		The unique identifier of the signed-in user must be a string, between 1-36 characters long
// claims (optional)		Optional custom claims to include in the Security Rules auth / request.auth variables
#[derive(Clone)]
pub struct GoogleAuth {
    key: Arc<PKeyWithDigest<Private>>,
    email: Arc<String>
}

/// The type returned when signing a custom jwt
pub type JsonWebToken = String;

impl GoogleAuth {
    /// Must contain the private key and services email. Can be obtained from the firebase console
    pub async fn load_from_google_services_file<P: AsRef<Path>>(path: P) -> Result<Self, AccountError> {
        let string = tokio::fs::read_to_string(path).await.map_err(|err| AccountError::Generic(err.to_string()))?;
        let mut map: HashMap<String, String> = serde_json::from_str(string.as_str()).map_err(|err| AccountError::Generic(err.to_string()))?;

        let priv_key = map.remove("private_key").ok_or_else(|| AccountError::Generic("Private key does not exist".to_string()))?;

        let key = PKey::from_rsa(Rsa::private_key_from_pem(priv_key.as_bytes()).map_err(|err| AccountError::Generic(err.to_string()))?).map_err(|err| AccountError::Generic(err.to_string()))?;
        let digest = MessageDigest::sha256();

        let key = PKeyWithDigest { key, digest };

        let service_email = map.remove("client_email").ok_or_else(|| AccountError::Generic("Service email not present".to_string()))?;

        Ok(Self { key: Arc::new(key), email: Arc::new(service_email) })
    }

    /// Creates a new JWT for the given user, allowing the user to login to google services
    #[allow(unused_results)]
    pub fn sign_new_custom_jwt_auth<T: ToString>(&self, uid: T) -> Result<JsonWebToken, AccountError> {
        let key = &self.key;
        let service_email = &self.email;

        let iat = SystemTime::UNIX_EPOCH.elapsed().map_err(|err| AccountError::Generic(err.to_string()))?.as_secs();
        let exp = iat + 1800;

        let iat = iat.to_string();
        let exp = exp.to_string();
        let implicated_cid = uid.to_string();

        //let final_claim = format!("array(\"cid\" => ${})", &implicated_cid);

        let mut claims = HashMap::new();
        claims.insert("alg", "RS256");
        claims.insert("iss", service_email.as_str());
        claims.insert("sub", service_email.as_str());
        claims.insert("aud", "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit");
        claims.insert("iat", iat.as_str());
        claims.insert("exp", exp.as_str());
        claims.insert("uid", &implicated_cid);
        //claims.insert("claims", final_claim.as_str());

        log::trace!(target: "lusna", "{:?}", &claims);

        claims.sign_with_key(&*key as &PKeyWithDigest<Private>).map_err(|err| AccountError::Generic(err.to_string()))
    }
}