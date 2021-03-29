use bstr::ByteSlice;
use serde::{Serialize, Deserialize};
use hyxe_crypt::sec_bytes::SecBuffer;
use hyxe_crypt::argon_container::{AsyncArgon, ArgonSettings, ArgonStatus};
use crate::misc::AccountError;


/// When creating credentials, this is required
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedCredentials {
    ///
    pub username: String,
    ///
    pub password_hashed: SecBuffer,
    ///
    pub full_name: String,
    /// Only existent if the new_register constructor is called
    pub registration_settings: Option<ArgonSettings>
}

impl ProposedCredentials {
    /// For storing the data
    pub fn new<T: Into<String> + Send, R: Into<String> + Send>(full_name: T, username: R, password_hashed: SecBuffer) -> Self {
        let (username, full_name, password_hashed) = Self::sanitize_and_prepare(username, full_name, password_hashed.as_ref());

        Self { username, password_hashed, full_name, registration_settings: None }
    }

    /// For storing the data
    pub async fn new_register<T: Into<String> + Send, R: Into<String> + Send>(full_name: T, username: R, password_unhashed: SecBuffer) -> Result<Self, AccountError> {
        let (username, full_name, password_unhashed) = Self::sanitize_and_prepare(username, full_name, password_unhashed.as_ref());

        let settings = ArgonSettings::new_defaults(full_name.clone().into_bytes());
        match AsyncArgon::hash(password_unhashed, settings.clone()).await.map_err(|err| AccountError::Generic(err.to_string()))? {
            ArgonStatus::HashSuccess(password_hashed) => {
                Ok(Self { username, password_hashed, full_name, registration_settings: Some(settings) })
            }

            _ => {
                Err(AccountError::Generic("Unable to hash input password".to_string()))
            }
        }
    }

    fn sanitize_and_prepare<T: Into<String> + Send, R: Into<String> + Send>(username: T, full_name: R, password: &[u8]) -> (String, String, SecBuffer) {
        let username = username.into();
        let full_name = full_name.into();


        let username = username.trim();
        let password = password.trim();
        let full_name = full_name.trim();

        (username.to_string(), full_name.to_string(), SecBuffer::from(password))
    }

    /// Gets all the internal values
    pub fn decompose(self) -> (String, SecBuffer, String, Option<ArgonSettings>) {
        (self.username, self.password_hashed, self.full_name, self.registration_settings)
    }
}

// no secret is used, as we want to ensure that the password be used even when the account info gets lost and recovery mode is desired
// TODO: Update these parameters for release mode. ALSO: `lanes` changes the hash. If the server ever has to hash, this will fail. Make a serializable argon2id config container along with the stored passwd hash
// https://www.twelve21.io/how-to-choose-the-right-parameters-for-argon2/
// Also: secret should be a hash of the symmetric key (maybe hash(A_primary XOR B_scramble)?)
// Goal: make hash time at least 0.5 seconds
// docker run -it --entrypoint kratos oryd/kratos:v0.5 hashers argon2 calibrate 0.8s
/*
fn get_argon2id_config<'a>(lanes: u32, name: &'a str) -> argon2::Config<'a> {
    argon2::Config {
        variant: argon2::Variant::Argon2id,
        version: argon2::Version::Version13,
        mem_cost: 1024 * 64,
        #[cfg(debug_assertions)]
        time_cost: 1,
        #[cfg(not(debug_assertions))]
        time_cost: 10,
        lanes,
        thread_mode: argon2::ThreadMode::Parallel,
        secret: &[],
        ad: name.as_bytes(),
        hash_length: 32
    }
}
*/