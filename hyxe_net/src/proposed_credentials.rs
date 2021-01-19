use bytes::BytesMut;
use secstr::SecVec;

use hyxe_crypt::aes_gcm::AES_GCM_NONCE_LEN_BYTES;
use bstr::ByteSlice;
use rand::prelude::ThreadRng;
use rand::Rng;
use bytes::buf::BufMutExt;
use serde::{Serialize, Deserialize};


/// When creating credentials, this is required
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedCredentials {
    ///
    pub username: String,
    ///
    pub password: SecVec<u8>,
    ///
    pub full_name: String,

    pub nonce: [u8; AES_GCM_NONCE_LEN_BYTES]
}

impl ProposedCredentials {
    /// Creates a new instance of Self
    pub fn new<T: ToString, R: ToString>(full_name: T, username: R, password: SecVec<u8>, password_repeated: SecVec<u8>, nonce: Option<&[u8]>) -> Option<Self> {
        let password_check_0 = password.unsecure();
        let password_check_1 = password_repeated.unsecure();
        if password_check_0 != password_check_1 {
            return None;
        }


        let (username, full_name, password, nonce) = Self::sanitize_and_prepare(username, full_name, password_check_0, nonce);

        Some(Self { username, password, full_name, nonce })
    }

    /// For storing the data
    pub fn new_unchecked<T: ToString, R: ToString>(full_name: T, username: R, password: SecVec<u8>, nonce: Option<&[u8]>) -> Self {
        let (username, full_name, password, nonce) = Self::sanitize_and_prepare(username, full_name, password.unsecure(), nonce);

        Self { username, password, full_name, nonce }
    }

    /// This does not sanitize nor compute the hash; it merely acts as a vessel for storing the data
    ///
    /// The server should call this
    pub fn new_from_hashed<T: ToString, R: ToString>(full_name: T, username: R, hashed_password: SecVec<u8>, hash_nonce: [u8; AES_GCM_NONCE_LEN_BYTES]) -> Self {
        let username = username.to_string();
        let full_name = full_name.to_string();
        let password = hashed_password;
        let nonce = hash_nonce;

        Self { username, password, full_name, nonce }
    }

    fn sanitize_and_prepare<T: ToString, R: ToString>(username: T, full_name: R, password: &[u8], nonce: Option<&[u8]>) -> (String, String, SecVec<u8>, [u8; AES_GCM_NONCE_LEN_BYTES]) {
        let username = username.to_string();
        let full_name = full_name.to_string();


        let username = username.trim();
        let password = password.trim();
        let full_name = full_name.trim();

        log::info!("\n\rPassword Raw({}): {:?}", password.len(), password);

        let nonce = get_nonce(nonce);
        let password_hash = SecVec::new(argon2::hash_raw(password, &nonce as &[u8], &get_argon2id_config(num_cpus::get() as u32, username)).unwrap());

        log::info!("\n\rHashed passwd({}): {:?}", password_hash.unsecure().len(), password_hash.unsecure());
        (username.to_string(), full_name.to_string(), password_hash, nonce)
    }

    /// Inscribed self into the proposed buffer, and then returns the length of the plaintext username, password, and full_name, respectively
    pub fn inscribe_into(&self, input: &mut BytesMut) -> (usize, usize, usize, usize) {
        let username_bytes = self.username.as_bytes();
        let password_bytes = self.password.unsecure();
        let full_name_bytes = self.full_name.as_bytes();
        let nonce = &self.nonce as &[u8];

        let plaintext_username_len = username_bytes.len();
        let plaintext_password_len = password_bytes.len();
        let plaintext_fullname_len = full_name_bytes.len();
        let nonce_len = nonce.len();

        let amt = bincode2::serialized_size(self).unwrap();
        input.reserve(amt as usize);
        
        bincode2::serialize_into(input.writer(), self).unwrap();

        (plaintext_username_len, plaintext_password_len, plaintext_fullname_len, nonce_len)
    }

    /// Useful for determining the length for a pre-allocated buffer
    pub fn get_expected_ciphertext_length(&self) -> usize {
        hyxe_crypt::net::crypt_splitter::calculate_aes_gcm_output_length(self.username.as_bytes().len() + self.password.unsecure().len() + self.full_name.as_bytes().len())
    }

    /// Returns the plaintext length of the username, password, and full_name, respectively
    pub fn get_item_lengths(&self) -> (usize, usize, usize) {
        (self.username.as_bytes().len(), self.password.unsecure().len(), self.full_name.as_bytes().len())
    }

    /// Consumes self and returns the individual elements
    pub fn decompose(self) -> (String, SecVec<u8>, String, [u8; AES_GCM_NONCE_LEN_BYTES]) {
        (self.username, self.password, self.full_name, self.nonce)
    }

    pub fn decompose_credentials(&self) -> (&[u8], &[u8]) {
        (self.username.as_bytes(), self.password.unsecure())
    }
}

/// no secret is used, as we want to ensure that the password be used even when the account info gets lost and recovery mode is desired
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

fn generate_salt() -> [u8; AES_GCM_NONCE_LEN_BYTES] {
    let mut rng = ThreadRng::default();
    let mut salt: [u8; AES_GCM_NONCE_LEN_BYTES] = Default::default();
    rng.fill(&mut salt);
    salt
}

fn get_nonce(nonce: Option<&[u8]>) -> [u8; AES_GCM_NONCE_LEN_BYTES] {
    nonce.map(|inner| {
        let mut ret: [u8; AES_GCM_NONCE_LEN_BYTES] = Default::default();
        ret.copy_from_slice(inner);
        ret
    }).unwrap_or_else(|| generate_salt())
}