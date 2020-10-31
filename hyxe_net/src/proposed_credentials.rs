use bytes::BufMut;
use secstr::SecVec;

use ez_pqcrypto::PostQuantumContainer;
use hyxe_crypt::aes_gcm::AES_GCM_NONCE_LEN_BYTES;
use bstr::ByteSlice;

/// When creating credentials, this is required
#[derive(Debug)]
pub struct ProposedCredentials {
    ///
    pub username: String,
    ///
    pub password: SecVec<u8>,
    ///
    pub full_name: String,
}

impl ProposedCredentials {
    /// Creates a new instance of Self
    pub fn new<T: ToString, R: ToString>(full_name: T, username: R, password: SecVec<u8>, password_repeated: SecVec<u8>) -> Option<Self> {
        let password_check_0 = password.unsecure();
        let password_check_1 = password_repeated.unsecure();
        if password_check_0 != password_check_1 {
            return None;
        }


        let (username, full_name, password) = Self::sanitize(username, full_name, password_check_0);

        Some(Self { username, password, full_name })
    }

    /// For storing the data
    pub fn new_unchecked<T: ToString, R: ToString>(full_name: T, username: R, password: SecVec<u8>) -> Self {
        let username = username.to_string();
        let full_name = full_name.to_string();

        let (username, full_name, password) = Self::sanitize(username, full_name, password.unsecure());

        Self { username, password, full_name }
    }

    fn sanitize<T: ToString, R: ToString>(username: T, full_name: R, password: &[u8]) -> (String, String, SecVec<u8>) {
        let username = username.to_string();
        let full_name = full_name.to_string();


        let username = username.trim();
        let password = password.trim();
        let full_name = full_name.trim();

        (username.to_string(), full_name.to_string(), SecVec::from(password))
    }

    /// Inscribed self into the proposed buffer, and then returns the length of the plaintext username, password, and full_name, respectively
    pub fn inscribe_into<B: BufMut>(&self, input: &mut B, nonce: &[u8; AES_GCM_NONCE_LEN_BYTES], post_quantum: &PostQuantumContainer) -> (usize, usize, usize) {
        let username_bytes = self.username.as_bytes();
        let password_bytes = self.password.unsecure();
        let full_name_bytes = self.full_name.as_bytes();

        let plaintext_username_len = username_bytes.len();
        let plaintext_password_len = password_bytes.len();
        let plaintext_fullname_len = full_name_bytes.len();

        let mut full_plaintext: Vec<u8> = Vec::with_capacity(plaintext_username_len + plaintext_password_len + plaintext_fullname_len);
        for byte in username_bytes {
            full_plaintext.push(*byte)
        }

        for byte in password_bytes {
            full_plaintext.push(*byte)
        }

        for byte in full_name_bytes {
            full_plaintext.push(*byte)
        }

        let full_ciphertext = post_quantum.encrypt(&full_plaintext as &[u8], nonce).unwrap();

        input.put(full_ciphertext.as_ref());
        (plaintext_username_len, plaintext_password_len, plaintext_fullname_len)
    }

    /// Useful for determining the length for a pre-allocated buffer
    pub fn get_expected_ciphertext_length(&self) -> usize {
        hyxe_crypt::net::crypt_splitter::calculate_aes_gcm_output_length(self.username.as_bytes().len() + self.password.unsecure().len() + self.full_name.as_bytes().len())
    }

    /// Returns the plaintext length of the username, password, and full_name, repectively
    pub fn get_item_lengths(&self) -> (usize, usize, usize) {
        (self.username.as_bytes().len(), self.password.unsecure().len(), self.full_name.as_bytes().len())
    }

    /// Consumes self and returns the individual elements
    pub fn decompose(self) -> (String, SecVec<u8>, String) {
        (self.username, self.password, self.full_name)
    }
}

impl Clone for ProposedCredentials {
    fn clone(&self) -> Self {
        let username = self.username.clone();
        let full_name = self.full_name.clone();
        let password = SecVec::new(self.password.unsecure().to_vec());
        Self { username, password, full_name }
    }
}