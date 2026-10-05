//! The credentials a login or registration carries.
//!
//! They name the account and nothing more. A password never travels and is never hashed here:
//! post-quantum sign-in turns it into an ML-KEM key on the client (see `auth::pq`), and the
//! server proves that key by encapsulation. A passwordless (transient) login carries only its
//! username.
//!
//! # Important Notes
//!
//! * Usernames and full names are trimmed (Unicode `White_Space`)
//! * `password_hashed` is always empty since the Argon2 sunset; it keeps the wire shape older
//!   nodes parse
//!
//! # Related Components
//!
//! * `DeclaredAuthenticationMode` - Final auth state
//! * `ServerMiscSettings` - Server validation rules
//! * `AccountManager` - Uses proposed credentials

use crate::auth::DeclaredAuthenticationMode;
use crate::misc::AccountError;
use bstr::ByteSlice;
use citadel_types::crypto::SecBuffer;
use serde::{Deserialize, Serialize};
use sha3::Digest;

/// When creating credentials, this is required
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(variant_size_differences)]
pub enum ProposedCredentials {
    /// Denotes that credentials will be used
    Enabled {
        /// Username of the client
        username: String,
        /// Empty. Before the Argon2 sunset it carried the client's Argon2 hash; it stays so the
        /// encoding is the one every node since 0.11 parses.
        password_hashed: SecBuffer,
        /// Full name or alternative moniker
        full_name: String,
    },

    /// Denotes that credentials will not be used (passwordless)
    Disabled { username: String },
}

impl ProposedCredentials {
    /// The credentials a post-quantum login carries in connect STAGE0: the account's names. The
    /// factors are proven by the exchange that precedes STAGE0.
    pub fn post_quantum(username: String, full_name: String) -> Self {
        Self::Enabled {
            username,
            password_hashed: SecBuffer::empty(),
            full_name,
        }
    }

    /// Generates an empty skeleton for authless mode
    pub fn transient<T: Into<String>>(username: T) -> Self {
        Self::Disabled {
            username: username.into(),
        }
    }

    /// The credentials a registration carries, with the names trimmed of whitespace (as defined by
    /// the Unicode Derived Core Property `White_Space`). The password goes to the post-quantum
    /// registration instead, through [`Self::registration_password`].
    pub fn new_register<T: Into<String>, R: Into<String>>(full_name: T, username: R) -> Self {
        let (username, full_name) = Self::sanitize(username, full_name);
        Self::post_quantum(username, full_name)
    }

    /// The password a post-quantum registration turns into a key: trimmed, as the names are.
    pub fn registration_password(password_unhashed: &SecBuffer) -> SecBuffer {
        password_unhashed.as_ref().trim().into()
    }

    fn sanitize<T: Into<String>, R: Into<String>>(username: T, full_name: R) -> (String, String) {
        let username = username.into();
        let full_name = full_name.into();
        (username.trim().to_string(), full_name.trim().to_string())
    }

    /// The username and full name. A passwordless login has no full name.
    pub fn decompose(self) -> (String, String) {
        match self {
            Self::Enabled {
                username,
                full_name,
                ..
            } => (username, full_name),
            Self::Disabled { username } => (username, String::new()),
        }
    }

    /// `SHA3-256` of the password, the input of the password factor's OPRF.
    pub fn password_transform<T: AsRef<[u8]>>(password_raw: T) -> SecBuffer {
        let mut digest = sha3::Sha3_256::default();
        digest.update(password_raw.as_ref());
        digest.finalize().to_vec().into()
    }

    /// The account a passwordless registration creates. A password account is created only by a
    /// post-quantum registration, which enrols its factors.
    pub(crate) fn into_transient_auth_store(
        self,
    ) -> Result<DeclaredAuthenticationMode, AccountError> {
        match self {
            Self::Disabled { username } => Ok(DeclaredAuthenticationMode::Transient {
                username,
                full_name: "authless.client".to_string(),
            }),
            Self::Enabled { .. } => Err(citadel_io::error!(
                citadel_io::ErrorCode::PqSignInUnavailable,
                "a password account registers with post-quantum factors"
            )),
        }
    }

    /// Returns true if passwordless
    pub fn is_passwordless(&self) -> bool {
        matches!(self, Self::Disabled { .. })
    }

    /// Returns the username or uuid of the client
    pub fn username(&self) -> &str {
        match self {
            ProposedCredentials::Enabled { username, .. }
            | ProposedCredentials::Disabled { username } => username.as_str(),
        }
    }

    /// Compares usernames for equality
    pub fn compare_username(&self, other: &[u8]) -> bool {
        self.username().as_bytes() == other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled(user: &str) -> ProposedCredentials {
        ProposedCredentials::Enabled {
            username: user.to_string(),
            password_hashed: SecBuffer::empty(),
            full_name: "Full Name".to_string(),
        }
    }

    #[test]
    fn transient_is_passwordless_and_username() {
        let t = ProposedCredentials::transient("bob");
        assert!(t.is_passwordless());
        assert_eq!(t.username(), "bob");
        let e = enabled("alice");
        assert!(!e.is_passwordless());
        assert_eq!(e.username(), "alice");
    }

    #[test]
    fn password_transform_is_deterministic_sha3_256() {
        // Arbitrary distinct byte inputs (not credential-shaped, so secret scanners stay quiet).
        let input_a: &[u8] = &[1, 2, 3, 4];
        let input_b: &[u8] = &[9, 9, 9];
        let a = ProposedCredentials::password_transform(input_a);
        let a2 = ProposedCredentials::password_transform(input_a);
        let b = ProposedCredentials::password_transform(input_b);
        assert_eq!(a.as_ref(), a2.as_ref());
        assert_ne!(a.as_ref(), b.as_ref());
        assert_eq!(a.as_ref().len(), 32); // SHA3-256 digest
    }

    #[test]
    fn registration_trims_the_names_and_the_password() {
        let creds = ProposedCredentials::new_register("  Alice S  ", "  alice  ");
        assert_eq!(creds.decompose(), ("alice".into(), "Alice S".into()));
        let password = ProposedCredentials::registration_password(&b"  pwd  "[..].into());
        assert_eq!(password.as_ref(), b"pwd");
    }

    #[test]
    fn decompose_enabled_and_disabled() {
        assert_eq!(
            enabled("alice").decompose(),
            ("alice".into(), "Full Name".into())
        );
        assert_eq!(
            ProposedCredentials::transient("bob").decompose(),
            ("bob".into(), String::new())
        );
    }

    #[test]
    fn only_passwordless_credentials_make_an_account_without_factors() {
        let transient = ProposedCredentials::transient("bob").into_transient_auth_store();
        assert!(transient.unwrap().is_transient());
        let refused = enabled("alice").into_transient_auth_store().unwrap_err();
        assert_eq!(refused.code, citadel_io::ErrorCode::PqSignInUnavailable);
    }

    #[test]
    fn compare_username_matches_exactly() {
        assert!(enabled("alice").compare_username(b"alice"));
        assert!(!enabled("alice").compare_username(b"bob"));
        assert!(ProposedCredentials::transient("x").compare_username(b"x"));
    }
}
