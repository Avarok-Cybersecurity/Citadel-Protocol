use crate::account_manager::AccountManager;
use crate::prelude::ClientNetworkAccount;
use crate::misc::AccountError;

/// The file extension for (H)yper(N)ode(A)ccounts (server/client NAC)
pub const NAC_SERIALIZED_EXTENSION: &'static str = "hna";
/// The file extension for (H)yper(N)ode(A)ccounts (CNAC only)
pub const CNAC_SERIALIZED_EXTENSION: &'static str = "hca";

/// For obtaniing data from a HyperNode account
pub trait HyperNodeAccountInformation {
    /// Returns either the CID or NID
    fn get_id(&self) -> u64;
}

/// A convenience wrapper for passing arguments to functions that require searches for a user
pub enum UserIdentifier {
    /// Raw user ID
    ID(u64),
    /// Username connected by an unspecified ID
    Username(String)
}

impl UserIdentifier {
    /// Searches for the account
    pub async fn search(&self, account_manager: &AccountManager) -> Result<Option<ClientNetworkAccount>, AccountError> {
        match self {
            Self::ID(cid) => account_manager.get_client_by_cid(*cid).await,
            Self::Username(uname) => account_manager.get_client_by_username(uname).await
        }
    }
}

impl From<String> for UserIdentifier {
    fn from(username: String) -> Self {
        Self::Username(username)
    }
}

impl From<&str> for UserIdentifier {
    fn from(username: &str) -> Self {
        Self::Username(username.to_string())
    }
}

impl From<u64> for UserIdentifier {
    fn from(cid: u64) -> Self {
        Self::ID(cid)
    }
}