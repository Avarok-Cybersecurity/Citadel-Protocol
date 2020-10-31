use crate::misc::AccountError;
use async_trait::async_trait;
use std::path::PathBuf;

/// The file extension for (H)yper(N)ode(A)ccounts (server/client NAC)
pub const NAC_SERIALIZED_EXTENSION: &'static str = "hna";
/// The file extension for (H)yper(N)ode(A)ccounts (CNAC only)
pub const CNAC_SERIALIZED_EXTENSION: &'static str = "hca";

/// For obtaniing data from a HyperNode account
#[async_trait]
pub trait HyperNodeAccountInformation {
    /// Returns either the CID or NID
    fn get_id(&self) -> u64;
    /// Clones the underlying path from where the object was deserialized from
    async fn get_filesystem_location(&self) -> PathBuf;
    /// Saves the account to memory
    async fn async_save_to_local_fs(self) -> Result<(), AccountError<String>>;
}