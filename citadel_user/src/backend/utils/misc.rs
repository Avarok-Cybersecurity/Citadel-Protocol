use citadel_crypt::misc::TransferType;
use std::fmt::Debug;

/// Used for determining location
pub trait StreamableTargetInformation: Debug + Send + Sync + 'static {
    /// Returns the target name. Should not include the full path,
    /// as this is determined by the backend
    fn get_target_name(&self) -> &String;
    /// Returns the CID.
    fn get_cid(&self) -> u64;
    /// Returns the
    fn get_virtual_directory(&self) -> &TransferType;
}
