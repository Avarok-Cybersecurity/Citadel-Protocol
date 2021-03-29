/// The file extension for (H)yper(N)ode(A)ccounts (server/client NAC)
pub const NAC_SERIALIZED_EXTENSION: &'static str = "hna";
/// The file extension for (H)yper(N)ode(A)ccounts (CNAC only)
pub const CNAC_SERIALIZED_EXTENSION: &'static str = "hca";

/// For obtaniing data from a HyperNode account
pub trait HyperNodeAccountInformation {
    /// Returns either the CID or NID
    fn get_id(&self) -> u64;
}