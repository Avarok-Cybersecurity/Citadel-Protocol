/// Used for determining location
pub trait StreamableTargetInformation: Send + 'static {
    /// Returns the target name. Should not include the full path,
    /// as this is determined by the backend
    fn get_target_name(&self) -> &String;
}