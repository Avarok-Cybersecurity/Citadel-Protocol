use citadel_io::tokio::io::Error;

#[derive(Debug)]
pub enum FirewallError {
    UPNP(String),
    HolePunch(String),
    Skip,
    NotApplicable,
    HolePunchExhausted,
    LocalIPAddrFail,
}

impl FirewallError {
    pub fn std(self) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::Other, self.to_string())
    }
}

impl ToString for FirewallError {
    fn to_string(&self) -> String {
        match self {
            FirewallError::UPNP(err) => err.to_string(),
            FirewallError::HolePunch(err) => err.to_string(),
            FirewallError::NotApplicable => "Method not applicable to local node".to_string(),
            FirewallError::HolePunchExhausted => "No more NAT traversal methods exist".to_string(),
            FirewallError::LocalIPAddrFail => "Unable to obtain local IP info".to_string(),
            FirewallError::Skip => "Skipped".to_string(),
        }
    }
}

impl From<FirewallError> for std::io::Error {
    fn from(val: FirewallError) -> Self {
        std::io::Error::new(std::io::ErrorKind::Other, val.to_string())
    }
}

impl From<std::io::Error> for FirewallError {
    fn from(err: Error) -> Self {
        FirewallError::HolePunch(err.to_string())
    }
}
