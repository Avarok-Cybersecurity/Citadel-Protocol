use tokio::io::Error;

#[derive(Debug)]
pub enum FirewallError {
    UPNP(String),
    HolePunch(String),
    NotApplicable,
    HolePunchExhausted,
    LocalIPAddrFail
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
            FirewallError::LocalIPAddrFail => "Unable to obtain local IP info".to_string()
        }
    }
}

impl Into<std::io::Error> for FirewallError {
    fn into(self) -> Error {
        std::io::Error::new(std::io::ErrorKind::Other, self.to_string())
    }
}