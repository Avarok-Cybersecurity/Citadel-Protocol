use std::fmt::Formatter;
use tokio::io::Error;

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

impl std::fmt::Display for FirewallError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                FirewallError::UPNP(err) | FirewallError::HolePunch(err) => err,
                FirewallError::NotApplicable => "Method not applicable to local node",
                FirewallError::HolePunchExhausted => "No more NAT traversal methods exist",
                FirewallError::LocalIPAddrFail => "Unable to obtain local IP info",
                FirewallError::Skip => "Skipped",
            }
        )
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
