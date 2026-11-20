//! What one client connection demands of the server's certificate. Each connect states it: there
//! is no default, since what a server's certificate must prove differs from one server to the
//! next (a deployment's own server against a peer's self-signed one).

/// What a client connection demands of the server's certificate.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CertVerification {
    /// The server must present a certificate the node's client roots verify. A server that offers
    /// no TLS at all (plain TCP, or a `ws://` URL) is refused, and so is a certificate the roots
    /// do not verify, whatever the server says about it.
    Required,
    /// A server that says its certificate is self-signed is taken without verifying it, and a
    /// server that offers no TLS is taken too. The session's own key exchange still runs.
    SelfSignedAccepted,
}

impl CertVerification {
    /// Whether this connection must verify the server's certificate.
    pub fn is_required(self) -> bool {
        matches!(self, Self::Required)
    }
}
