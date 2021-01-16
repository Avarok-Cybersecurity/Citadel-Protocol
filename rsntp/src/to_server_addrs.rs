use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

/// A trait for objects which can be converted or resolved to one or more SocketAddr values with or
/// without a port.
///
/// This is similar to the `std::net::ToSocketAddrs` trait, but port is optional. If no port is supplied
/// then the user of this trait falls back to a default one.
///
/// It is implemented for almost all types `ToSocketAddrs` is implemented for plus for some addition types
/// where the optional port is not present (`(IpAddr, u16)`, and also for simple `IpAddr`). For string
/// implementation the port is also optional, so both `<host>:<port>` or just `<host>` can be used.
///
/// The trait is intended to be opaque, details might change.
///
/// # Examples
///
/// ```no_run
/// use rsntp::ToServerAddrs;
/// use std::net::Ipv4Addr;
///
/// fn connect<A: ToServerAddrs>(addr: A) {
///   // connect to a server with default port 1234
/// }
///
/// connect("127.0.0.1"); // will connect to 127.0.0.1:1234
/// connect("127.0.0.1:456"); // will connect to 127.0.0.1:456
///
/// connect(Ipv4Addr::new(127, 0, 0, 1)); // will connect to 127.0.0.1:1234
/// connect((Ipv4Addr::new(127, 0, 0, 1), 456)); // will connect to 127.0.0.1:456
///
/// ```
pub trait ToServerAddrs {
    #[cfg(feature = "async")]
    #[doc(hidden)]
    type Return: std::net::ToSocketAddrs + tokio::net::ToSocketAddrs;
    #[cfg(not(feature = "async"))]
    #[doc(hidden)]
    type Return: std::net::ToSocketAddrs;

    #[doc(hidden)]
    fn to_server_addrs(&self, default_port: u16) -> Self::Return;
}

impl ToServerAddrs for SocketAddr {
    type Return = SocketAddr;

    fn to_server_addrs(&self, _default_port: u16) -> Self::Return {
        *self
    }
}

impl ToServerAddrs for SocketAddrV4 {
    type Return = SocketAddrV4;

    fn to_server_addrs(&self, _default_port: u16) -> Self::Return {
        *self
    }
}

impl ToServerAddrs for SocketAddrV6 {
    type Return = SocketAddrV6;

    fn to_server_addrs(&self, _default_port: u16) -> Self::Return {
        *self
    }
}

impl ToServerAddrs for IpAddr {
    type Return = (IpAddr, u16);

    fn to_server_addrs(&self, default_port: u16) -> Self::Return {
        (*self, default_port)
    }
}

impl ToServerAddrs for (IpAddr, u16) {
    type Return = (IpAddr, u16);

    fn to_server_addrs(&self, _default_port: u16) -> Self::Return {
        *self
    }
}

impl ToServerAddrs for Ipv4Addr {
    type Return = (Ipv4Addr, u16);

    fn to_server_addrs(&self, default_port: u16) -> Self::Return {
        (*self, default_port)
    }
}

impl ToServerAddrs for (Ipv4Addr, u16) {
    type Return = (Ipv4Addr, u16);

    fn to_server_addrs(&self, _default_port: u16) -> Self::Return {
        *self
    }
}

impl ToServerAddrs for Ipv6Addr {
    type Return = (Ipv6Addr, u16);

    fn to_server_addrs(&self, default_port: u16) -> Self::Return {
        (*self, default_port)
    }
}

impl ToServerAddrs for (Ipv6Addr, u16) {
    type Return = (Ipv6Addr, u16);

    fn to_server_addrs(&self, _default_port: u16) -> Self::Return {
        *self
    }
}

impl ToServerAddrs for str {
    type Return = String;

    fn to_server_addrs(&self, default_port: u16) -> Self::Return {
        if self.contains(':') {
            self.to_string()
        } else {
            self.to_string() + ":" + &default_port.to_string()
        }
    }
}

impl ToServerAddrs for String {
    type Return = String;

    fn to_server_addrs(&self, default_port: u16) -> Self::Return {
        (&**self).to_server_addrs(default_port)
    }
}

impl<'a> ToServerAddrs for (&'a str, u16) {
    type Return = (&'a str, u16);

    fn to_server_addrs(&self, _default_port: u16) -> Self::Return {
        *self
    }
}

impl<T: ToServerAddrs + ?Sized> ToServerAddrs for &T {
    type Return = T::Return;

    fn to_server_addrs(&self, default_port: u16) -> Self::Return {
        (**self).to_server_addrs(default_port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn works_for_socket_addr() {
        let s = SocketAddr::from(([127, 0, 0, 1], 1234));
        let s4 = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 1234);
        let s6 = SocketAddrV6::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 1234, 0, 0);

        assert_eq!(s.to_server_addrs(456), s);
        assert_eq!(s4.to_server_addrs(456), s4);
        assert_eq!(s6.to_server_addrs(456), s6);
    }

    #[test]
    fn works_for_ip_addr() {
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ip4 = Ipv4Addr::new(127, 0, 0, 1);
        let ip6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        assert_eq!(ip.to_server_addrs(456), (ip, 456));
        assert_eq!(ip4.to_server_addrs(456), (ip4, 456));
        assert_eq!(ip6.to_server_addrs(456), (ip6, 456));

        assert_eq!((ip, 1234).to_server_addrs(456), (ip, 1234));
        assert_eq!((ip4, 1234).to_server_addrs(456), (ip4, 1234));
        assert_eq!((ip6, 1234).to_server_addrs(456), (ip6, 1234));
    }

    #[test]
    fn works_for_strings() {
        assert_eq!("127.0.0.1".to_server_addrs(456), "127.0.0.1:456");
        assert_eq!("127.0.0.1:1234".to_server_addrs(456), "127.0.0.1:1234");
        assert_eq!(
            "127.0.0.1".to_string().to_server_addrs(456),
            "127.0.0.1:456"
        );
        assert_eq!(
            "127.0.0.1:1234".to_string().to_server_addrs(456),
            "127.0.0.1:1234"
        );

        assert_eq!(
            ("127.0.0.1", 1234).to_server_addrs(456),
            ("127.0.0.1", 1234)
        );
    }
}
