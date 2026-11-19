//! The C2S establisher's first phase, carved from `CitadelSessionManager::initiate_connection`
//! (S-C7, `ROBUST-CONNECTION-MANAGER.md` §2.2): dial the server and say where from. The later
//! phases (seal, deliver) still run inside the session; they move here as the stream swap lands
//! (lane L1 report, design gap 2).

use crate::proto::misc::local_rebind::LocalRebinder;
use crate::proto::misc::platform_ops::PlatformOps;
use citadel_io::{NetworkError, WebSocketEndpoint};
use std::marker::PhantomData;
use std::net::SocketAddr;

/// The path a C2S dial opened: the transport, and the local address it left from.
pub(crate) struct C2sPath<T: PlatformOps> {
    pub(crate) stream: T::Stream,
    pub(crate) local_addr: SocketAddr,
}

/// Opens C2S paths for one platform.
pub(crate) struct C2sEstablisher<T: PlatformOps>(PhantomData<T>);

impl<T: PlatformOps> C2sEstablisher<T> {
    /// Dials `server` (over its WebSocket `endpoint` when the account names one) and registers
    /// the transport with `rebinder`, so a QUIC client endpoint can move address later.
    pub(crate) async fn open_path(
        config: &T::ClientConfig,
        server: SocketAddr,
        endpoint: Option<WebSocketEndpoint>,
        rebinder: &LocalRebinder,
    ) -> Result<C2sPath<T>, NetworkError> {
        let addr = T::from_socket_addr(server);
        let stream = match endpoint {
            Some(endpoint) => T::connect_endpoint(config, addr, endpoint).await,
            None => T::connect(config, addr).await,
        }
        .map_err(|err| NetworkError::socket(err.to_string()))?;
        T::track_client_transport(&stream, rebinder);
        let local_addr = T::local_addr(&stream)
            .map(|addr| T::to_socket_addr(&addr))
            .map_err(|err| NetworkError::generic(err.to_string()))?;
        Ok(C2sPath { stream, local_addr })
    }
}
