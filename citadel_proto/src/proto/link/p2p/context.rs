//! What every step of one pair's establishment needs, gathered once when the pair's key
//! exchange finished and its coordination endpoint registered.

use citadel_crypt::ratchets::Ratchet;
use citadel_io::time::Instant;
use citadel_link::{ConnectionId, NatClass};
use citadel_types::proto::SessionSecuritySettings;
use citadel_wire::udp_traversal::turn_relay::TurnRelayConfig;
use netbeam::sync::network_endpoint::NetworkEndpoint;

use crate::proto::misc::dual_rwlock::DualRwLock;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::peer::peer_crypt::PeerNatInfo;
use crate::proto::peer::peer_layer::PeerConnectionType;
use crate::proto::remote::Ticket;
use crate::proto::session::CitadelSessionInner;

#[cfg(feature = "multi-threaded")]
pub(crate) type WeakSession<R, T> = std::sync::Weak<CitadelSessionInner<R, T>>;
#[cfg(not(feature = "multi-threaded"))]
pub(crate) type WeakSession<R, T> = std::rc::Weak<CitadelSessionInner<R, T>>;

/// One pair's facts. Every field is fixed for the pair's connection (PCND: no defaults).
pub(crate) struct P2pLinkContext<R: Ratchet, T: PlatformOps> {
    pub(crate) session: WeakSession<R, T>,
    pub(crate) session_cid: DualRwLock<Option<u64>>,
    pub(crate) local_cid: u64,
    pub(crate) peer_cid: u64,
    pub(crate) peer_connection_type: PeerConnectionType,
    /// The kernel ticket of the request that made the connection.
    pub(crate) ticket: Ticket,
    pub(crate) connection: ConnectionId,
    pub(crate) security: SessionSecuritySettings,
    pub(crate) peer_nat_info: PeerNatInfo,
    pub(crate) local_nat: NatClass,
    pub(crate) peer_nat: NatClass,
    /// The endpoint both peers registered over the relay; every stage coordinates on it.
    pub(crate) app: NetworkEndpoint,
    /// The P2P ratchet the punch's packets are sealed under.
    pub(crate) endpoint_ratchet: R,
    /// The TURN config the pair's plan was made with, if any.
    pub(crate) turn: Option<TurnRelayConfig>,
    /// When both ends begin the first punch (from the key exchange).
    pub(crate) sync_time: Instant,
}
