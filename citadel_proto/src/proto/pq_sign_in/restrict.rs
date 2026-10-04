//! A session signed in with a recovery code may enrol a security key and set the sign-in policy,
//! and nothing else. The server enforces it where requests enter: the packet dispatch admits only
//! the packets that carry sign-in management (and the ones that keep or end the session), and the
//! signal dispatch admits only management signals. The server's application is never told the
//! session exists, its peers are not told it is online, and it is sent no mailbox and no peer list.

use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::packet::packet_flags;
use crate::proto::peer::peer_layer::PeerSignal;
use crate::proto::session::CitadelSession;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::auth::SessionScope;

/// Whether this session signed in with a recovery code.
pub(crate) fn is_recovery<R: Ratchet, T: PlatformOps>(session: &CitadelSession<R, T>) -> bool {
    inner_state!(session.state_container).connect_state.pq.scope == SessionScope::Recovery
}

/// The packets a recovery session's client may send the server.
pub(crate) fn admits_packet(cmd_primary: u8) -> bool {
    use packet_flags::cmd::primary::*;
    matches!(
        cmd_primary,
        DO_CONNECT | KEEP_ALIVE | DO_DISCONNECT | PEER_CMD
    )
}

/// The signals a recovery session's client may send the server. Which changes it may make is the
/// management handler's decision (`SignInManagementOp::allowed_in_recovery`).
pub(crate) fn admits_signal(signal: &PeerSignal) -> bool {
    matches!(signal, PeerSignal::SignInManagement { .. })
}
