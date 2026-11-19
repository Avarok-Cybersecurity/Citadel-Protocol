//! What a hole punch did, returned beside the socket it punched (S-W4): which of its attempts
//! succeeded, how long the punch took, and the local NAT it identified. Address-free by
//! construction (a [`NatClass`], never an address), so it can be reported to the kernel.

use std::time::Duration;

use citadel_types::proto::NatClass;

use crate::udp_traversal::hole_punched_socket::HolePunchedUdpSocket;

/// The facts of one successful punch.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PunchReport {
    /// The attempt that punched, from 1.
    pub attempt: usize,
    /// How many attempts the punch was allowed.
    pub attempts_allowed: usize,
    /// From the punch's start to its socket, NAT identification included.
    pub elapsed: Duration,
    /// The local NAT as this punch identified it.
    pub local_nat: NatClass,
}

/// A punched socket and its report.
#[derive(Debug)]
pub struct Punched {
    pub socket: HolePunchedUdpSocket,
    pub report: PunchReport,
}
