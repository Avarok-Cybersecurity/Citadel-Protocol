//! The states and the input kinds the table spans, and how a state or a command is named.

use citadel_link::{LinkCommand, LinkState};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StateKind {
    Dormant,
    Resolving,
    Opening,
    Sealing,
    Reattaching,
    Up,
    Degraded,
    Resealing,
    Closing,
    Closed,
}

pub const STATES: [StateKind; 10] = [
    StateKind::Dormant,
    StateKind::Resolving,
    StateKind::Opening,
    StateKind::Sealing,
    StateKind::Reattaching,
    StateKind::Up,
    StateKind::Degraded,
    StateKind::Resealing,
    StateKind::Closing,
    StateKind::Closed,
];

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum InputKind {
    Start,
    Met,
    MeetFailed,
    PathOpened,
    PathFailed,
    Sealed,
    SealFailedHandshake,
    SealFailedRefused,
    SealFailedUnknown,
    Delivered,
    LostTransient,
    LostRoute,
    PeerClosing,
    NatChanged,
    InterfaceChanged,
    Rebound,
    Suspended,
    Resumed,
    SettingsAgreed,
    OfferHeld,
    OfferFresh,
    PeerReachable,
    ProbeOk,
    ProbeFailed,
    Retired,
    Tick,
    Shutdown,
}

pub const INPUTS: [InputKind; 27] = [
    InputKind::Start,
    InputKind::Met,
    InputKind::MeetFailed,
    InputKind::PathOpened,
    InputKind::PathFailed,
    InputKind::Sealed,
    InputKind::SealFailedHandshake,
    InputKind::SealFailedRefused,
    InputKind::SealFailedUnknown,
    InputKind::Delivered,
    InputKind::LostTransient,
    InputKind::LostRoute,
    InputKind::PeerClosing,
    InputKind::NatChanged,
    InputKind::InterfaceChanged,
    InputKind::Rebound,
    InputKind::Suspended,
    InputKind::Resumed,
    InputKind::SettingsAgreed,
    InputKind::OfferHeld,
    InputKind::OfferFresh,
    InputKind::PeerReachable,
    InputKind::ProbeOk,
    InputKind::ProbeFailed,
    InputKind::Retired,
    InputKind::Tick,
    InputKind::Shutdown,
];

pub fn kind_of(state: &LinkState) -> StateKind {
    match state {
        LinkState::Dormant => StateKind::Dormant,
        LinkState::Resolving { .. } => StateKind::Resolving,
        LinkState::Opening { .. } => StateKind::Opening,
        LinkState::Sealing { .. } => StateKind::Sealing,
        LinkState::Reattaching { .. } => StateKind::Reattaching,
        LinkState::Up { .. } => StateKind::Up,
        LinkState::Degraded { .. } => StateKind::Degraded,
        LinkState::Resealing { .. } => StateKind::Resealing,
        LinkState::Closing { .. } => StateKind::Closing,
        LinkState::Closed { .. } => StateKind::Closed,
    }
}

/// Every command but the wake (the wake is checked by the schedule tests), by name.
pub fn names(commands: &[LinkCommand]) -> Vec<&'static str> {
    commands
        .iter()
        .filter_map(|c| match c {
            LinkCommand::OpenPath { .. } => Some("OpenPath"),
            LinkCommand::Rendezvous { .. } => Some("Rendezvous"),
            LinkCommand::Seal { .. } => Some("Seal"),
            LinkCommand::Reattach { .. } => Some("Reattach"),
            LinkCommand::Deliver { .. } => Some("Deliver"),
            LinkCommand::ForkPath { .. } => Some("ForkPath"),
            LinkCommand::Cutover { .. } => Some("Cutover"),
            LinkCommand::Retire { .. } => Some("Retire"),
            LinkCommand::ClosePath => Some("ClosePath"),
            LinkCommand::FallBackToRelay => Some("FallBackToRelay"),
            LinkCommand::AttachRoute { .. } => Some("AttachRoute"),
            LinkCommand::Rebind { .. } => Some("Rebind"),
            LinkCommand::Probe => Some("Probe"),
            LinkCommand::Buffer(_) => Some("Buffer"),
            LinkCommand::Report(_) => Some("Report"),
            LinkCommand::ScheduleWake(_) => None,
        })
        .collect()
}
