//! The §3.2 table, written out independently of the core: for each state and input, the state
//! reached and the commands issued (wakes aside). Every pair not listed is a no-op.
//!
//! Resolutions of the design's open rows, recorded in the lane report: a failed first attempt
//! heals like any other (it closes only when the heal policy gives up); a seal that fails for a
//! reason other than a refusal reports the attempt's outcome; an offer while up is a half-open
//! link (degrade, then answer it); and an offer naming the held seal is a reattach.

use crate::kinds::{InputKind as I, StateKind as S};

pub fn expected(state: S, input: I) -> (S, Vec<&'static str>) {
    let to = |s: S, cmds: &[&'static str]| (s, cmds.to_vec());
    match (state, input) {
        (S::Closed, _) => to(S::Closed, &[]),
        (S::Closing, I::Retired) => to(S::Closed, &["Report"]),
        (S::Closing, _) => to(S::Closing, &[]),

        (S::Dormant, I::Start) => to(S::Resolving, &["Rendezvous"]),
        (S::Dormant, I::Shutdown | I::PeerClosing) => to(S::Closed, &["Report"]),

        (S::Resolving | S::Opening | S::Sealing, I::Shutdown | I::PeerClosing) => {
            to(S::Closed, &["ClosePath", "Report"])
        }
        (S::Up | S::Degraded | S::Reattaching, I::Shutdown | I::PeerClosing) => {
            to(S::Closing, &["ClosePath", "Retire"])
        }
        (S::Resealing, I::Shutdown | I::PeerClosing) => {
            to(S::Closing, &["ClosePath", "Retire", "Retire"])
        }

        (S::Resolving, I::Met) => to(S::Opening, &["OpenPath"]),
        (S::Resolving, I::MeetFailed | I::Tick) => to(S::Degraded, &["Report"]),

        (S::Opening, I::PathOpened) => to(S::Sealing, &["Seal"]),
        (S::Opening, I::PathFailed | I::Tick) => to(S::Opening, &["OpenPath"]),

        (S::Sealing | S::Reattaching, I::Sealed) => to(S::Up, &["Deliver", "Buffer", "Report"]),
        (S::Sealing, I::SealFailedRefused) => to(S::Closed, &["ClosePath", "Report"]),
        (S::Reattaching, I::SealFailedRefused) => to(S::Closing, &["ClosePath", "Retire"]),
        (S::Reattaching, I::SealFailedUnknown) => to(S::Sealing, &["Retire", "Seal"]),
        (S::Sealing, I::SealFailedHandshake | I::SealFailedUnknown | I::Tick)
        | (S::Reattaching, I::SealFailedHandshake | I::Tick) => {
            to(S::Degraded, &["ClosePath", "Report"])
        }

        (S::Up, I::LostTransient | I::ProbeFailed) => to(S::Degraded, &["Buffer", "Report"]),
        (S::Up, I::LostRoute) => to(S::Up, &["FallBackToRelay", "OpenPath"]),
        (S::Up, I::NatChanged | I::InterfaceChanged) => to(S::Up, &["Rebind"]),
        (S::Up, I::SettingsAgreed) => to(S::Resealing, &["ForkPath", "Seal"]),
        (S::Up, I::OfferHeld) => to(S::Reattaching, &["Buffer", "Report", "Reattach"]),
        (S::Up, I::OfferFresh) => to(S::Sealing, &["Buffer", "Report", "Seal"]),

        (S::Degraded, I::Tick) => to(S::Opening, &["OpenPath"]),
        (S::Degraded, I::OfferHeld) => to(S::Reattaching, &["Reattach"]),
        (S::Degraded, I::OfferFresh) => to(S::Sealing, &["Seal"]),

        (S::Resealing, I::Sealed) => to(S::Up, &["Cutover", "Retire", "Report"]),
        (
            S::Resealing,
            I::SealFailedHandshake | I::SealFailedRefused | I::SealFailedUnknown | I::Tick,
        ) => to(S::Up, &["Retire"]),
        (S::Resealing, I::LostTransient | I::LostRoute) => {
            to(S::Degraded, &["Retire", "Buffer", "Report"])
        }

        (state, _) => to(state, &[]),
    }
}
