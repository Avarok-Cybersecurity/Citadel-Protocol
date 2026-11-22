//! What a member is told when its group ends for it, and when it gets a group's state back.

use serde::{Deserialize, Serialize};
#[cfg(feature = "typescript")]
use ts_rs::TS;

/// Why a group ended for the member told.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum GroupEndReason {
    /// The owner closed the group.
    ClosedByOwner,
    /// The owner removed this member.
    Removed,
    /// A command hierarchy's owner left, or its session ended. The hierarchy's ranks are the
    /// owner's alone, so the group cannot go on without it; the members may start a new group.
    HierarchyOwnerGone,
}

/// Where a device's state for a group came from when the group was restored to it.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum GroupStateSource {
    /// The state this device kept. Everything it could read before, it reads again.
    ThisDevice,
    /// The state the server keeps sealed for the account, opened with the account's key (a
    /// recovered or new device). The device reads what the account could read before.
    Backup,
    /// No state was left: the member joined again, and reads only what is sent from now on.
    Rejoined,
    /// No state was left: the owner founded the group afresh, and every member joins again.
    Refounded,
}
