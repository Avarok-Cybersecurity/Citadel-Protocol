//! The path policy an example server uses. A server requires one: the SDK has no default.
//!
//! This is the precedence Citadel's own servers use: try a direct (hole-punched) path first,
//! then a peer relay, then TURN, and otherwise stay on the server relay, letting every class of
//! traffic use every path. An operator who pays for relayed bytes might instead remove `Media`
//! from the server relay's classes.

use citadel_sdk::prelude::{PathClasses, PathKind, PathPolicy, PathRule};
use std::time::Duration;

pub fn every_path_in_order() -> PathPolicy {
    let rules = PathKind::ALL
        .into_iter()
        .map(|kind| PathRule {
            kind,
            enabled: true,
            attempt_timeout: Duration::from_secs(30),
            cost_weight: 1,
            classes: PathClasses::ALL,
        })
        .collect();
    PathPolicy::new(rules, PathClasses::NONE).expect("a valid path policy")
}
