//! Throttling sign-in and recovery attempts on the server, before any OPRF evaluation or
//! encapsulation is spent on them.
//!
//! Pure: [`SignInThrottle`] holds counters and decides; the caller passes the time and the
//! client's address, and nothing here reads a clock or does I/O. Each attempt is counted under
//! two keys: the username with the client's network (an IPv4 /24 or an IPv6 /64), and the
//! username alone, whose limits are [`PER_USER_FACTOR`] times wider, so guesses spread over many
//! networks still meet one limit per account. A recovery attempt counts [`RECOVERY_COST`] times:
//! it is the one that needs no device bundle.
//!
//! A refused attempt reads exactly like a failed one to the client, so the throttle is no oracle
//! for which names exist; it says only that someone has been failing for this name.

mod policy;

pub use policy::{Attempt, Decision, ThrottlePolicy, PER_USER_FACTOR, RECOVERY_COST};

use crate::misc::AccountError;
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Key {
    username: String,
    /// The client's network; `None` for the username-only key.
    network: Option<[u8; 16]>,
}

#[derive(Clone, Debug, Default)]
struct Entry {
    window_start_ms: u64,
    starts: u32,
    failures: u32,
    locked_until_ms: u64,
    lockouts: u32,
    last_seen_ms: u64,
}

/// The counters of every key the server is tracking.
#[derive(Debug)]
pub struct SignInThrottle {
    policy: ThrottlePolicy,
    entries: HashMap<Key, Entry>,
}

impl SignInThrottle {
    pub fn new(policy: ThrottlePolicy) -> Result<Self, AccountError> {
        policy.validate()?;
        Ok(Self {
            policy,
            entries: HashMap::new(),
        })
    }

    pub fn policy(&self) -> &ThrottlePolicy {
        &self.policy
    }

    /// Called before the server spends anything on an attempt. A refused attempt is not counted.
    pub fn admit(
        &mut self,
        username: &str,
        source: Option<IpAddr>,
        attempt: Attempt,
        now_ms: u64,
    ) -> Decision {
        let keys = keys(username, source);
        let cost = attempt.cost();
        let policy = self.policy;
        for (key, factor) in &keys {
            if let Some(entry) = self.entries.get_mut(key) {
                roll(entry, &policy, now_ms);
                let over = entry.starts + cost > policy.max_starts_per_window * factor;
                if entry.locked_until_ms > now_ms || over {
                    return Decision::Refuse;
                }
            }
        }
        for (key, _) in keys {
            let Some(entry) = self.entry(key, now_ms) else {
                return Decision::Refuse;
            };
            entry.starts += cost;
        }
        Decision::Admit
    }

    /// A proof that failed. Past the limit, the key is locked out for the next lockout length.
    pub fn record_failure(
        &mut self,
        username: &str,
        source: Option<IpAddr>,
        attempt: Attempt,
        now_ms: u64,
    ) {
        let policy = self.policy;
        for (key, factor) in keys(username, source) {
            let Some(entry) = self.entry(key, now_ms) else {
                continue;
            };
            entry.failures += attempt.cost();
            if entry.failures >= policy.max_failures * factor {
                let doubling = 1u64.checked_shl(entry.lockouts).unwrap_or(u64::MAX);
                let length = policy.lockout_base_ms.saturating_mul(doubling);
                entry.locked_until_ms = now_ms.saturating_add(length.min(policy.lockout_max_ms));
                entry.lockouts = entry.lockouts.saturating_add(1);
                entry.failures = 0;
            }
        }
    }

    /// A proof that verified: both keys start over.
    pub fn record_success(&mut self, username: &str, source: Option<IpAddr>) {
        for (key, _) in keys(username, source) {
            let _ = self.entries.remove(&key);
        }
    }

    /// The entry for `key`, made room for when the table is full. `None` when every tracked key
    /// is locked out, so none may be forgotten.
    fn entry(&mut self, key: Key, now_ms: u64) -> Option<&mut Entry> {
        if !self.entries.contains_key(&key) && self.entries.len() >= self.policy.max_tracked_keys {
            self.make_room(now_ms)?;
        }
        let policy = self.policy;
        let entry = self.entries.entry(key).or_insert_with(|| Entry {
            window_start_ms: now_ms,
            ..Default::default()
        });
        roll(entry, &policy, now_ms);
        entry.last_seen_ms = now_ms;
        Some(entry)
    }

    fn make_room(&mut self, now_ms: u64) -> Option<()> {
        let idle_after = self.policy.window_ms.max(self.policy.lockout_max_ms);
        self.entries.retain(|_, entry| {
            entry.locked_until_ms > now_ms || now_ms.saturating_sub(entry.last_seen_ms) < idle_after
        });
        if self.entries.len() < self.policy.max_tracked_keys {
            return Some(());
        }
        let oldest = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.locked_until_ms <= now_ms)
            .min_by_key(|(_, entry)| entry.last_seen_ms)
            .map(|(key, _)| key.clone())?;
        self.entries.remove(&oldest).map(|_| ())
    }

    #[cfg(test)]
    pub(crate) fn tracked(&self) -> usize {
        self.entries.len()
    }
}

/// A new window once the last one has passed. Lockout history is kept until a success.
fn roll(entry: &mut Entry, policy: &ThrottlePolicy, now_ms: u64) {
    if now_ms.saturating_sub(entry.window_start_ms) >= policy.window_ms {
        entry.window_start_ms = now_ms;
        entry.starts = 0;
        entry.failures = 0;
    }
}

/// The (username, network) key, then the username-only key, with their limit factors.
fn keys(username: &str, source: Option<IpAddr>) -> [(Key, u32); 2] {
    let username = username.to_string();
    [
        (
            Key {
                username: username.clone(),
                network: Some(network_of(source)),
            },
            1,
        ),
        (
            Key {
                username,
                network: None,
            },
            PER_USER_FACTOR,
        ),
    ]
}

/// An IPv4 address's /24 or an IPv6 address's /64; an unknown address is one network of its own.
fn network_of(source: Option<IpAddr>) -> [u8; 16] {
    let mut network = [0u8; 16];
    match source.map(|ip| ip.to_canonical()) {
        Some(IpAddr::V4(v4)) => {
            network[0] = 4;
            network[1..4].copy_from_slice(&v4.octets()[..3]);
        }
        Some(IpAddr::V6(v6)) => {
            network[0] = 6;
            network[1..9].copy_from_slice(&v6.octets()[..8]);
        }
        None => network[0] = 0xFF,
    }
    network
}
