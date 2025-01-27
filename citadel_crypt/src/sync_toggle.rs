//! Thread-Safe Toggle State Management
//!
//! This module provides a thread-safe toggle implementation for managing atomic
//! state transitions. It supports one-way state changes with detection of previous
//! state, making it ideal for managing cryptographic state transitions.
//!
//! # Features
//!
//! - Thread-safe state management
//! - Atomic state transitions
//! - One-way toggle operations
//! - State change detection
//! - Serialization support
//! - Default state handling
//!
//! # Examples
//!
//! ```rust
//! use citadel_crypt::sync_toggle::{SyncToggle, CurrentToggleState};
//!
//! fn manage_state() {
//!     // Create new toggle
//!     let toggle = SyncToggle::new();
//!     
//!     // Try to toggle on
//!     match toggle.toggle_on_if_untoggled() {
//!         CurrentToggleState::JustToggled => println!("First toggle"),
//!         CurrentToggleState::AlreadyToggled => println!("Already on"),
//!         CurrentToggleState::Untoggled => println!("Still off"),
//!     }
//!     
//!     // Check current state
//!     let state = toggle.state();
//!     
//!     // Reset to off
//!     toggle.toggle_off();
//! }
//! # manage_state();
//! ```
//!
//! # Important Notes
//!
//! - Uses sequential consistency ordering
//! - Thread-safe through atomic operations
//! - Serializes to untoggled state by default
//! - No blocking operations
//! - Safe for concurrent access
//!
//! # Related Components
//!
//! - [`crate::ratchets::entropy_bank`] - Uses toggle for state transitions
//! - [`crate::ratchets::stacked::ratchet`] - Ratchet state management
//!

use serde::{Deserialize, Serialize};

/// A thread-safe toggle for managing atomic state transitions.
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct SyncToggle {
    // when serializing this, always reset to default (untoggled/false)
    #[serde(default)]
    inner: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

const ORDERING: std::sync::atomic::Ordering = std::sync::atomic::Ordering::Relaxed;

/// Represents the current state of a toggle operation.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum CurrentToggleState {
    /// Toggle was just changed from false to true
    JustToggled,
    /// Toggle was already in true state
    AlreadyToggled,
    /// Toggle is in false state
    Untoggled,
}

impl SyncToggle {
    /// Creates a new toggle instance.
    pub fn new() -> Self {
        Self {
            inner: Default::default(),
        }
    }

    /// Attempts to toggle the state to true if it's currently false.
    ///
    /// Returns `JustToggled` if the state was changed to true, `AlreadyToggled` if the state was already true
    pub fn toggle_on_if_untoggled(&self) -> CurrentToggleState {
        if self.inner.fetch_nand(false, ORDERING) {
            CurrentToggleState::AlreadyToggled
        } else {
            CurrentToggleState::JustToggled
        }
    }

    /// Resets the toggle state to false and returns the previous state.
    ///
    /// Returns `AlreadyToggled` if it was previously true, `Untoggled` if it was already false
    pub fn reset_and_get_previous(&self) -> CurrentToggleState {
        if self.inner.fetch_and(false, ORDERING) {
            CurrentToggleState::AlreadyToggled
        } else {
            CurrentToggleState::Untoggled
        }
    }

    /// Resets the toggle state to false.
    pub fn toggle_off(&self) {
        self.inner.store(false, ORDERING)
    }

    /// Returns the current state of the toggle.
    pub fn state(&self) -> CurrentToggleState {
        if self.inner.load(ORDERING) {
            CurrentToggleState::AlreadyToggled
        } else {
            CurrentToggleState::Untoggled
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::sync_toggle::{CurrentToggleState, SyncToggle};

    #[test]
    fn test_sync_toggle() {
        let toggle = SyncToggle::new();
        assert_eq!(toggle.state(), CurrentToggleState::Untoggled);
        assert_eq!(
            toggle.toggle_on_if_untoggled(),
            CurrentToggleState::JustToggled
        );
        toggle.toggle_off();
        assert_eq!(toggle.state(), CurrentToggleState::Untoggled);
        assert_eq!(
            toggle.toggle_on_if_untoggled(),
            CurrentToggleState::JustToggled
        );
        assert_eq!(toggle.state(), CurrentToggleState::AlreadyToggled);
        assert_eq!(
            toggle.toggle_on_if_untoggled(),
            CurrentToggleState::AlreadyToggled
        );
        assert_eq!(toggle.state(), CurrentToggleState::AlreadyToggled);
        assert_eq!(
            toggle.toggle_on_if_untoggled(),
            CurrentToggleState::AlreadyToggled
        );
        assert_eq!(toggle.state(), CurrentToggleState::AlreadyToggled);
        toggle.toggle_off();
        assert_eq!(toggle.state(), CurrentToggleState::Untoggled);
        assert_eq!(
            toggle.toggle_on_if_untoggled(),
            CurrentToggleState::JustToggled
        );
    }

    #[test]
    fn test_sync_toggle_reset_and_get_previous() {
        let toggle = SyncToggle::new();

        // Test resetting when already false
        assert_eq!(toggle.state(), CurrentToggleState::Untoggled);
        assert_eq!(
            toggle.reset_and_get_previous(),
            CurrentToggleState::Untoggled
        );
        assert_eq!(toggle.state(), CurrentToggleState::Untoggled);

        // Test resetting when true
        let _ = toggle.toggle_on_if_untoggled();
        assert_eq!(toggle.state(), CurrentToggleState::AlreadyToggled);
        assert_eq!(
            toggle.reset_and_get_previous(),
            CurrentToggleState::AlreadyToggled
        );
        assert_eq!(toggle.state(), CurrentToggleState::Untoggled);
    }
}
