use serde::{Serialize, Deserialize};

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct SyncToggle {
    // when serializing this, always reset to default (untoggled/false)
    #[serde(default)]
    inner: std::sync::Arc<std::sync::atomic::AtomicBool>
}

const ORDERING: std::sync::atomic::Ordering = std::sync::atomic::Ordering::SeqCst;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum CurrentToggleState {
    JustToggled,
    AlreadyToggled,
    Untoggled
}

impl SyncToggle {
    pub fn new() -> Self {
        Self { inner: Default::default()  }
    }

    // Returns true if value has already been toggled to true,
    // returns false otherwise, leaving a true value in its place
    pub fn toggle_on_if_untoggled(&self) -> CurrentToggleState {
        if self.inner.fetch_nand(false, ORDERING) {
            CurrentToggleState::AlreadyToggled
        } else {
            CurrentToggleState::JustToggled
        }
    }

    pub fn toggle_off(&self) {
        self.inner.store(false, ORDERING)
    }

    pub fn get(&self) -> CurrentToggleState {
        if self.inner.load(ORDERING) {
            CurrentToggleState::AlreadyToggled
        } else {
            CurrentToggleState::Untoggled
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::sync_toggle::{SyncToggle, CurrentToggleState};

    #[test]
    fn test_sync_toggle() {
        let toggle = SyncToggle::new();
        assert_eq!(toggle.get(), CurrentToggleState::Untoggled);
        assert_eq!(toggle.toggle_on_if_untoggled(), CurrentToggleState::JustToggled);
        toggle.toggle_off();
        assert_eq!(toggle.get(), CurrentToggleState::Untoggled);
        assert_eq!(toggle.toggle_on_if_untoggled(), CurrentToggleState::JustToggled);
        assert_eq!(toggle.get(), CurrentToggleState::AlreadyToggled);
        assert_eq!(toggle.toggle_on_if_untoggled(), CurrentToggleState::AlreadyToggled);
        assert_eq!(toggle.get(), CurrentToggleState::AlreadyToggled);
        assert_eq!(toggle.toggle_on_if_untoggled(), CurrentToggleState::AlreadyToggled);
        assert_eq!(toggle.get(), CurrentToggleState::AlreadyToggled);
        toggle.toggle_off();
        assert_eq!(toggle.get(), CurrentToggleState::Untoggled);
        assert_eq!(toggle.toggle_on_if_untoggled(), CurrentToggleState::JustToggled);
    }
}