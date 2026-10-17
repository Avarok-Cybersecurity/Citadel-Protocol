//! A typed value an error carries beside its message, for a caller that must act on more than
//! the code: an admission refusal's challenge, say. It never renders, compares or hashes: an
//! error with a detail is the same error as one without.

use super::NetworkError;
use std::any::Any;
use std::sync::Arc;

pub(crate) type Detail = Arc<dyn Any + Send + Sync>;

impl NetworkError {
    /// This error, carrying `detail`; it replaces any detail it carried before.
    pub fn with_detail<T: Any + Send + Sync>(mut self, detail: T) -> Self {
        self.0.detail = Some(Arc::new(detail));
        self
    }

    /// The detail this error carries, when it carries one of type `T`.
    pub fn detail<T: Any>(&self) -> Option<&T> {
        self.0.detail.as_deref()?.downcast_ref::<T>()
    }
}

#[cfg(test)]
mod tests {
    use crate::error::ErrorCode;

    #[derive(Debug, PartialEq)]
    struct Challenge(&'static str);

    #[test]
    fn a_detail_is_read_back_by_its_own_type_only() {
        let err = crate::error!(ErrorCode::Generic, "refused").with_detail(Challenge("key"));
        assert_eq!(err.detail::<Challenge>(), Some(&Challenge("key")));
        assert_eq!(err.detail::<String>(), None);
        assert_eq!(err.clone().detail::<Challenge>(), Some(&Challenge("key")));
    }

    #[test]
    fn an_error_without_one_has_none_and_a_detail_changes_nothing_else() {
        let plain = crate::error!(ErrorCode::Generic, "refused");
        assert_eq!(plain.detail::<Challenge>(), None);
        let carrying = plain.clone().with_detail(Challenge("key"));
        assert_eq!(carrying.to_string(), plain.to_string());
        assert_eq!(carrying, plain);
    }
}
