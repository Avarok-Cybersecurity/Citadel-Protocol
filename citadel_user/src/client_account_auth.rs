//! A CNAC's post-quantum view: what a login naming a username meets, and swapping the record.

use super::ClientNetworkAccount;
use crate::auth::pq::record::PqAuthRecord;
use crate::auth::pq::server::AccountAuth;
use crate::auth::{DeclaredAuthenticationMode, PqAuthSide};
use citadel_crypt::ratchets::Ratchet;

/// What a post-quantum login naming some username meets on an account, owned so it can outlive
/// the account's lock.
pub enum PqAccountState {
    PostQuantum(Box<PqAuthRecord>),
    /// Not this account, or one that has no sign-in record to prove: the login gets decoys.
    Unknown,
}

impl PqAccountState {
    pub fn as_account_auth(&self) -> AccountAuth<'_> {
        match self {
            Self::PostQuantum(record) => AccountAuth::PostQuantum(record),
            Self::Unknown => AccountAuth::Unknown,
        }
    }
}

impl<R: Ratchet, Fcm: Ratchet> ClientNetworkAccount<R, Fcm> {
    /// Server side. A name that is not this account's is unknown, exactly as a name with no
    /// account at all.
    pub fn pq_account_state(&self, username: &str) -> PqAccountState {
        let store = self.inner.auth_store.read();
        if store.username() != username {
            return PqAccountState::Unknown;
        }
        match &*store {
            DeclaredAuthenticationMode::PostQuantum {
                side: PqAuthSide::Server(record),
                ..
            } => PqAccountState::PostQuantum(record.clone()),
            _ => PqAccountState::Unknown,
        }
    }

    pub(crate) fn replace_auth_store(&self, auth_store: DeclaredAuthenticationMode) {
        *self.inner.auth_store.write() = auth_store;
    }

    pub(crate) fn set_pq_record(&self, record: PqAuthRecord) {
        if let DeclaredAuthenticationMode::PostQuantum { side, .. } =
            &mut *self.inner.auth_store.write()
        {
            *side = PqAuthSide::Server(Box::new(record));
        }
    }
}

#[cfg(test)]
#[path = "client_account_auth_tests.rs"]
mod tests;
