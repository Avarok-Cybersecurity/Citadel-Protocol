//! The account manager's legacy (Argon2) login check, which also replaces a stored hash whose
//! parameters are below the floor.

use super::AccountManager;
use crate::auth::proposed_credentials::ProposedCredentials;
use crate::auth::DeclaredAuthenticationMode;
use crate::client_account::ClientNetworkAccount;
use crate::misc::AccountError;
use citadel_crypt::argon::argon_container::ArgonContainerType;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::{error, ErrorCode};

impl<R: Ratchet, Fcm: Ratchet> AccountManager<R, Fcm> {
    /// Server side: checks a legacy login against the account's stored Argon2 hash.
    ///
    /// When the login verified and the stored hash was made with parameters below the floor
    /// ([`ArgonSettings::meets_floor`](citadel_crypt::argon::argon_container::ArgonSettings::meets_floor)),
    /// the hash is replaced by one under this node's settings, so an account created with weak
    /// parameters is brought up to the node's at its next login. A node whose own settings are
    /// below the floor (a test node that chose cheap hashing) keeps what is stored.
    pub async fn verify_legacy_login(
        &self,
        cnac: &ClientNetworkAccount<R, Fcm>,
        creds: ProposedCredentials,
    ) -> Result<(), AccountError> {
        cnac.validate_credentials(creds.clone()).await?;
        if !self.node_argon_settings.meets_floor() || !stored_below_floor(cnac) {
            return Ok(());
        }

        let argon = match creds
            .derive_server_container(&self.node_argon_settings, &self.server_misc_settings)
            .await?
        {
            DeclaredAuthenticationMode::Argon { argon, .. } => argon,
            _ => return Err(error!(ErrorCode::PasswordHashFailed)),
        };

        // The same lock as the post-quantum upgrade, which also replaces this record.
        let _guard = self.pq_record_lock.lock().await;
        if !stored_below_floor(cnac) {
            return Ok(());
        }
        let (username, full_name) = {
            let store = cnac.auth_store();
            (store.username().to_string(), store.full_name().to_string())
        };
        cnac.replace_auth_store(DeclaredAuthenticationMode::Argon {
            username,
            full_name,
            argon,
        });
        self.persistence_handler.save_cnac(cnac).await?;
        log::info!(target: "citadel", "Re-hashed the password of account {} to this node's Argon2 settings", cnac.get_cid());
        Ok(())
    }
}

/// Whether the account holds a server-side Argon2 hash made with parameters below the floor.
fn stored_below_floor<R: Ratchet, Fcm: Ratchet>(cnac: &ClientNetworkAccount<R, Fcm>) -> bool {
    match &*cnac.auth_store() {
        DeclaredAuthenticationMode::Argon {
            argon: argon @ ArgonContainerType::Server(_),
            ..
        } => !argon.settings().meets_floor(),
        _ => false,
    }
}
