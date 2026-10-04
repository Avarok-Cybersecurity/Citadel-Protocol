//! The account manager's post-quantum operations: creating an account from a post-quantum
//! registration, upgrading a legacy account, and changing a record under one lock.

use super::AccountManager;
use crate::auth::pq::record::PqAuthRecord;
use crate::auth::pq::server::PqAuthServerSettings;
use crate::auth::proposed_credentials::ProposedCredentials;
use crate::auth::{DeclaredAuthenticationMode, PqAuthSide};
use crate::client_account::ClientNetworkAccount;
use crate::misc::{now_ms, AccountError};
use crate::prelude::ConnectionInfo;
use citadel_crypt::endpoint_crypto_container::PeerSessionCrypto;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::{error, ErrorCode};
use citadel_types::auth::FactorId;

impl<R: Ratchet, Fcm: Ratchet> AccountManager<R, Fcm> {
    /// The server's post-quantum settings, if it offers post-quantum sign-in.
    pub fn pq_settings(&self) -> Option<&PqAuthServerSettings> {
        self.server_misc_settings.pq_sign_in.as_ref()
    }

    /// Server side: the account a post-quantum registration creates. No password is hashed here.
    pub async fn register_pq_client_network_account(
        &self,
        conn_info: ConnectionInfo,
        username: String,
        full_name: String,
        record: PqAuthRecord,
        session_crypto_state: PeerSessionCrypto<R>,
    ) -> Result<ClientNetworkAccount<R, Fcm>, AccountError> {
        let reserved_cid = self.persistence_handler.get_cid_by_username(&username);
        if reserved_cid == 0 {
            return Err(error!(ErrorCode::RegisterCidZero));
        }
        let auth_store = DeclaredAuthenticationMode::PostQuantum {
            username,
            full_name,
            side: PqAuthSide::Server(Box::new(record)),
        };
        self.create_impersonal_account(reserved_cid, conn_info, auth_store, session_crypto_state)
            .await
    }

    /// Server side: replaces a legacy account's Argon2 record with `record`, after a legacy login
    /// verified. From then on the legacy path is refused for the account.
    pub async fn upgrade_to_pq(&self, cid: u64, record: PqAuthRecord) -> Result<(), AccountError> {
        let _guard = self.pq_record_lock.lock().await;
        let cnac = self.load(cid).await?;
        let (username, full_name) = match &*cnac.auth_store() {
            DeclaredAuthenticationMode::Argon {
                username,
                full_name,
                ..
            } => (username.clone(), full_name.clone()),
            _ => {
                return Err(error!(
                    ErrorCode::PqSignInMalformed,
                    "an upgrade of a non-legacy account"
                ))
            }
        };
        cnac.replace_auth_store(DeclaredAuthenticationMode::PostQuantum {
            username,
            full_name,
            side: PqAuthSide::Server(Box::new(record)),
        });
        self.persistence_handler.save_cnac(&cnac).await
    }

    /// Server side: reads the account's current record, applies `change`, and saves the result,
    /// all under one lock. Nothing is saved when `change` fails.
    pub async fn update_pq_record<T>(
        &self,
        cid: u64,
        change: impl FnOnce(&mut PqAuthRecord) -> Result<T, AccountError>,
    ) -> Result<T, AccountError> {
        let _guard = self.pq_record_lock.lock().await;
        let cnac = self.load(cid).await?;
        let mut record = cnac.auth_store().pq_record().cloned().ok_or_else(|| {
            error!(
                ErrorCode::PqSignInUnavailable,
                "the account has no post-quantum record"
            )
        })?;
        let out = change(&mut record)?;
        cnac.set_pq_record(record);
        self.persistence_handler.save_cnac(&cnac).await?;
        Ok(out)
    }

    /// Server side: a verified login's factors get `last_used_ms`, and a recovery code among them
    /// is spent. Fails, saving nothing, if a factor was spent meanwhile.
    pub async fn record_pq_sign_in(&self, cid: u64, used: &[FactorId]) -> Result<(), AccountError> {
        self.update_pq_record(cid, |record| record.record_use(used, now_ms()))
            .await
    }

    /// Client side, after a post-quantum registration: the account keeps no secret at all, since
    /// every factor is rederived at sign-in.
    pub async fn register_personal_pq_server(
        &self,
        session_crypto_state: PeerSessionCrypto<R>,
        creds: ProposedCredentials,
        conn_info: ConnectionInfo,
    ) -> Result<ClientNetworkAccount<R, Fcm>, AccountError> {
        let valid_cid = self
            .persistence_handler
            .get_cid_by_username(creds.username());
        if valid_cid == 0 {
            return Err(error!(ErrorCode::RegisterCidZero));
        }
        let (username, _, full_name, _) = creds.decompose();
        let auth_store = DeclaredAuthenticationMode::PostQuantum {
            username,
            full_name,
            side: PqAuthSide::Client,
        };
        let cnac = ClientNetworkAccount::<R, Fcm>::new_from_network_personal(
            valid_cid,
            Some(session_crypto_state),
            auth_store,
            conn_info,
        )
        .await?;
        self.persistence_handler.save_cnac(&cnac).await?;
        Ok(cnac)
    }

    async fn load(&self, cid: u64) -> Result<ClientNetworkAccount<R, Fcm>, AccountError> {
        self.persistence_handler
            .get_cnac_by_cid(cid)
            .await?
            .ok_or_else(|| AccountError::account_client_non_exists(cid))
    }
}
