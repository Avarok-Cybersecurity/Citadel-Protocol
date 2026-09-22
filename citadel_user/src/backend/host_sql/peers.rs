//! Peer rows: one per direction of a pair, `(cid, peer_cid)` unique, so recording a pair again
//! updates it (#306) and one removal removes it (#307).

use super::{
    cid_value, read_cid, read_opt_text, schema, text_value, HostSqlBackend, SqlRow, SqlStatement,
};
use crate::misc::AccountError;
use crate::prelude::HYPERLAN_IDX;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::user::MutualPeer;

impl<R: Ratchet, Fcm: Ratchet> HostSqlBackend<R, Fcm> {
    /// Both directions, each carrying the other account's username as this server holds it.
    pub(super) async fn pair_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError> {
        self.require_account(cid0).await?;
        self.require_account(cid1).await?;
        let direction = |from: u64, to: u64| SqlStatement {
            sql: schema::UPSERT_PEER_FROM_CNAC,
            params: vec![cid_value(from), cid_value(to)],
        };
        self.run(vec![direction(cid0, cid1), direction(cid1, cid0)])
            .await
            .map(|_| ())
    }

    pub(super) async fn record_peer(
        &self,
        session_cid: u64,
        peer_cid: u64,
        peer_username: String,
    ) -> Result<(), AccountError> {
        self.require_account(session_cid).await?;
        let params = vec![
            cid_value(session_cid),
            cid_value(peer_cid),
            text_value(peer_username),
        ];
        self.query(schema::UPSERT_PEER, params).await.map(|_| ())
    }

    pub(super) async fn unpair_as_server(&self, cid0: u64, cid1: u64) -> Result<(), AccountError> {
        let direction = |from: u64, to: u64| SqlStatement {
            sql: schema::DELETE_PEER,
            params: vec![cid_value(from), cid_value(to)],
        };
        self.run(vec![direction(cid0, cid1), direction(cid1, cid0)])
            .await
            .map(|_| ())
    }

    /// Removes the peer and returns it as it was recorded, or `None` if it was not.
    pub(super) async fn forget_peer(
        &self,
        session_cid: u64,
        peer_cid: u64,
    ) -> Result<Option<MutualPeer>, AccountError> {
        let key = vec![cid_value(session_cid), cid_value(peer_cid)];
        let mut results = self
            .run(vec![
                SqlStatement {
                    sql: schema::SELECT_PEER,
                    params: key.clone(),
                },
                SqlStatement {
                    sql: schema::DELETE_PEER,
                    params: key,
                },
            ])
            .await?;
        results.swap_remove(0).first().map(row_to_peer).transpose()
    }

    /// Makes the recorded peers exactly `peers`; a peer listed twice is recorded once.
    pub(super) async fn replace_peers(
        &self,
        session_cid: u64,
        peers: Vec<MutualPeer>,
    ) -> Result<(), AccountError> {
        let mut statements = vec![SqlStatement {
            sql: schema::DELETE_PEERS_OF,
            params: vec![cid_value(session_cid)],
        }];
        statements.extend(peers.into_iter().map(|peer| SqlStatement {
            sql: schema::UPSERT_PEER,
            params: vec![
                cid_value(session_cid),
                cid_value(peer.cid),
                peer.username
                    .map(text_value)
                    .unwrap_or(super::SqlValue::Null),
            ],
        }));
        self.run(statements).await.map(|_| ())
    }

    pub(super) async fn peer(
        &self,
        session_cid: u64,
        peer_cid: u64,
    ) -> Result<Option<MutualPeer>, AccountError> {
        let params = vec![cid_value(session_cid), cid_value(peer_cid)];
        let rows = self.query(schema::SELECT_PEER, params).await?;
        rows.first().map(row_to_peer).transpose()
    }

    /// Every recorded peer of `session_cid`, oldest first. Filtering happens here rather than in
    /// SQL so no statement binds one parameter per peer (hosts cap bound parameters).
    pub(super) async fn peers_of(&self, session_cid: u64) -> Result<Vec<MutualPeer>, AccountError> {
        let rows = self
            .query(schema::SELECT_PEERS_OF, vec![cid_value(session_cid)])
            .await?;
        rows.iter().map(row_to_peer).collect()
    }

    async fn require_account(&self, cid: u64) -> Result<(), AccountError> {
        if self.account_exists(cid).await? {
            Ok(())
        } else {
            Err(AccountError::account_client_non_exists(cid))
        }
    }
}

fn row_to_peer(row: &SqlRow) -> Result<MutualPeer, AccountError> {
    Ok(MutualPeer {
        parent_icid: HYPERLAN_IDX,
        cid: read_cid(row, 0)?,
        username: read_opt_text(row, 1)?,
    })
}
