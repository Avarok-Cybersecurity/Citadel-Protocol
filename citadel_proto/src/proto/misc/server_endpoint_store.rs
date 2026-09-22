//! Where a client account remembers the WebSocket URL of its server.
//!
//! An account's CNAC records its server as a `SocketAddr`, which cannot name a server behind an
//! HTTP edge (many share the edge's addresses). The URL it registered to is kept beside it, in the
//! account's own byte map, so a later credentialed connect dials the same URL instead of the bare
//! address. The CNAC's serialized form is untouched, so accounts stored before this existed load
//! as before and connect as before.

use citadel_crypt::ratchets::Ratchet;
use citadel_io::WebSocketEndpoint;
use citadel_user::account_manager::AccountManager;

use crate::error::NetworkError;

/// Reserved for the protocol; distinct from the SDK key-value store's own key, so clearing an
/// application's key-value data never forgets the server.
const KEY: &str = "_INTERNAL_SERVER_ENDPOINT";
const SUB_KEY: &str = "url";
/// The account's own entries, as opposed to any peer's.
const SELF_PEER_CID: u64 = 0;

pub(crate) async fn store<R: Ratchet>(
    account_manager: &AccountManager<R, R>,
    cid: u64,
    endpoint: &WebSocketEndpoint,
) -> Result<(), NetworkError> {
    account_manager
        .get_persistence_handler()
        .store_byte_map_value(
            cid,
            SELF_PEER_CID,
            KEY,
            SUB_KEY,
            endpoint.as_str().as_bytes().to_vec(),
        )
        .await
        .map(|_previous| ())
        .map_err(|err| NetworkError::generic(err.into_string()))
}

pub(crate) async fn load<R: Ratchet>(
    account_manager: &AccountManager<R, R>,
    cid: u64,
) -> Result<Option<WebSocketEndpoint>, NetworkError> {
    let stored = account_manager
        .get_persistence_handler()
        .get_byte_map_value(cid, SELF_PEER_CID, KEY, SUB_KEY)
        .await
        .map_err(|err| NetworkError::generic(err.into_string()))?;
    match stored {
        None => Ok(None),
        Some(bytes) => {
            let url = String::from_utf8(bytes).map_err(|err| {
                NetworkError::generic(format!(
                    "stored server endpoint for {cid} is not UTF-8: {err}"
                ))
            })?;
            WebSocketEndpoint::parse(&url).map(Some)
        }
    }
}
