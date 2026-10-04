//! Ending a C2S session locally, without the server's ack (`NodeRemote::abandon_session`).
//!
//! A link that died silently (a network change, sleep) leaves the client's session looking
//! connected until its keep-alive gives up, and every login for the account meanwhile is refused
//! here with "Session for CID .. already exists". A connection supervisor that has seen its
//! probes time out abandons the session instead: it is stopped and forgotten at once, its
//! transport dropped, and the CID freed. Nothing is sent to the server; the session the server
//! still holds is replaced by the next login's resume token (see `session_resume`).

use crate::error::NetworkError;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::session_manager::{CitadelSessionManager, SESSION_DROP_GRACE};
use citadel_crypt::ratchets::Ratchet;
use citadel_io::{error, ErrorCode};
use std::future::Future;

impl<R: Ratchet, T: PlatformOps> CitadelSessionManager<R, T> {
    /// Stops and forgets every session this node holds for `cid`, admitted or still connecting.
    /// The returned future resolves once the admitted one has dropped (its teardown done), or
    /// after [`SESSION_DROP_GRACE`] if it has not; a login started after that cannot meet it.
    pub fn abandon_session(
        &self,
        cid: u64,
    ) -> Result<impl Future<Output = ()> + Send + 'static, NetworkError> {
        let (session, had_provisional) = {
            let mut this = inner_mut!(self);
            let had_provisional = this
                .provisional_connections
                .values()
                .any(|(_, _, sess)| sess.session_cid.get() == Some(cid));
            (this.stop_and_forget(cid), had_provisional)
        };
        let dropped = match session {
            None if !had_provisional => {
                return Err(error!(ErrorCode::SessionManagerNotActiveSession, cid))
            }
            None => None,
            Some(session) => {
                session.shutdown();
                let (tx, rx) = citadel_io::tokio::sync::oneshot::channel::<()>();
                // A login already waiting on this session's drop holds the listener; it is told.
                let listening = session.drop_listener.atomic_set_if_none(tx).is_none();
                listening.then_some(rx)
            }
        };
        Ok(async move {
            if let Some(dropped) = dropped {
                if citadel_io::time::timeout(SESSION_DROP_GRACE, dropped)
                    .await
                    .is_err()
                {
                    log::warn!(target: "citadel", "Abandoned session {cid} did not drop within {SESSION_DROP_GRACE:?}");
                }
            }
        })
    }
}
