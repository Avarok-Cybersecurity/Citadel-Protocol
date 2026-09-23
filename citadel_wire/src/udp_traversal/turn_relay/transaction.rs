//! Request/response transactions with the TURN server: retransmission on the UDP leg, the
//! long-term-credential NONCE dance (RFC 8489 §9.2) and response integrity checks.

use std::io;
use std::time::Duration;

use citadel_io::tokio::sync::oneshot;
use stun::attributes::ATTR_NONCE;
use stun::message::Message;

use super::codec::{self, Attr, LongTermAuth, Method};
use super::driver::{self, Shared};

/// RFC 8489 §6.2.1 retransmission for the UDP leg: RTO 500 ms, doubling, 5 sends (~7.5 s).
const UDP_RTO: Duration = Duration::from_millis(500);
const UDP_SENDS: u32 = 5;
/// A stream transport never loses a request; this only bounds a dead server.
const STREAM_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
const CODE_UNAUTHORIZED: u16 = 401;
const CODE_WRONG_CREDENTIALS: u16 = 441;
const CODE_STALE_NONCE: u16 = 438;

/// An authenticated request, re-sent once with a fresh NONCE on 438 Stale Nonce (or a 401 that
/// supplies one); success responses must carry a valid MESSAGE-INTEGRITY.
pub(crate) async fn transact(
    shared: &Shared,
    method: Method,
    attrs: &[Attr],
) -> io::Result<Message> {
    for _ in 0..2 {
        let auth = shared.auth.lock().clone();
        let mut response = request(shared, method, attrs, auth.as_ref()).await?;
        if response.typ.class == codec::CLASS_SUCCESS_RESPONSE {
            if let Some(auth) = auth {
                auth.verify(&mut response)
                    .map_err(|e| invalid(&format!("{method} response integrity: {e}")))?;
            }
            return Ok(response);
        }
        let (code, reason) = codec::error_code(&response).unwrap_or((0, String::new()));
        let fresh_nonce = codec::text(&response, ATTR_NONCE);
        match (code, fresh_nonce, shared.auth.lock().as_mut()) {
            (CODE_STALE_NONCE | CODE_UNAUTHORIZED, Some(nonce), Some(auth))
                if auth.nonce != nonce =>
            {
                auth.nonce = nonce;
            }
            _ => return Err(turn_error(&method.to_string(), code, &reason)),
        }
    }
    Err(invalid(&format!(
        "{method}: server kept rejecting the nonce"
    )))
}

/// Sends one request and awaits the response with the same transaction id.
pub(crate) async fn request(
    shared: &Shared,
    method: Method,
    attrs: &[Attr],
    auth: Option<&LongTermAuth>,
) -> io::Result<Message> {
    let tid = driver::new_transaction();
    let raw = codec::build(method, codec::CLASS_REQUEST, tid, attrs, auth, true)?.raw;
    let (tx, mut rx) = oneshot::channel();
    shared.pending.lock().insert(tid.0, tx);
    let _guard = PendingGuard(shared, tid.0);
    let (sends, mut wait) = if shared.is_stream {
        (1, STREAM_RESPONSE_TIMEOUT)
    } else {
        (UDP_SENDS, UDP_RTO)
    };
    for _ in 0..sends {
        shared
            .out
            .send(raw.clone())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "TURN link closed"))?;
        match citadel_io::tokio::time::timeout(wait, &mut rx).await {
            Ok(Ok(m)) => return Ok(m),
            Ok(Err(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "TURN link closed",
                ))
            }
            Err(_) => wait *= 2,
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("TURN {method} got no response"),
    ))
}

struct PendingGuard<'a>(&'a Shared, [u8; 12]);

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        self.0.pending.lock().remove(&self.1);
    }
}

pub(crate) fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

pub(crate) fn turn_error(what: &str, code: u16, reason: &str) -> io::Error {
    let kind = match code {
        CODE_UNAUTHORIZED | CODE_WRONG_CREDENTIALS => io::ErrorKind::PermissionDenied,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, format!("TURN {what} rejected: {code} {reason}"))
}
