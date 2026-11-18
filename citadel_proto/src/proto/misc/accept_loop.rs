//! A listener's accept loop, and the deadline on each accepted connection's handshake.
//!
//! An error from `accept()` belongs to one connection attempt, or to a passing condition such as
//! the process being out of descriptors; it never ends the listener. The loop logs it, waits
//! [`ACCEPT_ERROR_BACKOFF`] so a persistent condition does not spin a core, and accepts again.
//! Each accepted connection's handshake runs on its own task, bounded by
//! [`INBOUND_HANDSHAKE_TIMEOUT`], so a peer that stalls mid-handshake holds only its own socket,
//! and only that long.

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

/// The pause after a failed `accept()` before the next. A failure such as running out of
/// descriptors persists until a connection closes; this lets one close without retrying
/// thousands of times meanwhile.
pub(crate) const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// How long an accepted connection may take over its handshake (the first packet, and the TLS
/// or WebSocket upgrade where there is one). Several times a client's default wait for its whole
/// connect ([`crate::constants::TCP_CONN_TIMEOUT`], 4 s), so a slow but live link completes, while a peer that
/// stalls holds its socket at most this long.
pub(crate) const INBOUND_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Accepts with `accept` for as long as the listener lives, handing each connection to
/// `on_accepted`. It returns only by being dropped.
pub(crate) async fn accept_forever<S, Fut>(
    mut accept: impl FnMut() -> Fut,
    mut on_accepted: impl FnMut(S, SocketAddr),
) -> std::io::Result<()>
where
    Fut: Future<Output = std::io::Result<(S, SocketAddr)>>,
{
    loop {
        match accept().await {
            Ok((stream, addr)) => on_accepted(stream, addr),
            Err(err) => {
                log::warn!(target: "citadel", "accept() failed; the listener goes on accepting: {err}");
                citadel_io::time::sleep(ACCEPT_ERROR_BACKOFF).await;
            }
        }
    }
}

/// `handshake`, or a `TimedOut` error once [`INBOUND_HANDSHAKE_TIMEOUT`] has passed.
pub(crate) async fn within_handshake_deadline<T>(
    handshake: impl Future<Output = std::io::Result<T>>,
) -> std::io::Result<T> {
    citadel_io::time::timeout(INBOUND_HANDSHAKE_TIMEOUT, handshake)
        .await
        .unwrap_or_else(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "inbound handshake did not finish in time",
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_io::tokio;
    use std::collections::VecDeque;
    use std::io::{Error, ErrorKind};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[tokio::test(start_paused = true)]
    async fn a_listener_survives_accept_errors_and_accepts_after_them() {
        let mut script: VecDeque<std::io::Result<(u16, SocketAddr)>> = VecDeque::from([
            Ok((1, addr(1))),
            Err(Error::other("Too many open files (os error 24)")),
            Err(Error::from(ErrorKind::ConnectionAborted)),
            Ok((2, addr(2))),
        ]);
        let (accepted_tx, mut accepted) = tokio::sync::mpsc::unbounded_channel();
        let listener = accept_forever(
            move || {
                let next = script.pop_front();
                async move {
                    match next {
                        Some(result) => result,
                        None => std::future::pending().await,
                    }
                }
            },
            move |stream, _| accepted_tx.send(stream).unwrap(),
        );
        tokio::pin!(listener);
        let mut got = Vec::new();
        while got.len() < 2 {
            tokio::select! {
                ended = &mut listener => panic!("the listener ended: {ended:?}"),
                Some(stream) = accepted.recv() => got.push(stream),
            }
        }
        assert_eq!(got, [1, 2]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_handshake_ends_at_its_deadline() {
        let started = tokio::time::Instant::now();
        let result = tokio::time::timeout(
            INBOUND_HANDSHAKE_TIMEOUT * 2,
            within_handshake_deadline(std::future::pending::<std::io::Result<()>>()),
        )
        .await
        .expect("the handshake was still running at twice its deadline");
        assert_eq!(result.unwrap_err().kind(), ErrorKind::TimedOut);
        assert_eq!(started.elapsed(), INBOUND_HANDSHAKE_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn a_handshake_within_its_deadline_is_unchanged() {
        let result = within_handshake_deadline(async {
            tokio::time::sleep(INBOUND_HANDSHAKE_TIMEOUT / 2).await;
            Ok(7)
        })
        .await;
        assert_eq!(result.unwrap(), 7);
    }
}
