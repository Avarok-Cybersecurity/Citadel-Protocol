#![cfg(not(target_family = "wasm"))]
//! A session the server holds for a client that has already gone yields to that same
//! client's next authenticated login, without `force_login`.
//!
//! An agent whose IP changed reconnects without forcing, because forcing would also
//! displace a live session that is not its own. Its server held the dead session and
//! refused it with "Session Already Connected" until the keep-alive expired. The server
//! now recognises its own client by the resume token it issued that session, so the
//! reconnect replaces it at once, and only after the credentials check out.

mod common;

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::half_open_scenario::{run_scenario, Relogin};
    use citadel_io::tokio;

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_reconnect_replaces_its_own_half_open_session() {
        let notices = run_scenario(Relogin {
            force_login: false,
            correct_password: true,
        })
        .await;
        assert_eq!(
            notices, 1,
            "the old session's peer was not told, once, that it ended"
        );
    }

    #[citadel_io::tokio::test(flavor = "multi_thread")]
    async fn a_reconnect_with_the_wrong_password_leaves_the_held_session_alone() {
        let notices = run_scenario(Relogin {
            force_login: false,
            correct_password: false,
        })
        .await;
        assert_eq!(
            notices, 0,
            "a login that failed authentication tore the held session down"
        );
    }
}
