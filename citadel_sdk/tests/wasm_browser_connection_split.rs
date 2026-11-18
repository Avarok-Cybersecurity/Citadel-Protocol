//! Splitting a browser connection leaves the connection with its caller.
//!
//! `BrowserConnection` shuts its node down when dropped. `split` used to take the connection by
//! value, so it dropped it, and the node shut down the moment the halves were handed out; the
//! module's own usage example did exactly that. The property is checked at compile time: this
//! file builds only while `split` borrows the connection, which the caller then still holds.
#![cfg(target_family = "wasm")]

use citadel_sdk::net::BrowserConnection;
use citadel_sdk::prelude::*;
use wasm_bindgen_test::*;

/// Splits, then uses the connection: valid only if `split` left it with the caller.
#[allow(dead_code)]
fn split_leaves_the_connection_with_its_caller(
    conn: &mut BrowserConnection<StackedRatchet>,
) -> (
    PeerChannelSendHalf<StackedRatchet>,
    PeerChannelRecvHalf<StackedRatchet>,
) {
    let halves = conn.split();
    let _still_held = conn.remote();
    halves
}

#[wasm_bindgen_test]
fn the_split_contract_compiles() {
    let _ = split_leaves_the_connection_with_its_caller;
}
