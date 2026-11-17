//! Awaiting a JS `Promise` from Rust, by callback and oneshot (no `wasm_bindgen_futures`
//! dependency), to match the WASM transport's style.

use citadel_io::tokio::sync::oneshot;
use std::sync::{Arc, Mutex};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsValue;

/// What `promise` settles to: its value, or the value it was rejected with.
pub(crate) async fn settle(promise: js_sys::Promise) -> Result<JsValue, JsValue> {
    let (tx, rx) = oneshot::channel::<Result<JsValue, JsValue>>();
    let tx = Arc::new(Mutex::new(Some(tx)));

    let tx_ok = tx.clone();
    let on_resolve = Closure::once(move |val: JsValue| {
        if let Some(tx) = tx_ok.lock().unwrap().take() {
            let _ = tx.send(Ok(val));
        }
    });

    let tx_err = tx.clone();
    let on_reject = Closure::once(move |val: JsValue| {
        if let Some(tx) = tx_err.lock().unwrap().take() {
            let _ = tx.send(Err(val));
        }
    });

    let _ = promise.then2(&on_resolve, &on_reject);

    // Keep closures alive until promise resolves
    let result = rx
        .await
        .unwrap_or_else(|_| Err(JsValue::from_str("JS promise channel dropped")));

    drop(on_resolve);
    drop(on_reject);

    result
}
