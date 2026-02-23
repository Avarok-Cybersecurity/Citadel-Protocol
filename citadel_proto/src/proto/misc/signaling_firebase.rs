//! Firebase RTDB signaling backend for serverless browser-to-browser connections.
//!
//! Implements [`SignalingService`] using the Firebase Realtime Database REST API
//! via the browser Fetch API (`web_sys::Request`). Zero additional dependencies
//! beyond what the WASM target already provides.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;

use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;

use super::signaling::SignalingService;

/// Configuration for the Firebase RTDB signaling backend.
#[derive(Clone, Debug)]
pub struct FirebaseSignalingConfig {
    /// Base URL of the Firebase project, e.g. `"https://myproject.firebaseio.com"`.
    pub base_url: String,
    /// Optional Firebase auth token appended as `?auth=<token>`.
    pub auth_token: Option<String>,
    /// Path prefix for signaling rooms. Default: `"signaling/rooms"`.
    pub rooms_path: String,
}

impl Default for FirebaseSignalingConfig {
    fn default() -> Self {
        Self {
            base_url: String::new(),
            auth_token: None,
            rooms_path: "signaling/rooms".into(),
        }
    }
}

/// Firebase RTDB signaling service.
pub struct FirebaseSignaling {
    config: FirebaseSignalingConfig,
}

impl FirebaseSignaling {
    pub fn new(config: FirebaseSignalingConfig) -> Self {
        Self { config }
    }

    /// Build the full URL for a path, with optional auth query param.
    fn url(&self, room: &str, key: &str) -> String {
        let base = self.config.base_url.trim_end_matches('/');
        let path = &self.config.rooms_path;
        let mut url = format!("{base}/{path}/{room}/{key}.json");
        if let Some(ref token) = self.config.auth_token {
            url.push_str(&format!("?auth={token}"));
        }
        url
    }

    /// Build URL for the room root (used for delete_room).
    fn room_url(&self, room: &str) -> String {
        let base = self.config.base_url.trim_end_matches('/');
        let path = &self.config.rooms_path;
        let mut url = format!("{base}/{path}/{room}.json");
        if let Some(ref token) = self.config.auth_token {
            url.push_str(&format!("?auth={token}"));
        }
        url
    }
}

/// Execute a fetch request and return the response text.
async fn fetch_text(url: &str, method: &str, body: Option<&str>) -> io::Result<String> {
    let opts = web_sys::RequestInit::new();
    opts.set_method(method);
    opts.set_mode(web_sys::RequestMode::Cors);

    if let Some(b) = body {
        opts.set_body(&JsValue::from_str(b));
    }

    let request = web_sys::Request::new_with_str_and_init(url, &opts).map_err(js_err)?;

    if body.is_some() {
        request
            .headers()
            .set("Content-Type", "application/json")
            .map_err(js_err)?;
    }

    let window = web_sys::window()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no global window"))?;

    let resp_js = await_js_promise(window.fetch_with_request(&request)).await?;
    let resp: web_sys::Response = resp_js.dyn_into().map_err(js_err)?;

    if !resp.ok() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Firebase HTTP {}: {}", resp.status(), resp.status_text()),
        ));
    }

    let text_promise = resp.text().map_err(js_err)?;
    let text_js = await_js_promise(text_promise).await?;
    text_js
        .as_string()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "response not a string"))
}

fn js_err(e: JsValue) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("{e:?}"))
}

/// Await a JS Promise via callback+oneshot (reuses the pattern from wasm_rtc.rs).
async fn await_js_promise(promise: js_sys::Promise) -> io::Result<JsValue> {
    use std::sync::Arc;
    let (tx, rx) = citadel_io::tokio::sync::oneshot::channel::<Result<JsValue, JsValue>>();
    let tx = Arc::new(std::sync::Mutex::new(Some(tx)));

    let tx_ok = tx.clone();
    let on_resolve = wasm_bindgen::closure::Closure::once(move |val: JsValue| {
        if let Some(tx) = tx_ok.lock().unwrap().take() {
            let _ = tx.send(Ok(val));
        }
    });

    let tx_err = tx.clone();
    let on_reject = wasm_bindgen::closure::Closure::once(move |val: JsValue| {
        if let Some(tx) = tx_err.lock().unwrap().take() {
            let _ = tx.send(Err(val));
        }
    });

    let _ = promise.then2(&on_resolve, &on_reject);
    let result = rx
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "JS promise channel dropped"))?;

    drop(on_resolve);
    drop(on_reject);

    result.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e:?}")))
}

impl SignalingService for FirebaseSignaling {
    fn publish(
        &self,
        room: &str,
        key: &str,
        value: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>>>> {
        let url = self.url(room, key);
        let body = serde_json::to_string(&value).unwrap_or_else(|_| "null".into());
        Box::pin(async move {
            fetch_text(&url, "PUT", Some(&body)).await?;
            Ok(())
        })
    }

    fn read(
        &self,
        room: &str,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = io::Result<Option<serde_json::Value>>>>> {
        let url = self.url(room, key);
        Box::pin(async move {
            let text = fetch_text(&url, "GET", None).await?;
            if text == "null" {
                return Ok(None);
            }
            let val: serde_json::Value = serde_json::from_str(&text)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            Ok(Some(val))
        })
    }

    fn list_children(
        &self,
        room: &str,
        prefix: &str,
    ) -> Pin<Box<dyn Future<Output = io::Result<HashMap<String, serde_json::Value>>>>> {
        let url = self.url(room, prefix);
        Box::pin(async move {
            let text = fetch_text(&url, "GET", None).await?;
            if text == "null" {
                return Ok(HashMap::new());
            }
            let map: HashMap<String, serde_json::Value> = serde_json::from_str(&text)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            Ok(map)
        })
    }

    fn delete_room(&self, room: &str) -> Pin<Box<dyn Future<Output = io::Result<()>>>> {
        let url = self.room_url(room);
        Box::pin(async move {
            fetch_text(&url, "DELETE", None).await?;
            Ok(())
        })
    }
}
