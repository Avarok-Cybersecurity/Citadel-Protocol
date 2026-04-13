//! WebAssembly platform implementation
//!
//! This module provides the implementation of the Citadel Nexus traits for
//! WebAssembly targets using WebRTC DataChannels, WebSockets, and browser APIs.

pub mod nat;
pub mod provider;
pub mod signaling;
pub mod webrtc;
pub mod websocket;

pub use nat::WasmNatTraversal;
pub use provider::WasmIOProvider;
pub use webrtc::{WebRtcDataChannel, WebRtcListener};
pub use websocket::{WebSocketListener, WebSocketStream};
