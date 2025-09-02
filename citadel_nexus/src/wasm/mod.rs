//! WebAssembly platform implementation 
//!
//! This module provides the implementation of the Citadel Nexus traits for
//! WebAssembly targets using WebRTC DataChannels, WebSockets, and browser APIs.

pub mod provider;
pub mod webrtc;
pub mod websocket; 
pub mod nat;

pub use provider::WasmIOProvider;
pub use webrtc::{WebRtcDataChannel, WebRtcListener};
pub use websocket::{WebSocketStream, WebSocketListener};
pub use nat::WasmNatTraversal;