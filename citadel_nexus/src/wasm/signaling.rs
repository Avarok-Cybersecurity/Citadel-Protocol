//! WebRTC Signaling Implementation
//!
//! This module provides the signaling infrastructure required for WebRTC connections
//! in WASM environments. It handles offer/answer exchange and ICE candidate negotiation.

use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    RtcPeerConnection, RtcPeerConnectionIceEvent, RtcSdpType,
    RtcDataChannel, RtcSessionDescription, RtcSessionDescriptionInit,
    RtcIceCandidate, RtcIceCandidateInit, WebSocket, MessageEvent
};
use wasm_bindgen::JsCast;
use js_sys::{Promise, Object, Reflect};
use crate::error::{NexusResult, NexusError};
use std::rc::Rc;
use std::cell::RefCell;
use std::collections::VecDeque;
use futures::channel::oneshot;

/// WebRTC signaling server configuration
#[derive(Debug, Clone)]
pub struct SignalingConfig {
    /// WebSocket URL for signaling server
    pub signaling_url: String,
    /// STUN server URLs for ICE negotiation
    pub stun_servers: Vec<String>,
    /// TURN server URLs for NAT traversal (optional)
    pub turn_servers: Vec<TurnServerConfig>,
}

/// TURN server configuration
#[derive(Debug, Clone)]
pub struct TurnServerConfig {
    pub url: String,
    pub username: Option<String>,
    pub credential: Option<String>,
}

/// Signaling message types for WebRTC negotiation
#[derive(Debug)]
pub enum SignalingMessage {
    Offer {
        sdp: String,
        peer_id: String,
    },
    Answer {
        sdp: String,
        peer_id: String,
    },
    IceCandidate {
        candidate: String,
        sdp_mid: Option<String>,
        sdp_m_line_index: Option<u16>,
        peer_id: String,
    },
    Error {
        message: String,
    },
}

/// WebRTC connection manager that handles signaling
#[derive(Debug)]
pub struct WebRtcSignaling {
    config: SignalingConfig,
    websocket: Option<WebSocket>,
    peer_connections: Rc<RefCell<std::collections::HashMap<String, RtcPeerConnection>>>,
    pending_ice_candidates: Rc<RefCell<std::collections::HashMap<String, Vec<RtcIceCandidate>>>>,
    message_queue: Rc<RefCell<VecDeque<SignalingMessage>>>,
}

impl WebRtcSignaling {
    /// Create a new WebRTC signaling manager
    pub fn new(config: SignalingConfig) -> Self {
        Self {
            config,
            websocket: None,
            peer_connections: Rc::new(RefCell::new(std::collections::HashMap::new())),
            pending_ice_candidates: Rc::new(RefCell::new(std::collections::HashMap::new())),
            message_queue: Rc::new(RefCell::new(VecDeque::new())),
        }
    }

    /// Connect to the signaling server
    pub async fn connect(&mut self) -> NexusResult<()> {
        let ws = WebSocket::new(&self.config.signaling_url)
            .map_err(|e| NexusError::Connection(format!("Failed to create WebSocket: {:?}", e)))?;

        ws.set_binary_type(web_sys::BinaryType::Arraybuffer);

        let message_queue = self.message_queue.clone();
        
        // Set up message handler
        let onmessage_callback = Closure::wrap(Box::new(move |e: MessageEvent| {
            if let Ok(txt) = e.data().dyn_into::<js_sys::JsString>() {
                let msg_str: String = txt.into();
                if let Ok(message) = Self::parse_signaling_message(&msg_str) {
                    message_queue.borrow_mut().push_back(message);
                }
            }
        }) as Box<dyn FnMut(_)>);
        ws.set_onmessage(Some(onmessage_callback.as_ref().unchecked_ref()));
        onmessage_callback.forget();

        // Wait for connection to open
        let (tx, rx) = oneshot::channel();
        let tx = Rc::new(RefCell::new(Some(tx)));

        let onopen_callback = Closure::wrap(Box::new(move || {
            if let Some(sender) = tx.borrow_mut().take() {
                let _ = sender.send(Ok(()));
            }
        }) as Box<dyn FnMut()>);
        ws.set_onopen(Some(onopen_callback.as_ref().unchecked_ref()));
        onopen_callback.forget();

        let onerror_callback = Closure::wrap(Box::new(move |_: web_sys::Event| {
            // Handle WebSocket errors
        }) as Box<dyn FnMut(_)>);
        ws.set_onerror(Some(onerror_callback.as_ref().unchecked_ref()));
        onerror_callback.forget();

        self.websocket = Some(ws);

        rx.await.map_err(|_| NexusError::Connection("Failed to connect to signaling server".to_string()))?
    }

    /// Create a WebRTC peer connection with proper ICE configuration
    pub fn create_peer_connection(&self, peer_id: &str) -> NexusResult<RtcPeerConnection> {
        let mut config = web_sys::RtcConfiguration::new();
        let ice_servers = js_sys::Array::new();
        
        // Add STUN servers
        for stun_url in &self.config.stun_servers {
            let server = web_sys::RtcIceServer::new();
            let urls = js_sys::Array::new();
            urls.push(&JsValue::from_str(stun_url));
            server.set_urls(&urls);
            ice_servers.push(&server);
        }

        // Add TURN servers
        for turn_config in &self.config.turn_servers {
            let server = web_sys::RtcIceServer::new();
            let urls = js_sys::Array::new();
            urls.push(&JsValue::from_str(&turn_config.url));
            server.set_urls(&urls);
            
            if let Some(username) = &turn_config.username {
                server.set_username(username);
            }
            if let Some(credential) = &turn_config.credential {
                server.set_credential(credential);
            }
            ice_servers.push(&server);
        }

        config.ice_servers(&ice_servers);
        
        let peer_connection = RtcPeerConnection::new_with_configuration(&config)
            .map_err(|e| NexusError::Connection(format!("Failed to create peer connection: {:?}", e)))?;

        // Set up ICE candidate handling
        let peer_id_clone = peer_id.to_string();
        let ws_clone = self.websocket.as_ref().cloned();
        let onicecandidate_callback = Closure::wrap(Box::new(move |e: web_sys::RtcPeerConnectionIceEvent| {
            if let Some(candidate) = e.candidate() {
                if let Some(ws) = &ws_clone {
                    let message = SignalingMessage::IceCandidate {
                        candidate: candidate.candidate(),
                        sdp_mid: candidate.sdp_mid(),
                        sdp_m_line_index: candidate.sdp_m_line_index(),
                        peer_id: peer_id_clone.clone(),
                    };
                    if let Ok(json) = Self::serialize_signaling_message(&message) {
                        let _ = ws.send_with_str(&json);
                    }
                }
            }
        }) as Box<dyn FnMut(_)>);
        peer_connection.set_onicecandidate(Some(onicecandidate_callback.as_ref().unchecked_ref()));
        onicecandidate_callback.forget();

        self.peer_connections.borrow_mut().insert(peer_id.to_string(), peer_connection.clone());
        Ok(peer_connection)
    }

    /// Create an offer for a WebRTC connection
    pub async fn create_offer(&self, peer_id: &str) -> NexusResult<String> {
        let peer_connections = self.peer_connections.borrow();
        let peer_connection = peer_connections.get(peer_id)
            .ok_or_else(|| NexusError::Connection("Peer connection not found".to_string()))?;

        let offer_promise = peer_connection.create_offer();
        let offer = JsFuture::from(offer_promise).await
            .map_err(|e| NexusError::Connection(format!("Failed to create offer: {:?}", e)))?;

        let offer_desc = offer.dyn_into::<RtcSessionDescription>()
            .map_err(|_| NexusError::Connection("Invalid offer description".to_string()))?;

        // Create offer description init for setting
        let offer_init_obj = js_sys::Object::new();
        js_sys::Reflect::set(&offer_init_obj, &"type".into(), &RtcSdpType::Offer.into()).unwrap();
        js_sys::Reflect::set(&offer_init_obj, &"sdp".into(), &offer_desc.sdp().into()).unwrap();
        let offer_init: &RtcSessionDescriptionInit = offer_init_obj.unchecked_ref();
        
        // Set local description  
        let set_local_desc = peer_connection.set_local_description(offer_init);
        JsFuture::from(set_local_desc).await
            .map_err(|e| NexusError::Connection(format!("Failed to set local description: {:?}", e)))?;

        Ok(offer_desc.sdp())
    }

    /// Create an answer for a WebRTC connection
    pub async fn create_answer(&self, peer_id: &str, offer_sdp: &str) -> NexusResult<String> {
        let peer_connections = self.peer_connections.borrow();
        let peer_connection = peer_connections.get(peer_id)
            .ok_or_else(|| NexusError::Connection("Peer connection not found".to_string()))?;

        // Set remote description from offer
        let remote_desc_obj = js_sys::Object::new();
        js_sys::Reflect::set(&remote_desc_obj, &"type".into(), &RtcSdpType::Offer.into()).unwrap();
        js_sys::Reflect::set(&remote_desc_obj, &"sdp".into(), &offer_sdp.into()).unwrap();
        let remote_desc: &RtcSessionDescriptionInit = remote_desc_obj.unchecked_ref();

        let set_remote_desc = peer_connection.set_remote_description(remote_desc);
        JsFuture::from(set_remote_desc).await
            .map_err(|e| NexusError::Connection(format!("Failed to set remote description: {:?}", e)))?;

        // Create answer
        let answer_promise = peer_connection.create_answer();
        let answer = JsFuture::from(answer_promise).await
            .map_err(|e| NexusError::Connection(format!("Failed to create answer: {:?}", e)))?;

        let answer_desc = answer.dyn_into::<RtcSessionDescription>()
            .map_err(|_| NexusError::Connection("Invalid answer description".to_string()))?;

        // Create answer description init for setting
        let answer_init_obj = js_sys::Object::new();
        js_sys::Reflect::set(&answer_init_obj, &"type".into(), &RtcSdpType::Answer.into()).unwrap();
        js_sys::Reflect::set(&answer_init_obj, &"sdp".into(), &answer_desc.sdp().into()).unwrap();
        let answer_init: &RtcSessionDescriptionInit = answer_init_obj.unchecked_ref();

        // Set local description
        let set_local_desc = peer_connection.set_local_description(answer_init);
        JsFuture::from(set_local_desc).await
            .map_err(|e| NexusError::Connection(format!("Failed to set local description: {:?}", e)))?;

        Ok(answer_desc.sdp())
    }

    /// Handle received answer
    pub async fn handle_answer(&self, peer_id: &str, answer_sdp: &str) -> NexusResult<()> {
        let peer_connections = self.peer_connections.borrow();
        let peer_connection = peer_connections.get(peer_id)
            .ok_or_else(|| NexusError::Connection("Peer connection not found".to_string()))?;

        let remote_desc_obj = js_sys::Object::new();
        js_sys::Reflect::set(&remote_desc_obj, &"type".into(), &RtcSdpType::Answer.into()).unwrap();
        js_sys::Reflect::set(&remote_desc_obj, &"sdp".into(), &answer_sdp.into()).unwrap();
        let remote_desc: &RtcSessionDescriptionInit = remote_desc_obj.unchecked_ref();
        
        let set_remote_desc = peer_connection.set_remote_description(remote_desc);
        JsFuture::from(set_remote_desc).await
            .map_err(|e| NexusError::Connection(format!("Failed to set remote description: {:?}", e)))?;

        Ok(())
    }

    /// Handle received ICE candidate
    pub async fn handle_ice_candidate(
        &self,
        peer_id: &str,
        candidate: &str,
        sdp_mid: Option<String>,
        sdp_m_line_index: Option<u16>
    ) -> NexusResult<()> {
        let peer_connections = self.peer_connections.borrow();
        let peer_connection = peer_connections.get(peer_id)
            .ok_or_else(|| NexusError::Connection("Peer connection not found".to_string()))?;

        let ice_candidate_init = web_sys::RtcIceCandidateInit::new(candidate);
        if let Some(mid) = sdp_mid {
            ice_candidate_init.set_sdp_mid(Some(&mid));
        }
        if let Some(line_index) = sdp_m_line_index {
            ice_candidate_init.set_sdp_m_line_index(Some(line_index));
        }

        let ice_candidate = RtcIceCandidate::new(&ice_candidate_init)
            .map_err(|e| NexusError::Connection(format!("Failed to create ICE candidate: {:?}", e)))?;

        let add_candidate = peer_connection.add_ice_candidate_with_opt_rtc_ice_candidate(Some(&ice_candidate));
        JsFuture::from(add_candidate).await
            .map_err(|e| NexusError::Connection(format!("Failed to add ICE candidate: {:?}", e)))?;

        Ok(())
    }

    /// Send a signaling message
    pub fn send_message(&self, message: SignalingMessage) -> NexusResult<()> {
        if let Some(ws) = &self.websocket {
            let json = Self::serialize_signaling_message(&message)?;
            ws.send_with_str(&json)
                .map_err(|e| NexusError::Connection(format!("Failed to send message: {:?}", e)))?;
        }
        Ok(())
    }

    /// Get the next signaling message from the queue
    pub fn get_next_message(&self) -> Option<SignalingMessage> {
        self.message_queue.borrow_mut().pop_front()
    }

    fn parse_signaling_message(json: &str) -> Result<SignalingMessage, serde_json::Error> {
        // Simple JSON parsing for signaling messages
        // In a real implementation, you'd use proper JSON deserialization
        if json.contains("\"type\":\"offer\"") {
            Ok(SignalingMessage::Offer {
                sdp: "".to_string(), // Parse from JSON
                peer_id: "".to_string(), // Parse from JSON
            })
        } else if json.contains("\"type\":\"answer\"") {
            Ok(SignalingMessage::Answer {
                sdp: "".to_string(), // Parse from JSON
                peer_id: "".to_string(), // Parse from JSON
            })
        } else if json.contains("\"type\":\"ice-candidate\"") {
            Ok(SignalingMessage::IceCandidate {
                candidate: "".to_string(), // Parse from JSON
                sdp_mid: None, // Parse from JSON
                sdp_m_line_index: None, // Parse from JSON
                peer_id: "".to_string(), // Parse from JSON
            })
        } else {
            Ok(SignalingMessage::Error {
                message: "Unknown message type".to_string(),
            })
        }
    }

    fn serialize_signaling_message(message: &SignalingMessage) -> NexusResult<String> {
        // Simple JSON serialization for signaling messages
        // In a real implementation, you'd use proper JSON serialization
        match message {
            SignalingMessage::Offer { sdp, peer_id } => {
                Ok(format!(r#"{{"type":"offer","sdp":"{}","peer_id":"{}"}}"#, sdp, peer_id))
            }
            SignalingMessage::Answer { sdp, peer_id } => {
                Ok(format!(r#"{{"type":"answer","sdp":"{}","peer_id":"{}"}}"#, sdp, peer_id))
            }
            SignalingMessage::IceCandidate { candidate, peer_id, .. } => {
                Ok(format!(r#"{{"type":"ice-candidate","candidate":"{}","peer_id":"{}"}}"#, candidate, peer_id))
            }
            SignalingMessage::Error { message } => {
                Ok(format!(r#"{{"type":"error","message":"{}"}}"#, message))
            }
        }
    }
}

impl Default for SignalingConfig {
    fn default() -> Self {
        Self {
            signaling_url: "ws://localhost:3000/signaling".to_string(),
            stun_servers: vec![
                "stun:stun.l.google.com:19302".to_string(),
                "stun:stun1.l.google.com:19302".to_string(),
            ],
            turn_servers: vec![],
        }
    }
}
