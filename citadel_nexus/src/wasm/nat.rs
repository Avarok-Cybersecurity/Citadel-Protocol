//! NAT traversal implementation for WASM

use async_trait::async_trait;
use futures::FutureExt;
use std::net::{IpAddr, SocketAddr};

use crate::error::{NexusError, NexusResult};
use crate::traits::{
    ConnectivityResult, DatagramSocket, HolePunchConfig, HolePunchStats, HolePunchedSocket,
    NatTraversal, NatType, TraversalStrategy,
};

/// WASM implementation of NAT traversal using browser APIs
#[derive(Clone)]
pub struct WasmNatTraversal {
    stun_servers: Vec<String>,
}

impl WasmNatTraversal {
    pub async fn new() -> NexusResult<Self> {
        Ok(Self {
            stun_servers: vec![
                "stun:stun.l.google.com:19302".to_string(),
                "stun:stun1.l.google.com:19302".to_string(),
                "stun:stun2.l.google.com:19302".to_string(),
            ],
        })
    }
}

#[async_trait(?Send)]
impl NatTraversal for WasmNatTraversal {
    async fn identify_nat_type(&self, stun_servers: Vec<String>) -> NexusResult<NatType> {
        // In browser context, we use WebRTC to identify NAT type

        #[cfg(target_family = "wasm")]
        {
            use js_sys::Array;
            use wasm_bindgen::prelude::*;
            use wasm_bindgen_futures::JsFuture;
            use web_sys::*;

            // Use provided STUN servers or defaults
            let servers = if stun_servers.is_empty() {
                self.stun_servers.clone()
            } else {
                stun_servers
            };

            // Create RTCPeerConnection with STUN servers
            let config = RtcConfiguration::new();
            let ice_servers = Array::new();

            for server_url in &servers {
                let server = RtcIceServer::new();
                server.set_urls(&JsValue::from_str(server_url));
                ice_servers.push(&server);
            }
            config.set_ice_servers(&ice_servers);

            let peer_connection =
                RtcPeerConnection::new_with_configuration(&config).map_err(|e| {
                    NexusError::NatTraversal(format!("Failed to create peer connection: {:?}", e))
                })?;

            // Create a data channel to trigger ICE gathering
            let data_channel = peer_connection.create_data_channel("nat-detection");

            // Create an offer to start ICE gathering
            let offer_promise = peer_connection.create_offer();
            let offer = JsFuture::from(offer_promise).await.map_err(|e| {
                NexusError::NatTraversal(format!("Failed to create offer: {:?}", e))
            })?;

            let offer_desc = offer
                .dyn_into::<RtcSessionDescription>()
                .map_err(|_| NexusError::NatTraversal("Invalid offer".to_string()))?;

            let offer_init = {
                let obj = js_sys::Object::new();
                js_sys::Reflect::set(&obj, &"type".into(), &RtcSdpType::Offer.into()).unwrap();
                js_sys::Reflect::set(&obj, &"sdp".into(), &offer_desc.sdp().into()).unwrap();
                obj
            };

            let set_local = peer_connection.set_local_description(offer_init.unchecked_ref());
            JsFuture::from(set_local).await.map_err(|e| {
                NexusError::NatTraversal(format!("Failed to set local description: {:?}", e))
            })?;

            // Wait for ICE gathering to complete
            let (tx, mut rx) = futures::channel::oneshot::channel();
            let tx = std::rc::Rc::new(std::cell::RefCell::new(Some(tx)));
            let candidates = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));

            let candidates_clone = candidates.clone();
            let tx_clone = tx.clone();
            let onicecandidate =
                Closure::wrap(Box::new(move |event: web_sys::RtcPeerConnectionIceEvent| {
                    if let Some(candidate) = event.candidate() {
                        candidates_clone.borrow_mut().push(candidate.candidate());
                    } else {
                        // null candidate means gathering is complete
                        if let Some(sender) = tx_clone.borrow_mut().take() {
                            let _ = sender.send(());
                        }
                    }
                }) as Box<dyn FnMut(_)>);

            peer_connection.set_onicecandidate(Some(onicecandidate.as_ref().unchecked_ref()));
            onicecandidate.forget();

            // Wait for ICE gathering to complete (with timeout)
            let timeout = Box::pin(async {
                wasm_bindgen_futures::JsFuture::from(js_sys::Promise::new(
                    &mut |resolve, _reject| {
                        web_sys::window()
                            .unwrap()
                            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 5000)
                            .unwrap();
                    },
                ))
                .await
                .ok();
            });

            futures::select! {
                _ = rx => {},
                _ = timeout.fuse() => {},
            }

            // Analyze gathered candidates
            let candidate_list = candidates.borrow();
            let mut has_host = false;
            let mut has_srflx = false; // Server reflexive (behind NAT)
            let mut has_relay = false;
            let mut external_ips = Vec::new();

            for candidate in candidate_list.iter() {
                if candidate.contains("typ host") {
                    has_host = true;
                } else if candidate.contains("typ srflx") {
                    has_srflx = true;
                    // Try to extract IP from candidate string
                    // Format: "candidate:... IP PORT typ srflx..."
                    if let Some(ip_part) = candidate.split_whitespace().nth(4) {
                        if let Ok(ip) = ip_part.parse::<std::net::IpAddr>() {
                            external_ips.push(ip);
                        }
                    }
                } else if candidate.contains("typ relay") {
                    has_relay = true;
                }
            }

            // Clean up
            peer_connection.close();
            data_channel.close();

            // Determine NAT type based on candidates
            let nat_type = if !has_srflx && !has_relay && has_host {
                // Only host candidates - no NAT
                NatType::None
            } else if has_srflx && !external_ips.is_empty() {
                // Has server reflexive candidates - behind NAT
                // In browsers, we typically can't distinguish between cone types
                // so we assume RestrictedCone as a reasonable default
                NatType::RestrictedCone {
                    external_ip: external_ips[0],
                    port_mapping: crate::traits::PortMapping::Random,
                }
            } else if has_relay {
                // Only relay candidates available - likely symmetric NAT
                NatType::Symmetric {
                    external_ips: external_ips,
                    port_mapping: crate::traits::PortMapping::Random,
                }
            } else {
                NatType::Unknown
            };

            return Ok(nat_type);
        }

        #[cfg(not(target_family = "wasm"))]
        {
            Err(NexusError::Platform(
                "WASM NAT traversal called on non-WASM target".to_string(),
            ))
        }
    }

    async fn punch_hole(
        &self,
        _local_socket: &dyn DatagramSocket,
        config: HolePunchConfig,
    ) -> NexusResult<HolePunchedSocket> {
        // In WASM, hole punching is handled by WebRTC infrastructure
        // We don't need to manually send packets

        #[cfg(target_family = "wasm")]
        {
            use js_sys::Array;
            use wasm_bindgen::prelude::*;
            use wasm_bindgen_futures::JsFuture;
            use web_sys::*;

            let start_time = std::time::Instant::now();

            // Create RTCPeerConnection with STUN/TURN servers
            let rtc_config = RtcConfiguration::new();
            let ice_servers = Array::new();

            // Add STUN servers
            for server_url in &self.stun_servers {
                let server = RtcIceServer::new();
                server.set_urls(&JsValue::from_str(server_url));
                ice_servers.push(&server);
            }

            // Add TURN server if configured in strategy
            if let TraversalStrategy::TurnRelay {
                relay_server,
                credentials,
            } = &config.strategy
            {
                let server = RtcIceServer::new();
                server.set_urls(&JsValue::from_str(&format!("turn:{}", relay_server)));

                if let Some(creds) = credentials {
                    server.set_username(&creds.username);
                    server.set_credential(&creds.password);
                }

                ice_servers.push(&server);
            }

            rtc_config.set_ice_servers(&ice_servers);

            let peer_connection =
                RtcPeerConnection::new_with_configuration(&rtc_config).map_err(|e| {
                    NexusError::NatTraversal(format!("Failed to create peer connection: {:?}", e))
                })?;

            // Create reliable data channel
            let data_channel_init = RtcDataChannelInit::new();
            data_channel_init.set_ordered(true);
            data_channel_init.set_max_retransmits(3);

            let data_channel = peer_connection
                .create_data_channel_with_data_channel_dict("hole-punch", &data_channel_init);

            // Track connection establishment
            let connected = std::rc::Rc::new(std::cell::RefCell::new(false));
            let connected_clone = connected.clone();

            let (conn_tx, mut conn_rx) = futures::channel::oneshot::channel();
            let conn_tx = std::rc::Rc::new(std::cell::RefCell::new(Some(conn_tx)));
            let conn_tx_clone = conn_tx.clone();

            // Track data channel opening
            let onopen = Closure::wrap(Box::new(move || {
                *connected_clone.borrow_mut() = true;
                if let Some(sender) = conn_tx_clone.borrow_mut().take() {
                    let _ = sender.send(true);
                }
            }) as Box<dyn FnMut()>);

            data_channel.set_onopen(Some(onopen.as_ref().unchecked_ref()));
            onopen.forget();

            // Create offer
            let offer_promise = peer_connection.create_offer();
            let offer = JsFuture::from(offer_promise).await.map_err(|e| {
                NexusError::NatTraversal(format!("Failed to create offer: {:?}", e))
            })?;

            let offer_desc = offer
                .dyn_into::<RtcSessionDescription>()
                .map_err(|_| NexusError::NatTraversal("Invalid offer".to_string()))?;

            let offer_init = {
                let obj = js_sys::Object::new();
                js_sys::Reflect::set(&obj, &"type".into(), &RtcSdpType::Offer.into()).unwrap();
                js_sys::Reflect::set(&obj, &"sdp".into(), &offer_desc.sdp().into()).unwrap();
                obj
            };

            let set_local = peer_connection.set_local_description(offer_init.unchecked_ref());
            JsFuture::from(set_local).await.map_err(|e| {
                NexusError::NatTraversal(format!("Failed to set local description: {:?}", e))
            })?;

            // Collect ICE candidates
            let candidates = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
            let candidates_clone = candidates.clone();

            let (ice_tx, mut ice_rx) = futures::channel::oneshot::channel();
            let ice_tx = std::rc::Rc::new(std::cell::RefCell::new(Some(ice_tx)));
            let ice_tx_clone = ice_tx.clone();

            let onicecandidate =
                Closure::wrap(Box::new(move |event: web_sys::RtcPeerConnectionIceEvent| {
                    if let Some(candidate) = event.candidate() {
                        candidates_clone.borrow_mut().push(candidate);
                    } else {
                        // ICE gathering complete
                        if let Some(sender) = ice_tx_clone.borrow_mut().take() {
                            let _ = sender.send(());
                        }
                    }
                }) as Box<dyn FnMut(_)>);

            peer_connection.set_onicecandidate(Some(onicecandidate.as_ref().unchecked_ref()));
            onicecandidate.forget();

            // Wait for ICE gathering with timeout
            let ice_timeout = Box::pin(async {
                wasm_bindgen_futures::JsFuture::from(js_sys::Promise::new(
                    &mut |resolve, _reject| {
                        web_sys::window()
                            .unwrap()
                            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 5000)
                            .unwrap();
                    },
                ))
                .await
                .ok();
            });

            futures::select! {
                _ = ice_rx => {},
                _ = ice_timeout.fuse() => {},
            }

            // In a real implementation, we would:
            // 1. Send our offer SDP and ICE candidates to peer via signaling server
            // 2. Receive peer's answer SDP and ICE candidates
            // 3. Apply remote description and remote candidates
            //
            // For now, we simulate successful connection if we gathered candidates

            let gathered_candidates = candidates.borrow();
            if gathered_candidates.is_empty() {
                peer_connection.close();
                return Err(NexusError::NatTraversal(
                    "Failed to gather ICE candidates for hole punching".to_string(),
                ));
            }

            // Wait for connection establishment or timeout
            let conn_timeout = Box::pin(async {
                wasm_bindgen_futures::JsFuture::from(js_sys::Promise::new(
                    &mut |resolve, _reject| {
                        web_sys::window()
                            .unwrap()
                            .set_timeout_with_callback_and_timeout_and_arguments_0(
                                &resolve,
                                config.timeout.as_millis() as i32,
                            )
                            .unwrap();
                    },
                ))
                .await
                .ok();
                false
            });

            let success = futures::select! {
                result = conn_rx => result.unwrap_or(false),
                result = conn_timeout.fuse() => result,
            };

            let duration = start_time.elapsed();

            if !success {
                peer_connection.close();
                return Err(NexusError::NatTraversal(format!(
                    "Hole punch failed: connection not established within {:?}",
                    config.timeout
                )));
            }

            // Determine which strategy was used based on gathered candidate types
            let mut used_relay = false;
            let mut used_srflx = false;

            for candidate in gathered_candidates.iter() {
                let candidate_str = candidate.candidate();
                if candidate_str.contains("typ relay") {
                    used_relay = true;
                } else if candidate_str.contains("typ srflx") {
                    used_srflx = true;
                }
            }

            let strategy = if used_relay {
                TraversalStrategy::TurnRelay {
                    relay_server: if let TraversalStrategy::TurnRelay { relay_server, .. } =
                        &config.strategy
                    {
                        relay_server.clone()
                    } else {
                        "unknown".to_string()
                    },
                    credentials: None,
                }
            } else if used_srflx {
                TraversalStrategy::SimpleHolePunch
            } else {
                TraversalStrategy::Direct
            };

            let stats = HolePunchStats {
                attempts: config.max_retries,
                duration,
                successful_strategy: Some(strategy),
                bytes_exchanged: 0, // WebRTC tracks this internally
            };

            // Create socket wrapper
            // Note: In a real implementation, this would wrap the WebRTC DataChannel
            // in a DatagramSocket-compatible interface. For now we create a stub.
            struct WasmDatagramSocket {
                #[allow(dead_code)]
                peer_addr: SocketAddr,
            }

            #[async_trait(?Send)]
            impl DatagramSocket for WasmDatagramSocket {
                async fn send_to(&self, _buf: &[u8], _target: SocketAddr) -> NexusResult<usize> {
                    Err(NexusError::NotSupported(
                        "WASM datagram socket not fully implemented".into(),
                    ))
                }
                async fn recv_from(&self, _buf: &mut [u8]) -> NexusResult<(usize, SocketAddr)> {
                    Err(NexusError::NotSupported(
                        "WASM datagram socket not fully implemented".into(),
                    ))
                }
                fn local_addr(&self) -> NexusResult<SocketAddr> {
                    Ok("0.0.0.0:0".parse().unwrap())
                }
                async fn connect(&self, _addr: SocketAddr) -> NexusResult<()> {
                    Ok(())
                }
                async fn send(&self, _buf: &[u8]) -> NexusResult<usize> {
                    Err(NexusError::NotSupported(
                        "WASM datagram socket not fully implemented".into(),
                    ))
                }
                async fn recv(&self, _buf: &mut [u8]) -> NexusResult<usize> {
                    Err(NexusError::NotSupported(
                        "WASM datagram socket not fully implemented".into(),
                    ))
                }
                fn stats(&self) -> crate::traits::datagram::DatagramStats {
                    Default::default()
                }
                fn supports_multicast(&self) -> bool {
                    false
                }
                async fn join_multicast(&self, _multicast_addr: SocketAddr) -> NexusResult<()> {
                    Err(NexusError::NotSupported(
                        "Multicast not supported on WASM".into(),
                    ))
                }
                async fn leave_multicast(&self, _multicast_addr: SocketAddr) -> NexusResult<()> {
                    Err(NexusError::NotSupported(
                        "Multicast not supported on WASM".into(),
                    ))
                }
            }

            let socket = HolePunchedSocket {
                socket: Box::new(WasmDatagramSocket {
                    peer_addr: config.peer_public_addr,
                }),
                peer_addr: config.peer_public_addr,
                stats,
            };

            // Keep connection alive by not closing peer_connection and data_channel
            // In production, these would be stored in the HolePunchedSocket
            std::mem::forget(peer_connection);
            std::mem::forget(data_channel);

            return Ok(socket);
        }

        #[cfg(not(target_family = "wasm"))]
        {
            Err(NexusError::Platform(
                "WASM hole punching called on non-WASM target".to_string(),
            ))
        }
    }

    async fn get_external_ip(&self, stun_server: &str) -> NexusResult<IpAddr> {
        // In browser, we can get external IP through WebRTC

        #[cfg(target_family = "wasm")]
        {
            use js_sys::Array;
            use wasm_bindgen::prelude::*;
            use wasm_bindgen_futures::JsFuture;
            use web_sys::*;

            // Create RTCPeerConnection with provided STUN server
            let config = RtcConfiguration::new();
            let ice_servers = Array::new();

            let server = RtcIceServer::new();
            server.set_urls(&JsValue::from_str(stun_server));
            ice_servers.push(&server);

            config.set_ice_servers(&ice_servers);

            let peer_connection =
                RtcPeerConnection::new_with_configuration(&config).map_err(|e| {
                    NexusError::NatTraversal(format!("Failed to create peer connection: {:?}", e))
                })?;

            // Create a data channel to trigger ICE gathering
            let data_channel = peer_connection.create_data_channel("ip-detection");

            // Create an offer to start ICE gathering
            let offer_promise = peer_connection.create_offer();
            let offer = JsFuture::from(offer_promise).await.map_err(|e| {
                NexusError::NatTraversal(format!("Failed to create offer: {:?}", e))
            })?;

            let offer_desc = offer
                .dyn_into::<RtcSessionDescription>()
                .map_err(|_| NexusError::NatTraversal("Invalid offer".to_string()))?;

            let offer_init = {
                let obj = js_sys::Object::new();
                js_sys::Reflect::set(&obj, &"type".into(), &RtcSdpType::Offer.into()).unwrap();
                js_sys::Reflect::set(&obj, &"sdp".into(), &offer_desc.sdp().into()).unwrap();
                obj
            };

            let set_local = peer_connection.set_local_description(offer_init.unchecked_ref());
            JsFuture::from(set_local).await.map_err(|e| {
                NexusError::NatTraversal(format!("Failed to set local description: {:?}", e))
            })?;

            // Wait for ICE candidates
            let (tx, mut rx) = futures::channel::oneshot::channel();
            let tx = std::rc::Rc::new(std::cell::RefCell::new(Some(tx)));
            let external_ip = std::rc::Rc::new(std::cell::RefCell::new(None));

            let external_ip_clone = external_ip.clone();
            let tx_clone = tx.clone();
            let onicecandidate =
                Closure::wrap(Box::new(move |event: web_sys::RtcPeerConnectionIceEvent| {
                    if let Some(candidate) = event.candidate() {
                        let candidate_str = candidate.candidate();

                        // Look for server reflexive (srflx) candidate which contains our external IP
                        if candidate_str.contains("typ srflx") {
                            // Parse candidate string: "candidate:... IP PORT typ srflx..."
                            if let Some(ip_str) = candidate_str.split_whitespace().nth(4) {
                                if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                                    *external_ip_clone.borrow_mut() = Some(ip);
                                    if let Some(sender) = tx_clone.borrow_mut().take() {
                                        let _ = sender.send(());
                                    }
                                }
                            }
                        }
                    } else if external_ip_clone.borrow().is_some() {
                        // Gathering complete and we have an IP
                        if let Some(sender) = tx_clone.borrow_mut().take() {
                            let _ = sender.send(());
                        }
                    }
                }) as Box<dyn FnMut(_)>);

            peer_connection.set_onicecandidate(Some(onicecandidate.as_ref().unchecked_ref()));
            onicecandidate.forget();

            // Wait with timeout
            let timeout = Box::pin(async {
                wasm_bindgen_futures::JsFuture::from(js_sys::Promise::new(
                    &mut |resolve, _reject| {
                        web_sys::window()
                            .unwrap()
                            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 5000)
                            .unwrap();
                    },
                ))
                .await
                .ok();
            });

            futures::select! {
                _ = rx => {},
                _ = timeout.fuse() => {},
            }

            // Clean up
            peer_connection.close();
            data_channel.close();

            // Return discovered external IP
            let ip = external_ip.borrow().clone();
            ip.ok_or_else(|| {
                NexusError::NatTraversal(
                    "Failed to discover external IP: no srflx candidate found".to_string(),
                )
            })
        }

        #[cfg(not(target_family = "wasm"))]
        {
            Err(NexusError::Platform(
                "WASM external IP discovery called on non-WASM target".to_string(),
            ))
        }
    }

    async fn test_connectivity(&self, peer_addr: SocketAddr) -> NexusResult<ConnectivityResult> {
        // In browser, connectivity testing is done through WebRTC

        #[cfg(target_family = "wasm")]
        {
            use js_sys::Array;
            use wasm_bindgen::prelude::*;
            use wasm_bindgen_futures::JsFuture;
            use web_sys::*;

            // Create RTCPeerConnection with STUN servers
            let config = RtcConfiguration::new();
            let ice_servers = Array::new();

            for server_url in &self.stun_servers {
                let server = RtcIceServer::new();
                server.set_urls(&JsValue::from_str(server_url));
                ice_servers.push(&server);
            }

            config.set_ice_servers(&ice_servers);

            let peer_connection =
                RtcPeerConnection::new_with_configuration(&config).map_err(|e| {
                    NexusError::NatTraversal(format!("Failed to create peer connection: {:?}", e))
                })?;

            // Create a data channel for testing
            let data_channel_init = RtcDataChannelInit::new();
            data_channel_init.set_ordered(true);

            let data_channel = peer_connection.create_data_channel_with_data_channel_dict(
                "connectivity-test",
                &data_channel_init,
            );

            // Track connection state
            let connection_state =
                std::rc::Rc::new(std::cell::RefCell::new(RtcPeerConnectionState::New));
            let connection_state_clone = connection_state.clone();

            let (state_tx, _state_rx) = futures::channel::oneshot::channel();
            let state_tx = std::rc::Rc::new(std::cell::RefCell::new(Some(state_tx)));
            let state_tx_clone = state_tx.clone();

            let onconnectionstatechange = Closure::wrap(Box::new(move || {
                let state = connection_state_clone.borrow().clone();
                match state {
                    RtcPeerConnectionState::Connected => {
                        if let Some(sender) = state_tx_clone.borrow_mut().take() {
                            let _ = sender.send(true);
                        }
                    }
                    RtcPeerConnectionState::Failed | RtcPeerConnectionState::Closed => {
                        if let Some(sender) = state_tx_clone.borrow_mut().take() {
                            let _ = sender.send(false);
                        }
                    }
                    _ => {}
                }
            }) as Box<dyn FnMut()>);

            peer_connection.set_onconnectionstatechange(Some(
                onconnectionstatechange.as_ref().unchecked_ref(),
            ));
            onconnectionstatechange.forget();

            // Create offer for signaling (in real scenario, this would be exchanged with peer)
            let offer_promise = peer_connection.create_offer();
            let offer = JsFuture::from(offer_promise).await.map_err(|e| {
                NexusError::NatTraversal(format!("Failed to create offer: {:?}", e))
            })?;

            let offer_desc = offer
                .dyn_into::<RtcSessionDescription>()
                .map_err(|_| NexusError::NatTraversal("Invalid offer".to_string()))?;

            let offer_init = {
                let obj = js_sys::Object::new();
                js_sys::Reflect::set(&obj, &"type".into(), &RtcSdpType::Offer.into()).unwrap();
                js_sys::Reflect::set(&obj, &"sdp".into(), &offer_desc.sdp().into()).unwrap();
                obj
            };

            let set_local = peer_connection.set_local_description(offer_init.unchecked_ref());
            JsFuture::from(set_local).await.map_err(|e| {
                NexusError::NatTraversal(format!("Failed to set local description: {:?}", e))
            })?;

            // Measure RTT by monitoring data channel opening time
            let start_time = std::time::Instant::now();

            // Track data channel state
            let (dc_tx, mut dc_rx) = futures::channel::oneshot::channel();
            let dc_tx = std::rc::Rc::new(std::cell::RefCell::new(Some(dc_tx)));
            let dc_tx_clone = dc_tx.clone();

            let onopen = Closure::wrap(Box::new(move || {
                if let Some(sender) = dc_tx_clone.borrow_mut().take() {
                    let _ = sender.send(true);
                }
            }) as Box<dyn FnMut()>);

            data_channel.set_onopen(Some(onopen.as_ref().unchecked_ref()));
            onopen.forget();

            // Wait for connection with timeout
            let timeout = Box::pin(async {
                wasm_bindgen_futures::JsFuture::from(js_sys::Promise::new(
                    &mut |resolve, _reject| {
                        web_sys::window()
                            .unwrap()
                            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 10000)
                            .unwrap();
                    },
                ))
                .await
                .ok();
                false
            });

            let success = futures::select! {
                result = dc_rx => result.unwrap_or(false),
                result = timeout.fuse() => result,
            };

            let elapsed = start_time.elapsed();

            // Clean up
            peer_connection.close();
            data_channel.close();

            let result = if success {
                ConnectivityResult {
                    success: true,
                    rtt: Some(elapsed),
                    error: None,
                    packet_loss: None, // WebRTC handles retransmission internally
                }
            } else {
                ConnectivityResult {
                    success: false,
                    rtt: None,
                    error: Some(format!(
                        "Failed to establish connectivity to {} within timeout",
                        peer_addr
                    )),
                    packet_loss: None,
                }
            };

            return Ok(result);
        }

        #[cfg(not(target_family = "wasm"))]
        {
            Err(NexusError::Platform(
                "WASM connectivity test called on non-WASM target".to_string(),
            ))
        }
    }

    fn get_traversal_strategy(&self, nat_type: &NatType) -> TraversalStrategy {
        // In browser context, WebRTC handles most NAT traversal automatically
        // We mainly need to provide ICE servers

        match nat_type {
            NatType::None => TraversalStrategy::Direct,
            NatType::FullCone { .. } | NatType::RestrictedCone { .. } => {
                // WebRTC can usually handle these
                TraversalStrategy::SimpleHolePunch
            }
            NatType::PortRestrictedCone { .. } | NatType::Symmetric { .. } => {
                // These might need TURN relay
                TraversalStrategy::TurnRelay {
                    relay_server: "turn:stun.l.google.com:19302".to_string(),
                    credentials: None, // Would need actual TURN credentials
                }
            }
            NatType::Unknown | NatType::DetectionFailed(_) => {
                // Try both approaches
                TraversalStrategy::Sequential(vec![
                    TraversalStrategy::SimpleHolePunch,
                    TraversalStrategy::TurnRelay {
                        relay_server: "turn:stun.l.google.com:19302".to_string(),
                        credentials: None,
                    },
                ])
            }
        }
    }
}

impl std::fmt::Debug for WasmNatTraversal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmNatTraversal").finish()
    }
}
