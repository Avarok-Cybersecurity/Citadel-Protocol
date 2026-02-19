//! WASM Integration Tests — Basic P2P
//!
//! Verifies that the Citadel SDK P2P types and kernel lifecycle work
//! on the wasm32-unknown-unknown target.

#![cfg(target_family = "wasm")]

use citadel_sdk::prefabs::client::peer_connection::PeerConnectionSetupAggregator;
use citadel_sdk::prelude::*;
use wasm_bindgen_test::*;

/// Verify P2P type construction and configuration on WASM.
#[wasm_bindgen_test]
fn test_p2p_type_construction() {
    let _peers = PeerConnectionSetupAggregator::default()
        .with_peer_custom("alice")
        .with_udp_mode(UdpMode::Disabled)
        .add()
        .with_peer_custom("bob")
        .with_session_security_settings(SessionSecuritySettings::default())
        .add();
}

/// Verify NodeBuilder can be configured for a peer node on WASM.
#[wasm_bindgen_test]
fn test_node_builder_construction() {
    let mut builder = DefaultNodeBuilder::default();
    let _ = builder
        .with_node_type(NodeType::Peer)
        .with_backend(BackendType::InMemory)
        .with_stun_servers(["stun1", "stun2", "stun3"]);
}

/// Verify session security settings are constructible on WASM.
#[wasm_bindgen_test]
fn test_session_security_settings() {
    let settings = SessionSecuritySettingsBuilder::default()
        .with_crypto_params(EncryptionAlgorithm::AES_GCM_256 + KemAlgorithm::MlKem)
        .with_security_level(SecurityLevel::Standard)
        .build();
    assert!(settings.is_ok());
}

/// Verify the full kernel lifecycle works on WASM:
/// NodeBuilder::build() → KernelExecutor → CitadelNode::init() → kernel starts → shutdown.
#[wasm_bindgen_test]
async fn test_kernel_lifecycle_on_wasm() {
    struct ShutdownKernel {
        remote: citadel_io::Mutex<Option<NodeRemote<StackedRatchet>>>,
    }

    #[async_trait]
    impl NetKernel<StackedRatchet> for ShutdownKernel {
        fn load_remote(
            &mut self,
            server_remote: NodeRemote<StackedRatchet>,
        ) -> Result<(), NetworkError> {
            *self.remote.lock() = Some(server_remote);
            Ok(())
        }

        async fn on_start(&self) -> Result<(), NetworkError> {
            // Kernel successfully started on WASM — shut down cleanly
            let remote = self.remote.lock().clone().unwrap();
            remote.shutdown().await?;
            Ok(())
        }

        async fn on_node_event_received(
            &self,
            _message: NodeResult<StackedRatchet>,
        ) -> Result<(), NetworkError> {
            Ok(())
        }

        async fn on_stop(&mut self) -> Result<(), NetworkError> {
            Ok(())
        }
    }

    let kernel = ShutdownKernel {
        remote: citadel_io::Mutex::new(None),
    };

    let mut builder = DefaultNodeBuilder::default();
    let _ = builder
        .with_node_type(NodeType::Peer)
        .with_backend(BackendType::InMemory);

    let node_future = builder.build(kernel).expect("NodeBuilder::build failed");
    let _kernel = node_future.await.expect("Kernel execution failed");
}
