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

/// Verify all EncryptionAlgorithm variants work with SessionSecuritySettingsBuilder on WASM.
#[wasm_bindgen_test]
fn test_all_encryption_algorithms() {
    let algorithms = [
        EncryptionAlgorithm::AES_GCM_256,
        EncryptionAlgorithm::ChaCha20Poly_1305,
        EncryptionAlgorithm::Ascon80pq,
    ];

    for enc in algorithms {
        let result = SessionSecuritySettingsBuilder::default()
            .with_crypto_params(enc + KemAlgorithm::MlKem)
            .build();
        assert!(result.is_ok(), "Failed for encryption: {enc:?}");
    }
}

/// Verify all SecurityLevel variants are constructible on WASM.
#[wasm_bindgen_test]
fn test_all_security_levels() {
    let levels = [
        SecurityLevel::Standard,
        SecurityLevel::Reinforced,
        SecurityLevel::High,
        SecurityLevel::Ultra,
        SecurityLevel::Extreme,
        SecurityLevel::Custom(10),
    ];

    for level in levels {
        let result = SessionSecuritySettingsBuilder::default()
            .with_security_level(level)
            .build();
        assert!(result.is_ok(), "Failed for security level: {level:?}");
    }
}

/// Verify BackendType::default() returns InMemory on WASM.
#[wasm_bindgen_test]
fn test_backend_type_default_is_in_memory() {
    let backend = BackendType::default();
    assert_eq!(backend, BackendType::InMemory);
}

/// Verify UdpMode variants are configurable on WASM.
#[wasm_bindgen_test]
fn test_udp_mode_variants() {
    let _peers = PeerConnectionSetupAggregator::default()
        .with_peer_custom("peer1")
        .with_udp_mode(UdpMode::Disabled)
        .add()
        .with_peer_custom("peer2")
        .with_udp_mode(UdpMode::Enabled)
        .add();
}

/// Verify SecrecyMode variants work in session settings on WASM.
#[wasm_bindgen_test]
fn test_secrecy_modes() {
    let modes = [SecrecyMode::BestEffort, SecrecyMode::Perfect];

    for mode in modes {
        let result = SessionSecuritySettingsBuilder::default()
            .with_secrecy_mode(mode)
            .build();
        assert!(result.is_ok(), "Failed for secrecy mode: {mode:?}");
    }
}

/// Verify MlKemHybrid encryption works (combines PQC + classical + signature).
#[wasm_bindgen_test]
fn test_hybrid_encryption_settings() {
    // MlKemHybrid requires a post-quantum signature algorithm
    let result = SessionSecuritySettingsBuilder::default()
        .with_crypto_params(
            EncryptionAlgorithm::MlKemHybrid + KemAlgorithm::MlKem + SigAlgorithm::MlDsa65,
        )
        .with_security_level(SecurityLevel::Ultra)
        .build();
    assert!(result.is_ok());
}
