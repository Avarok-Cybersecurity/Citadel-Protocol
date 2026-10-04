//! Shared harness for the post-quantum sign-in suites: a server whose account manager the test
//! can read, with chosen sign-in settings and backend.

use crate::common::group::{Events, GroupTestKernel};
use citadel_io::tokio;
use citadel_io::tokio::sync::Mutex;
use citadel_sdk::prelude::*;
use citadel_sdk::test_common::server_test_node;
use citadel_user::auth::pq::oprf::OprfSeed;
use citadel_user::auth::pq::record::KsfParams;
use citadel_user::auth::pq::server::PqAuthServerSettings;
use citadel_user::server_misc_settings::ServerMiscSettings;
use futures::StreamExt;
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;

pub const PASSWORD: &str = "correct horse battery";

pub type Slot = Arc<Mutex<Option<NodeRemote<StackedRatchet>>>>;

pub fn pq_settings() -> ServerMiscSettings {
    ServerMiscSettings {
        pq_sign_in: Some(
            PqAuthServerSettings::new(OprfSeed::generate(), KsfParams::FLOOR).unwrap(),
        ),
        ..Default::default()
    }
}

pub fn server(
    misc: ServerMiscSettings,
    backend: Option<BackendType>,
) -> (impl std::future::Future<Output = ()>, SocketAddr, Slot) {
    let slot: Slot = Arc::new(Mutex::new(None));
    let kernel = {
        let slot = slot.clone();
        GroupTestKernel::new(
            move |remote: NodeRemote<StackedRatchet>, _: Events| async move {
                *slot.lock().await = Some(remote);
                Ok(())
            },
        )
    };
    let (node, addr) = server_test_node(kernel, |builder| {
        let _ = builder.with_server_misc_settings(misc);
        if let Some(backend) = backend {
            let _ = builder.with_backend(backend);
        }
    });
    (async move { node.await.map(|_| ()).unwrap() }, addr, slot)
}

pub fn username(tag: &str) -> String {
    format!("{tag}_{}", &Uuid::new_v4().to_string()[..8])
}

pub async fn login(
    remote: &NodeRemote<StackedRatchet>,
    user: &str,
    password: &str,
) -> Result<CitadelClientServerConnection<StackedRatchet>, NetworkError> {
    remote
        .connect_with_defaults(AuthenticationRequest::credentialed(
            user.to_string(),
            password,
        ))
        .await
}

/// Registers with password credentials but without the post-quantum exchange (no password handed
/// over for it), the way only a client from before the Argon2 sunset did.
pub async fn register_legacy(
    remote: &NodeRemote<StackedRatchet>,
    server_addr: SocketAddr,
    user: &str,
) -> Result<(), NetworkError> {
    let request = NodeRequest::RegisterToHypernode(RegisterToHypernode {
        remote_addr: server_addr,
        proposed_credentials: ProposedCredentials::new_register(user, user),
        static_security_settings: Default::default(),
        session_password: Default::default(),
        endpoint: None,
        password: None,
        admission: None,
    });
    let mut results = remote.send_callback_subscription(request).await?;
    while let Some(result) = results.next().await {
        match result.into_result()? {
            NodeResult::RegisterOkay(_) => return Ok(()),
            NodeResult::RegisterFailure(failure) => {
                return Err(NetworkError::msg(failure.error_message))
            }
            _ => {}
        }
    }
    Err(NetworkError::msg("registration ended without an answer"))
}

/// What the server stores for `user`.
#[derive(Debug)]
pub struct ServerRecord {
    pub post_quantum: bool,
}

pub async fn server_mode(slot: &Slot, user: &str) -> ServerRecord {
    let remote = slot.lock().await.clone().expect("server remote loaded");
    let cnac = remote
        .account_manager()
        .get_client_by_username(user)
        .await
        .unwrap()
        .expect("the server has the account");
    let mode = cnac.auth_store();
    ServerRecord {
        post_quantum: mode.pq_record().is_some(),
    }
}

/// Runs `client` against `server` until the client finishes.
pub async fn run<F, Fut>(server: impl std::future::Future<Output = ()>, client: F)
where
    F: FnOnce(NodeRemote<StackedRatchet>, Events) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<(), NetworkError>> + Send + 'static,
{
    let client = DefaultNodeBuilder::default()
        .build(GroupTestKernel::new(client))
        .unwrap();
    tokio::select! {
        _ = server => panic!("the server ended first"),
        res = client => { res.unwrap(); }
    }
}
