//! Shared bootstrap for the typed facades: engine construction plus initial-value
//! establishment. Exactly the `initial_value_owner` supplies `Some(initial)`
//! (mirroring the 2-node primitives' one-`Some` rule, but with an explicit,
//! config-designated owner instead of an implicit role).

use crate::sync::group::acceptor::AcceptorStateStore;
use crate::sync::group::config::GroupLockConfig;
use crate::sync::group::engine::Engine;
use crate::sync::group::error::GroupLockError;
use crate::sync::group::op_types::{Op, OpDenied};
use crate::sync::group::proposer::ProposeError;
use crate::sync::group::transport::GroupTransport;
use crate::sync::group::LockId;
use crate::sync::primitives::NetObject;
use std::sync::Arc;

pub(crate) async fn create_engine<T: NetObject>(
    transport: Arc<GroupTransport>,
    lock_id: LockId,
    cfg: GroupLockConfig,
    store: Arc<dyn AcceptorStateStore>,
    initial: Option<T>,
) -> Result<Arc<Engine>, GroupLockError> {
    let is_owner = cfg.local_id() == cfg.initial_value_owner();
    if is_owner != initial.is_some() {
        return Err(GroupLockError::InitialValueOwnership {
            local: cfg.local_id(),
            owner: cfg.initial_value_owner(),
        });
    }
    if transport.local_id() != cfg.local_id() {
        return Err(GroupLockError::InvalidConfig(
            "transport local_id differs from config local_id".to_string(),
        ));
    }

    // Fold a value-type tag into the packet digest so two members configuring the
    // same lock id with different T fail fast (dropped packets + loud logs) instead
    // of exchanging garbage bytes. Uses type_name, which is stable within a build
    // but not guaranteed across rustc versions — heterogeneous-toolchain deployments
    // must keep member binaries in sync (already the norm for netbeam consumers).
    let type_tag = crate::sync::group::fnv1a(core::any::type_name::<T>().as_bytes());
    let mut digest_input = [0u8; 16];
    digest_input[..8].copy_from_slice(&cfg.digest().to_le_bytes());
    digest_input[8..].copy_from_slice(&type_tag.to_le_bytes());
    let wire_digest = crate::sync::group::fnv1a(&digest_input);

    let engine = Engine::new(transport, lock_id, cfg, wire_digest, store)?;
    let result = establish(&engine, initial).await;
    if result.is_err() {
        engine.shutdown();
    }
    result.map(|_| engine)
}

async fn establish<T: NetObject>(
    engine: &Arc<Engine>,
    initial: Option<T>,
) -> Result<(), GroupLockError> {
    let deadline_ms =
        crate::sync::group::engine_util::deadline(engine.now_ms(), engine.cfg.acquire_timeout());
    match initial {
        Some(value) => {
            let op = Op::Init {
                value: bincode::serialize(&value)?,
            };
            match engine.propose(&op, deadline_ms).await {
                Ok(_) => Ok(()),
                // a previous incarnation already initialized this lock: fine
                Err(ProposeError::Denied(OpDenied::AlreadyInitialized, _)) => Ok(()),
                Err(ProposeError::Denied(denied, _)) => Err(GroupLockError::Io(format!(
                    "unexpected init denial: {denied:?}"
                ))),
                Err(ProposeError::QuorumUnavailable) => Err(GroupLockError::QuorumUnavailable),
            }
        }
        None => loop {
            match engine.quorum_read(deadline_ms).await {
                Ok(Some(_)) => return Ok(()),
                Ok(None) => {
                    if engine.now_ms() >= deadline_ms {
                        return Err(GroupLockError::Timeout);
                    }
                    citadel_io::time::sleep(engine.cfg.waiter_poll_interval()).await;
                }
                Err(ProposeError::QuorumUnavailable) => {
                    return Err(GroupLockError::QuorumUnavailable)
                }
                Err(ProposeError::Denied(..)) => {
                    unreachable!("quorum_read never yields op denials")
                }
            }
        },
    }
}
