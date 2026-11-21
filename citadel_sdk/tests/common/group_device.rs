//! Devices of one account for the device-transfer group test: each derives the account's key
//! from the recovery phrase's seed, as an application does.

use crate::common::group::REJOIN_DEADLINE;
use crate::common::recovery::DOMAIN;
use citadel_io::tokio;
use citadel_sdk::prelude::*;
use futures::StreamExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The seed a device derives the account's key from, once it knows the account's phrase.
pub type Root = Arc<Mutex<Option<[u8; 32]>>>;

pub fn device<'a, K: NetKernel<StackedRatchet> + 'a>(kernel: K, root: Root) -> NodeFuture<'a, K> {
    let keys = move |cid: u64| {
        let root = (*root.lock().unwrap())?;
        RevfsKey::derive(&root, DOMAIN, cid).ok()
    };
    citadel_sdk::test_common::node_builder()
        .with_link_manager(LinkManagerMode::Legacy)
        .with_stun_servers(citadel_sdk::test_common::LOCALHOST_STUN_SERVERS)
        .with_max_security_level(citadel_sdk::test_common::localhost_max_security_level())
        .with_revfs_key_source(keys)
        .build(kernel)
        .unwrap()
}

/// Waits until the server keeps a sealed state of `member`'s for `key`.
pub async fn until_state_kept(
    server: &NodeRemote<StackedRatchet>,
    member: u64,
    key: MessageGroupKey,
) {
    let pers = server.account_manager().get_persistence_handler().clone();
    let sub_key = key.mgid.to_string();
    tokio::time::timeout(REJOIN_DEADLINE, async move {
        while pers
            .get_byte_map_value(member, key.cid, GROUP_BACKUP_MAP, &sub_key)
            .await
            .expect("the server's kept states are readable")
            .is_none()
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the server never kept the member's state")
}

/// Reads `rx` until a message starting with `prefix`; `false` if none came in time.
pub async fn read(rx: &mut GroupChannelRecvHalf, prefix: &str) -> bool {
    tokio::time::timeout(REJOIN_DEADLINE, async {
        while let Some(payload) = rx.next().await {
            match payload {
                GroupBroadcastPayload::Message { payload, .. }
                    if payload.as_ref().starts_with(prefix.as_bytes()) =>
                {
                    return true;
                }
                other => log::info!(target: "citadel", "while waiting for {prefix}: {other:?}"),
            }
        }
        false
    })
    .await
    .unwrap_or(false)
}

/// Sends `prefix-N` every 500 ms until `read` is set: a message sent before the reader's
/// Welcome lands is sealed under a leaf it no longer holds.
pub async fn send_until_read(
    tx: &GroupChannelSendHalf,
    prefix: &str,
    read: &AtomicBool,
) -> Result<(), NetworkError> {
    let started = std::time::Instant::now();
    let mut n = 0u32;
    while !read.load(Ordering::SeqCst) && started.elapsed() < REJOIN_DEADLINE {
        tx.send_message(SecBuffer::from(format!("{prefix}-{n}").into_bytes()))
            .await?;
        n += 1;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Ok(())
}
