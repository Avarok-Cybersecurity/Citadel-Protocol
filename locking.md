# Locking Audit (Citadel-Protocol)

Scope: initial deep dive focusing on citadel_crypt and citadel_proto. Goal: identify locks, whether they’re held across .await, and spots likely to block the Tokio runtime (> ~5ms), especially key exchange and crypto-heavy paths. Follow-ups will expand to other crates (netbeam, citadel_wire, etc.).

Recent changes:
- Applied “single lock per phase” to citadel_proto connect_packet.rs (STAGE0 and SUCCESS) and consolidated post-await channel_signal store into a short lock.
- Eliminated holding a write lock across await in peer_cmd_packet.rs PostConnect routing by introducing an internal-lock helper; lock now scoped to short pre-await operations.
- citadel_proto tests pass; workspace doctest issues in citadel_wire addressed (get_reuse_udp_socket -> get_udp_socket).

## Summary of High-Risk Findings

Scope: initial deep dive focusing on citadel_crypt and citadel_proto. Goal: identify locks, whether they’re held across .await, and spots likely to block the Tokio runtime (> ~5ms), especially key exchange and crypto-heavy paths. Follow-ups will expand to other crates (netbeam, citadel_wire, etc.).

## Summary of High-Risk Findings

- citadel_crypt::endpoint_crypto_container::commit_next_ratchet_version
  - Holds a write lock (parking_lot::RwLock via citadel_io::RwLock) over heavy crypto work (constructor stage0_bob, finish, update). Risk of blocking runtime and other readers/writers. Action: move heavy work out of the lock; optionally offload to tokio::task::spawn_blocking for multi-threaded builds.
- citadel_crypt::ratchets::ratchet_manager rekey path (trigger_rekey_with_payload, rekey)
  - Crypto-heavy operations (stage0_alice, new_bob, stage1_alice, bincode of large structures) run in async contexts without spawn_blocking. Action: offload heavy steps to spawn_blocking (multi-threaded); ensure no locks are captured by closures; keep lock scopes minimal.
- Async mutex held across await (bring to attention):
  - citadel_proto::proto::peer::hole_punch_compat_sink_stream::ReliableOrderedCompatStream.from_stream (tokio::Mutex) — recv awaits while guard held.
  - citadel_proto::proto::peer::channel (webrtc impl): recv_half (tokio::Mutex) — next().await while guard held.
  - citadel_crypt::ratchets::ratchet_manager::sender (tokio::Mutex) — send(...).await while guard held. Likely acceptable but should remain low contention.

Consider enabling parking_lot deadlock detection in debug (citadel_io exposes parking_lot::deadlock when feature-enabled).

## Inventory Table

| Brief Name | Crate | File Location | Fully qualified name | Held across .await? | Held for too long? |
|---|---|---|---|---|---|
| Toolset state (session crypto) | citadel_crypt | citadel_crypt/src/endpoint_crypto_container.rs (struct field `toolset`) | citadel_io::RwLock<Toolset<_>> (parking_lot::RwLock) | No | Yes – write lock held during heavy constructor work in commit_next_ratchet_version |
| Update-in-progress toggle | citadel_crypt | citadel_crypt/src/endpoint_crypto_container.rs | atomic/SyncToggle (no lock) | N/A | N/A |
| Sender (ratchet manager) | citadel_crypt | citadel_crypt/src/ratchets/ratchet_manager.rs (`sender`) | tokio::sync::Mutex<S> | Yes (send(...).await) | Unlikely (network-bound), but can serialize concurrent sends |
| Receiver (ratchet manager) | citadel_crypt | citadel_crypt/src/ratchets/ratchet_manager.rs (`receiver`) | citadel_io::Mutex<Option<I>> (parking_lot::Mutex) | No | No |
| Attached payload rx | citadel_crypt | citadel_crypt/src/ratchets/ratchet_manager.rs (`attached_payload_rx`) | citadel_io::Mutex<Option<UnboundedReceiver<_>>> | No | No |
| Local listener swap | citadel_crypt | citadel_crypt/src/ratchets/ratchet_manager.rs (`local_listener`) | citadel_io::Mutex<Option<oneshot::Sender<_>>> | No | No |
| Enqueued messages | citadel_crypt | citadel_crypt/src/messaging.rs (`enqueued_messages`) | tokio::sync::Mutex<VecDeque<_>> | No (lock released before await) | No |
| Stream buffer (scrambler) | citadel_crypt | citadel_crypt/src/scramble/streaming_crypt_scrambler.rs (`buffer`) | citadel_io::Mutex<Vec<u8>> (parking_lot::Mutex) | No | No (heavy encrypt offloaded via spawn_blocking) |
| Callback map | citadel_proto | citadel_proto/src/kernel/kernel_communicator.rs | citadel_io::Mutex<HashMap<..>> | No | No |
| Underlying TCP listener | citadel_proto | citadel_proto/src/proto/misc/underlying_proto.rs | citadel_io::Mutex<Option<tokio::net::TcpListener>> | No | No |
| Peer layer (outer) | citadel_proto | citadel_proto/src/proto/peer/peer_layer.rs (`CitadelNodePeerLayer.inner`) | citadel_io::tokio::sync::RwLock<CitadelNodePeerLayerInner<_>> | No | No |
| Peer layer (inner) | citadel_proto | citadel_proto/src/proto/peer/peer_layer.rs (`CitadelNodePeerLayerInner.inner`) | citadel_io::RwLock<SharedInner> (parking_lot::RwLock) | No | No |
| Hole punch compat stream inbox | citadel_proto | citadel_proto/src/proto/peer/hole_punch_compat_sink_stream.rs | citadel_io::tokio::sync::Mutex<UnboundedReceiver<Bytes>> | Yes (recv().await) | Potentially (await duration unbounded) – document justification or refactor |
| WebRTC compat recv_half | citadel_proto | citadel_proto/src/proto/peer/channel.rs (webrtc impl) | citadel_io::tokio::sync::Mutex<PeerChannelRecvHalf<_>> | Yes (next().await) | Potentially (await duration unbounded) – document justification or refactor |

Notes:
- “Held for too long?” is a heuristic relative to ~5ms. Crypto/KEM operations routinely exceed this threshold.
- Async locks held across await are called out to prompt review. In some cases these are acceptable if the lock guards exclusive access to a single receiver and there’s no broader contention.

## Key Crypto/Exchange Sites To Offload (spawn_blocking, multi-threaded)

- citadel_crypt
  - ratchets/ratchet_manager.rs
    - trigger_rekey_with_payload: stage0_alice()
    - rekey:
      - new_bob(...)
      - stage1_alice(...)
      - commit paths that call session_crypto_state.update_sync_safe(...)
  - endpoint_crypto_container.rs
    - commit_next_ratchet_version: stage0_bob(), finish_with_custom_cid(), update_from(...)
- citadel_proto
  - proto/packet_processor/register_packet.rs
    - STAGE0 (server/Bob): new_bob(...), stage0_bob(), finish()
    - STAGE1 (client/Alice): stage1_alice(...), finish()

Implementation guidelines:
- Do not hold any lock guards when calling spawn_blocking or awaiting its JoinHandle.
- Use platform/feature awareness:
  - multi-threaded + non-wasm: use tokio::task::spawn_blocking
  - single-threaded or wasm: call synchronously, but ensure minimal/zero lock scope
- Keep lock scopes minimal: compute heavy work first, then acquire write lock briefly to commit/swap state.

## Additions to Inventory (This PR)

- citadel_proto/src/proto/packet_processor/register_packet.rs
  - STAGE0: Heavy constructor work offloaded via spawn_blocking before state commit; single short lock for register_state updates. No locks across awaits.
  - STAGE1: Extracted constructor and creds under a short lock; stage1_alice + finish offloaded via spawn_blocking; state commit done under short lock. No locks across awaits.
  - STAGE2: Used read-only state to validate and construct work items; dropped state lock before account_manager awaits. No locks across awaits.
  - SUCCESS: Read-only state to validate; dropped state lock before account registration awaits; short post-await state updates where necessary.

- citadel_crypt/src/endpoint_crypto_container.rs
  - commit_next_ratchet_version: Verified heavy ops (stage0_bob/finish) computed outside write locks; only update_from commits under short write lock. Added @human-review note. Callers should offload heavy compute on async runtimes (spawn_blocking) — current register/connect flows comply.

- citadel_proto/src/proto/packet_processor/connect_packet.rs
  - STAGE0 (server): Short critical section updates connect_state, UDP oneshot, channel init, reads session_security_settings; no await while locked.
  - SUCCESS (client): Compatibility computed outside lock; short state read/commit; no await while locked. Channel_signal store happens post-await under a short lock.

- citadel_proto/src/proto/packet_processor/peer/peer_cmd_packet.rs
  - PostConnect (server): Previously held write lock on CitadelNodePeerLayerInner across await; now replaced with helper that acquires write lock only for route prelude, drops before await. Avoids runtime stalls.

## Proposed Next Steps

1) Refactor commit_next_ratchet_version to avoid heavy work under write lock (compute outside, short commit section). Add @human-review markers on critical transitions.
2) Offload key exchange steps in ratchet_manager and register_packet.rs via spawn_blocking for multi-threaded builds; ensure no captured locks.
3) Add clippy guardrails (#![warn(clippy::await_holding_lock)]) behind a feature if needed to avoid noise.
4) Add focused tests to verify event loop responsiveness while rekey/registration run (<= ~5ms jitter target in multi-threaded builds).
5) Revisit async mutex held-across-await cases in citadel_proto for justification or refactor suggestions.

## Appendix: Methodology

- Searched for locks: tokio::sync::{Mutex,RwLock}, citadel_io::{Mutex,RwLock}, parking_lot::{Mutex,RwLock}, std::sync::{Mutex,RwLock}
- Flagged any .await executed while holding async lock guards.
- Marked potential runtime-blocking sites where heavy crypto/KEM occurs inside async code paths.