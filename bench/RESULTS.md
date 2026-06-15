# Optimization Sweep — Benchmark Results

Branch: `perf/optimization-sweep` (off merged master). Measurement-driven: every change is
justified by a benchmark delta and gated on the correctness/NAT suites.

## Speed v2 — DGX (20-core ARM) measurement findings (READ FIRST, reframes the scaling story)

Phase-0 of the v2 plan stood up a real many-core host (DGX: 10× Cortex-X925 + 10× Cortex-A725, Linux,
hardware AES). Three findings reframe everything:

1. **The multi-vconn *aggregate* ceiling is a BENCH ARTIFACT, not a protocol lock.** On 20 cores the
   P2P-mesh aggregate still *collapses* (mesh=2 → 49k msgs/s, mesh=16 → 20k) while StateContainer
   writes stay tiny (≤2.3k) and read-wait is ~600ns — the lock is provably idle. The mesh bench runs
   all K nodes in ONE process over the OS loopback + one tokio runtime, so the ceiling is shared
   process/loopback contention, NOT per-session lock contention. ⇒ multi-vconn *aggregate* is not a
   valid protocol-scaling signal; **single-stream (the macro bench) is the clean target.**
2. **`deadlock-detection` was confounding (and is decoupled now).** `citadel_sdk/localhost-testing`
   pulled `citadel_io/deadlock-detection` (parking_lot's process-global lock tracker). Measured cost
   ~5% at mesh=2 — real overhead, worth keeping out of benches, but NOT the ceiling (ruled out by a
   with/without A/B on the DGX). Now opt-in: `localhost-testing` is harness-only; tests/CI add
   `deadlock-detection` for the safety net; benches run without it.
3. **Single-stream baseline (macro bench, DGX, no deadlock-detection):**
   - AES-GCM best_effort: **12,752 msgs/s, 49.8 MiB/s, p50 484µs / p99 1781µs**
   - ChaCha20 best_effort: 15,661 msgs/s, 61.2 MiB/s, p50 506µs / p99 1994µs
   - AES-GCM **perfect (PFS): 762 msgs/s, 3.0 MiB/s, p50 1859µs / p99 3332µs** ← **~17× cliff**
   Two new top levers the research pass missed: (a) **PFS per-message rekey is a ~17× throughput
   cliff** — the single highest-impact win if Perfect mode is used; (b) **best_effort p50 ~500µs per
   loopback round-trip is all per-message software overhead** (not network) — the target for the
   latency wins (A1/A3/B6) + a single-stream flamegraph.

### Phase-A latency wins — outcomes
- **A3 (landed):** bound the inbound `try_for_each_concurrent(None,…)` to `Some(64)` (session.rs). The
  inbound reader + outbound writer share one `select!` task; unbounded inbound starves the writer
  (ACK/WAVE_ACK, OUTBOUND_FLUSH_BURST=32). A finite cap makes the reader go `Pending` when full, giving
  the writer a turn; ordering is enforced downstream by `OrderedChannel` so a cap is safe. (Correction:
  the "drop per-packet Arc clone" sub-item was a non-issue — `this_main` is already a `&` reference.)
- **A1 (attempted, REVERTED):** replacing the blind 100ms terminating-error sleep (session.rs:1111) with
  a deterministic flush-barrier (a `Flush(oneshot)` `OutboundPacket` the writer drains+acks) **broke
  `test_c2s_reconnection`**. Root cause: a `flush()` that errors on a closing socket made the writer's
  `select!` branch exit with that error, changing the session exit reason. Reverted; needs careful
  teardown-semantics work (best-effort flush that never changes the exit reason) — not a "safe" win yet.
- **B6 (SKIPPED — unsafe):** a lock-free in-order fast path for `OrderedChannel` is incorrect under
  concurrent delivery. `on_packet_received` can run concurrently for one channel (inbound
  `try_for_each_concurrent`), and a CAS-claim-then-`sink.send` fast path lets two in-order sends race →
  reordering. The `Mutex` is load-bearing (it serializes the send with the index advance; the reorder
  map keeps order regardless of lock-acquisition order). Eliding it is unsafe; keeping it costs ~15ns.
- **A4 (landed):** de-dup the per-packet header parse in `process_primary_packet`'s tracing span
  (`primary_group_packet.rs`). The `tracing::instrument` `fields(src = packet.parse()…, target =
  packet.parse()…)` ran the zerocopy `parse()` **twice** at span entry, and the body parses the header a
  third time — all under `localhost-testing` (the feature every bench runs with), inflating the dev-box
  numbers the whole plan is gated on. Fix: declare `src`/`target` as `tracing::field::Empty` (keeping
  `ret`/`err`) and `Span::record` them once from the header the body already parses → 3 parses → 1.
  Release path (feature off) is unchanged (DCE'd). Validated: c2s messaging stress passes; both feature
  states compile clean.
- **B7 (SKIPPED — premise invalid):** the plan flagged the rekey worker's O(n) scan of
  `active_virtual_connections` (session.rs:1209) as "meaningful at 40+ peers" and proposed a derived
  initiator-P2P index maintained at insert/remove. But **every** rekey frequency
  (`REKEY_UPDATE_FREQUENCY_{STANDARD..EXTREME}`) is **480 s**, and `DRILL_REKEY_WORKER` is the only
  trigger — so the scan runs once per 8 minutes per session. An O(n) HashMap filter over even hundreds of
  vconns, amortized over 480 000 ms, is unmeasurable; the lock is held for microseconds every 8 min.
  Against that, a parallel index mutated at 4 removal sites across 4 files (session_manager,
  peer_cmd_packet, p2p_conn_handler, wasm_p2p) is real SSOT/desync risk (a missed site → rekey on a dead
  vconn) for zero benefit. Not implemented — fails the "must win on the metric that isolates it" gate
  a priori.

## Benchmarking environment caveat (READ FIRST)

Local dev box is **Apple Silicon (aarch64) laptop** — thermally constrained. Back-to-back heavy
(LTO) builds throttle the CPU and inflate *all* micro-bench times uniformly by ~15-45%. Therefore:
- **Trust local micro-benches only for LARGE structural wins** (>~2x), which dominate the thermal
  noise (e.g. the aes_armv8 finding below).
- **Sub-~20% deltas (LTO, allocator, micro-opts) are below the local noise floor** — validate those
  on the **CI Linux runners** (stable) or via the **macro throughput bench** (less micro-sensitive),
  NOT this laptop. A uniform %-change across unrelated benchmarks = thermal, not code.

`cargo bench -p citadel_crypt --bench crypto_hot_path` (criterion). 256-byte message; SecurityLevel
Standard; MlKem. `--warm-up-time 1 --measurement-time 3`.

## Phase 0 baseline (master, default release profile, software AES on aarch64)

| bench | time | thrpt |
|---|---|---|
| protect AES-GCM-256 (256B msg) | **2.33 µs** | 104 MiB/s |
| protect ChaCha20-Poly1305 | 0.98 µs | 249 MiB/s |
| protect Ascon-80pq | 1.12 µs | 217 MiB/s |
| scramble AES-GCM 16 KiB | 168 µs | 93 MiB/s |
| scramble AES-GCM 256 KiB | 393 µs | 635 MiB/s |
| scramble AES-GCM 1 MiB | 1.07 ms | 930 MiB/s |

**Anomaly:** AES-GCM was 2.4× *slower* than ChaCha20 — backwards. Root cause: the RustCrypto `aes`
0.8.4 crate uses *software* (fixslice) AES on aarch64 unless `--cfg aes_armv8` enables the ARMv8
hardware-AES backend (x86-64 AES-NI is already runtime-detected). 2.33µs matches software-AES timing.

## Phase 1 — Build & toolchain

### aes_armv8 (aarch64 hardware AES) — CONFIRMED WIN (above thermal noise)
`.cargo/config.toml`: `[target.'cfg(target_arch="aarch64")'] rustflags=["--cfg","aes_armv8"]`.

| bench | before | after | delta |
|---|---|---|---|
| protect AES-GCM-256 | 2.33 µs | **0.80 µs** | **-65.6% (2.9×)** |

AES-GCM now *beats* ChaCha20 (as expected with HW AES). Also speeds the AES-GCM scramble path.
x86-64 unaffected (already runtime-detects AES-NI). Safe for application-class aarch64
(Apple Silicon / Graviton / modern ARM servers all have FEAT_AES).

### LTO=fat + codegen-units=1 + strip — compiles clean; effect below local noise floor
Root `Cargo.toml [profile.release]`. Expected ~8-15% from cross-crate inlining/vectorization on the
per-packet crypto/serialization/scramble paths that span citadel_crypt/pqcrypto/proto. **Could not
resolve locally** (thermal noise > expected delta; a re-measure showed a uniform ~+45% across all
algos that recovered ~-13% after a 20s cooldown — i.e. throttling, not a real regression). Kept as
standard best-practice; **real effect to be measured on CI / the macro throughput bench**. NOT
`panic=abort` (a server must keep unwinding so one panicking task can't abort the process).
**Build validated**: full-workspace `cargo build --release -p citadel_sdk` finishes in 3m25s,
exit 0 — fat LTO + cgu=1 compiles cleanly across all 13 crates, no OOM.

## Phase 2 — Transport tuning

### TCP_NODELAY on all long-lived TCP data paths — CORRECTNESS-VALIDATED
Nagle was only disabled on the brief QUIC-redirect handshake stream. The reliable-TCP data paths
(`OrderedReliable` plain TCP + `OrderedReliableSecure` TLS) ran WITH Nagle on both ends, coalescing
the protocol's small framed packets and adding per-message latency. Now `set_nodelay(true)` at every
TCP acquisition chokepoint (client connect + raw-TCP/TLS/WebSocket server accept). TCP-only — does
NOT touch the UDP/QUIC hole-punch path, so no NAT-matrix risk. **Validated: 8/8
stress_test_c2s_messaging (TCP/TLS/MlKemHybrid) pass; clippy -D warnings clean.** Latency delta
(esp. p99 on small messages) to be quantified by the macro bench / on a real WAN link.
Deliberately NOT sizing TCP SO_RCVBUF/SNDBUF: manual sizing disables the Linux kernel TCP autotuner
and commonly regresses throughput.

## Phase 0 macro bench — C2S messaging throughput + latency (FOUNDATION, done)
`citadel_sdk/benches/macro_throughput.rs` (custom harness). Full stack: connect → ratchet handshake
→ per-message AEAD+serialization on the reliable channel. Echo server + a pipelined throughput phase
and a serial ping-pong latency phase, synchronized by a per-config barrier so teardown can't race the
last receive. 4 KiB messages. Far less thermally sensitive than the micro-benches (sustained work),
and it is the PGO training workload. Writes `bench/macro_results.json` (gitignored — host-specific).

Run: `cargo bench -p citadel_sdk --features localhost-testing,multi-threaded --bench macro_throughput`
(env: `BENCH_MSGS`, `BENCH_LAT_ROUNDS`).

Representative baseline (this aarch64 laptop, current tree = aes_armv8 + LTO + TCP_NODELAY; 20k msgs,
2k rtts — indicative, not a regression gate; use CI for deltas):

| config | msgs/s | MiB/s | p50 | p99 |
|---|---|---|---|---|
| AES-GCM-256 / BestEffort | 25,217 | 98.5 | 360 µs | 880 µs |
| AES-GCM-256 / Perfect (PFS) | 1,325 | 5.2 | 1136 µs | 1190 µs |
| ChaCha20 / BestEffort | 23,573 | 92.1 | 442 µs | 906 µs |

Sanity: AES-GCM now edges out ChaCha20 (HW AES engaged); PFS per-message rekey is ~19× the
BestEffort path (expected). This is the harness deltas (mimalloc, QUIC tuning, PGO, nonce) get
measured against — reliably in CI, indicatively here.

## Phase 4 — PGO + BOLT pipeline (latest-method, user-requested)
Profile-Guided Optimization (+ optional BOLT post-link) wired as opt-in cargo-make tasks and a
non-blocking CI workflow. Training workload = the macro bench (real connect+handshake+per-message
crypto/serde paths), so the profiles reflect production hot code.

- `cargo make release-pgo` — instrument (`cargo pgo bench`) → train on the macro bench → optimized
  rebuild+measure (`cargo pgo optimize bench`). Works on all tier-1 targets incl. aarch64. Needs
  `llvm-tools-preview` (auto-added) + cargo-pgo (auto-installed).
- `cargo make release-pgo-bolt` — extends the above with a BOLT post-link pass. x86-64-Linux only
  (needs an LLVM built with BOLT); gracefully skips elsewhere.
- CI: `.github/workflows/release-optimized.yml` — manual + weekly (NOT on the PR path). Runs the
  plain-release baseline, then PGO, then PGO+BOLT on an x86-64 Linux runner, and uploads the
  msgs/sec + p50/p99 snapshots. This is the authoritative environment for the PGO/BOLT win (the
  laptop's thermal noise can't resolve it; CI can).

PGO measured win: **to be measured in CI** (Linux). Local validation on this aarch64 box ran the
full pipeline end-to-end (instrument build 2m11s → instrumented training run of all 3 configs →
optimize step, exit 0) but the instrumented binary emitted **no profiles** —
`LLVM Profile Error: Runtime and instrumentation version mismatch : expected 10, but get 8`. The
toolchain is internally consistent (rustc 1.96 / LLVM 22.1.2, matching llvm-profdata), so this is a
cargo-pgo-vs-LLVM-22 tooling gap on a bleeding-edge toolchain, not a pipeline defect. Consequently
`optimize` would have silently produced a NON-PGO binary — so `release-pgo` now **hard-fails** if no
`.profraw`/`.profdata` is generated (guard added), and the same guard protects the CI run. The
numbers from that local run were therefore plain-release±thermal, not PGO, and are not recorded as a
PGO win. The CI workflow (clean x86-64 Linux toolchain) is the authoritative measurement.

## Landed (this sweep)
aes_armv8 · release LTO · TCP_NODELAY · macro bench · PGO+BOLT pipeline · **mimalloc** (opt-in,
Phase 1) · **nonce SHA3→BLAKE3** (Phase 3, wire-breaking, proto v9→v10, 4 new nonce tests) · **QUIC
stream window 8 MiB + send 16 MiB + UDP buffers** (Phase 2, 7/7 P2P-over-QUIC stress pass). See git
log on `perf/optimization-sweep`.

## Follow-up sweep (`perf/sweep-followups`) — the four deferred items, revisited
**Landed:**
- **Multi-session contention bench** (`citadel_sdk/benches/multi_session_throughput.rs`): N concurrent
  C2S sessions → aggregate msgs/sec + per-session scaling efficiency. Local sample (laptop, CPU/
  loopback-confounded): eff 1.00→0.42(4)→0.14(16) — a real shared bottleneck; clean attribution
  needs a many-core CI runner + profiling.
- **Atomic ordering**: `session_queue_handler.rs` periodic-ticket counter `SeqCst → Relaxed` (counter
  only mints unique IDs; no happens-before needed). Cheaper fence on aarch64/ARM.

**Multiversioning — CONCLUSIVELY no target (no code).** Verified in `scramble_encrypt_wave`
(crypt_splitter.rs): the "scramble" is AEAD-encrypt (AES-NI/ARMv8, already dispatched) + zero-copy
ref-counted slicing + scalar port mapping + a packet-*order* shuffle. The data-parallel work is AEAD
and memcpy, both already SIMD. `#[multiversion]` anywhere here = bloat with no measured win.

**StateContainer split — warranted but a dedicated refactor.** Confirmed real intra-session
contention: `execute_inbound_stream` processes packets with `try_for_each_concurrent(None, …)`
(unbounded concurrency), so a single busy session's packet processors all serialize on its one
`StateContainer` write lock. BUT the hot collection (`active_virtual_connections`) is co-accessed
atomically with `stale_p2p_ratchets` + `peer_kem_states` in `create_virtual_connection` (the
simultaneous-connect tie-break), so splitting it needs CAS/coarse-guard preservation, not a naive
DashMap swap. Roadmap: (1) profile lock-wait on a many-core box with the new bench to confirm the
win; (2) first try converting hot read-only `inner_mut!`→`inner!` accesses (compiler-verified safe,
lets concurrent readers proceed) before splitting; (3) split per-collection with NAT+stress green
between steps.

## StateContainer phase (`perf/iouring-statecontainer`) — multi-vconn contention bench + first data

**Multi-vconn contention bench** (`citadel_sdk/benches/multi_vconn_throughput.rs`): the measurement
the lock-split actually needs. Drives a full P2P **mesh** of K peers so each peer's *single* session
holds K-1 peer vconns in *one* StateContainer; all pairs message simultaneously, so K-1 concurrent
inbound packet streams funnel through that session's single `inner_mut_state!` write guard. (The
other two benches each touch only one vconn per container — macro = 1 C2S vconn; multi-session = N
*separate* containers — so neither sees intra-session contention.) Added `TestBarrier::reset()` so one
process can sweep mesh sizes.

First local sweep (laptop, `bench` profile, 500 msgs/vconn/dir):

| mesh K | vconns/session | aggregate msgs/s | per-vconn | scaling-eff |
|---|---|---|---|---|
| 2 | 1 | 29,471 | 14,736 | 1.00 |
| 4 | 3 | 10,041 |   837 | 0.06 |
| 6 | 5 | 12,001 |   400 | 0.03 |
| 8 | 7 | 11,608 |   207 | 0.01 |

**Reading it — strong signal, one honest confounder.** Aggregate throughput *drops* ~3× from K=2→4
then plateaus ~10–12k while offered concurrency keeps rising. A throughput *collapse* under added
load (not a plateau) is the classic write-lock **convoy** signature — consistent with the per-packet
`inner_mut_state!` write lock on the single `Arc<RwLock<StateContainerInner>>` serializing + cache-
line-bouncing across concurrent vconns. Confounder: this is one process on a thermally-constrained
laptop, so whole-process CPU/crypto saturation is partly mixed into the K≥4 plateau; and the K=2
baseline is unusually high (2 nodes, minimal scheduling). So the bench *strongly motivates* the split
and gives the baseline to verify against, but clean attribution to the lock (vs. CPU) wants either a
flamegraph/lock-wait profile under K=8 or a many-core CI run. **Do not split blind on these numbers** —
profile first, then granularize, then re-run this bench to confirm the convoy flattens.

**ATTRIBUTION DONE — it's the lock, decisively.** Added an opt-in `lock-profiling` feature
(`citadel_proto::lock_profiling`, fed by the `inner_state!`/`inner_mut_state!` macros — which are used
*only* on `state_container`) that times each acquire-wait; the bench prints it per mesh size:

| mesh K | avg **write** acquire-wait | total write-wait (window) | aggregate msgs/s |
|---|---|---|---|
| 2 | **94 ns** | 0.2 ms | 20,697 |
| 4 | **101,060 ns** (~101 µs) | 970 ms | 10,959 |
| 8 | **125,304 ns** (~125 µs) | 5,576 ms | 13,187 |

The mean StateContainer write-lock acquire-wait jumps **~1,075×** (94 ns → 101 µs) the instant a
session holds >1 vconn, and total write-wait at K=8 is **5.6 s** of thread-time parked on one lock
during the window. CPU starvation cannot inflate *acquire-wait* (it slows work *between* acquisitions,
not the blocking on the lock itself) — this is a textbook write-lock **convoy**. So the single
`Arc<RwLock<StateContainerInner>>` write lock IS the multi-vconn ceiling, and granularization is
warranted. Roadmap unchanged but now evidence-backed: (1) cheap win first — flip hot read-only
`inner_mut!`→`inner!` so readers stop serializing; (2) split the hottest independently-accessed
collections to their own guards/DashMaps, preserving the `create_virtual_connection` cross-collection
tie-break; (3) re-run this bench under `lock-profiling` after each step — success = the avg write-wait
stops scaling with K.

**Corrected hot-path finding (messaging ≠ file transfer).** Tracing the bench workload (plain
messages, not file transfers): the per-message receive path is `primary_group_packet.rs:92`
`inner_mut_state!` → the `GROUP_HEADER::Ratchet` fast-message branch →
`forward_data_to_ordered_channel` (state_container.rs:553). That takes the **write** lock only to (a)
deliver into *one* vconn's `OrderedChannel` reorder buffer (`active_virtual_connections[target].
endpoint_container.to_ordered_local_channel.on_packet_received(&mut self)`) and (b) bump
`meta_expiry_state` (a single `Instant`). It does **not** touch `inbound_files`/`inbound_groups`/
`outbound_transmitters` (those are the *file-transfer* paths the first access-map focused on). So for
messaging the convoy is N vconns serializing their independent per-vconn deliveries on the one global
write lock — exactly what the profiler shows.

**Attempt 1 — read/write split (TRIED, MEASURED, REVERTED): the wrong tool.** Hypothesis: push the
per-message delivery's two mutations behind interior locks so the hot receive branch holds only a read
lock and N vconns deliver concurrently. Implemented + validated correct (15/15 c2s+p2p messaging
stress, strict ordering; rekey + reserve-write green), then profiled (mesh 2/4/8, `lock-profiling`):

| metric @ mesh=8 | before (write-only) | after read-flip |
|---|---|---|
| writes | 44,502 @ 125µs | **21,476 @ 168µs** (count halved, wait ↑) |
| reads  | 27,988 @ 104µs | **71,523 @ 40µs** (wait ↓ ~2.6×) |
| aggregate msgs/s | 11,608 | **11,720 (no change)** |

The flip worked *structurally* (receive-deliver moved to reads, read-wait fell sharply) but **did not
move throughput** — and write-wait *rose*. Root cause: **every message still needs ≥1 write** (the
*sender's* `GROUP_HEADER_ACK` → `on_group_header_ack_received` mutates `outbound_transmitters`).
Flooding the `RwLock` with reads just **starves the remaining writers**. Conclusion: read/write
splitting can't dissolve this convoy because the write floor is one-write-per-message. Reverted the
`primary_group_packet.rs`/proxy lock-mode flips (no win + starvation on the hottest path).

**KEPT (foundation, behavior-preserving, tested):** the interior-mutability that the *right* fix needs:
1. `citadel_crypt::ordered_channel::OrderedChannel`: reorder `map`+`last_message_received` behind a
   `citadel_io::Mutex`; `sink` already `&self`-send → `on_packet_received(&self)`. (3 ordering tests
   pass, incl. concurrent.)
2. `MetaExpiryState`: `last_valid_event` behind `citadel_io::Mutex<Instant>` → `on_event_confirmation
   (&self)`.
3. `forward_data_to_ordered_channel(&self)` (via the `&self` endpoint getter).

These are required because the real fix is **per-collection sharding**, where delivery goes through a
`DashMap::get` **shared** ref — so per-vconn `OrderedChannel`/meta_expiry mutation *must* be `&self`.

**Attempt 2 — DashMap-shard `outbound_transmitters` (DONE): the convoy is eliminated.** Scope shrank
once the foundation landed: the per-message path only *reads* `active_virtual_connections` (delivery
mutates the now-interior-mutable `OrderedChannel`; `last_delivered_message_timestamp` is `DualCell`),
so only **`outbound_transmitters`** — structurally mutated per message (sender `insert` on send,
`remove` on `GROUP_HEADER_ACK`) — needed concurrency. Changed it to `dashmap::DashMap` (wasm-checked),
made `on_group_header_ack_received(&self)`, and flipped the three per-message hot paths to a *read*
lock: receive-deliver (`primary_group_packet` GROUP_HEADER::Ratchet), sender-ack (GROUP_HEADER_ACK),
and the send-register path (`session.rs` group-sender loop). File/wave branches escalate read→write
via a wrapper alias. `on_wave_ack_received` + the outbound-file timeout closure were restructured for
DashMap's `Ref`/`RefMut` borrow semantics (re-borrow `&mut *guard` for field-splitting; read the flag
then drop the `Ref` before mutating other collections).

Profiled (mesh 2/4/8, `lock-profiling`) — **per-message StateContainer writes are gone**:

| metric | mesh=2 | mesh=4 | mesh=8 |
|---|---|---|---|
| writes (was 1.9k / 9.6k / 44.5k) | **5** | **103** | **574** |
| avg read-wait (was 0.1 / 77 / 104 µs) | 37 ns | **1.07 µs** | **1.03 µs** |

The write count fell ~99% (mesh=8: 44,502→574) and read-wait collapsed ~100× (104µs→1µs) — the convoy
the profiler attributed is **eliminated**, the metric that isolates the fix. (The 574 residual writes
are rare setup/teardown ops — `create_virtual_connection` etc. — totalling 162ms of wait over the
window, negligible.) Correctness: builds on
multi-threaded + single-threaded + **wasm**; clippy `-D warnings` clean; 17/17 c2s+p2p messaging
stress (strict ordering) + reserve-write + rekey; 9/9 file-transfer + reconnection.

**Aggregate throughput on this box stays flat (eff still ~0.02–0.07) — and that's expected.** With the
lock convoy gone, the remaining ceiling is the single-process **CPU/crypto saturation** confounder
flagged in the "READ FIRST" caveat: a fixed core count divided across K meshed nodes, each doing
per-message AEAD. The lock-wait metric (writes ~eliminated, read-wait ~1µs) is the correct measure
that the *lock* is fixed; the aggregate-throughput payoff needs a many-core box where CPU isn't the
binding constraint (run this bench on a CI server / many-core host to see it). Unlike the reverted
read/write-split (Attempt 1, which didn't even move the lock metric), this is a real, measured win on
the contention metric — landed. Remaining for a future pass: `active_virtual_connections` is still a
HashMap under the lock (only read per message, so not on the convoy path); shard it too only if a
many-core profile shows the read-side RwLock atomic (read-wait grew 37ns→1µs with K) becoming the next
ceiling. Docker NAT 16/16 validates in CI.

**Bounded outbound channels — wire channel must stay unbounded.** Re-confirmed: 74 `unbounded_send`
sites, many in the session task that also drains via `select!` → bounded `send().await` deadlocks.
The existing burst(32)+`yield_now` is the correct anti-starvation design. The safe OOM-under-
adversarial-load path is a producer-admission soft-cap (atomic queue-depth counter on
`OutboundPrimaryStreamSender`; the file-transfer wave producer — a separate task — pauses when
congested), NOT making the wire channel blocking. Scoped for dedicated flow-control work.

**io_uring — LANDED (Linux-only, opt-in `io-uring` feature).** The inbound raw-UDP recv half now has
an io_uring backend. The unsafe ring code lives in `citadel_io` (`standard/udp_io_uring.rs`) because
`citadel_proto` is `forbid(unsafe_code)`. It runs a single-shot (re-armed) `recvmsg` loop on a
dedicated OS thread over a `dup(2)`'d socket fd, bridging completions to the async side via an
unbounded channel; `RawUdpSocketStream` became a `Standard | IoUring` enum and only the io_uring
reader consumes the socket (the standard `SplitStream` is dropped). Graceful fallback: if
`io_uring_setup(2)` fails (old kernel / seccomp sandbox / fd-dup failure) `try_spawn` returns `None`
and the standard tokio path is used; the send half is untouched. Source addresses are decoded from
the kernel-filled `msg_name`, so behavior is byte-identical to the `UdpFramed`/`recv_from` path.
Validated on real Linux (arm64) via an OrbStack container, `cargo check`/`clippy` clean with the
feature, and **both datapaths proven**: (1) io_uring **active** (`--security-opt seccomp=unconfined`)
— the "Raw UDP recv using io_uring backend" trace fires on *both* ends of a C2S connection and the
8/8 UDP stress suite passes; (2) **fallback** — Docker's default seccomp blocks `io_uring_setup(2)`,
so `try_spawn` returns `None`, the standard tokio path is used, and the same suite passes. CI: a new
ubuntu-only `io_uring` job in `validate.yml` compile-checks both thread models and runs the UDP
stress tests (GitHub-hosted runners execute steps directly on the VM, so io_uring is typically
permitted there; either way the job is fallback-safe). Future optimization: provided-buffer multishot
(`RecvMsgMulti` + buf_ring) to amortize the per-recv SQE.

## Investigated and deliberately NOT landed (concrete blockers, not conservatism)
These were each researched to file:line; each has a real blocker that makes a blind, locally-
unvalidatable change unsafe on the just-stabilized datapath. Recorded so they can be done properly.

- **Runtime multiversioning** (Phase 1): **no valid target.** The data-parallel hot paths are already
  optimal — AEAD dispatches to AES-NI/ARMv8 at runtime, wave reassembly is memcpy. The plan's
  candidate `generate_packet_vector` (packet_vector.rs) is scalar (div-mod + map lookup), not a
  vectorizable loop. Applying `#[multiversion]` here = speculative bloat with no measured win →
  skipped per measure-first.
- **Bounded outbound channels** (Phase 6): **would deadlock.** 74 `unbounded_send`/`_split` call
  sites feed the primary stream, and many run *inside the session task's own packet-processing loop*
  (raw_primary_packet, peer_cmd, keep_alive, preconnect, …) — the same task that drains the channel
  via `select!`. A bounded `send().await` from that task while full deadlocks it; the failure only
  shows under load/NAT. The existing burst(32)+`yield_now` drain (session.rs ~848) is the correct
  mitigation. Safer future direction: a producer-admission soft-cap (reject new *application*
  messages above a queue-depth threshold) that never makes the wire channel itself blocking.
- **StateContainer granularization** (Phase 6): **cross-collection atomicity blocks a blind split.**
  10 sites hold the single guard across ≥2 hot collections (e.g. `on_group_payload_received` touches
  inbound_groups→inbound_files→file_transfer_handles atomically; state_container.rs ~1551). Splitting
  those into independent DashMaps breaks the invariants without CAS/versioning, and the contention
  *win* is unmeasurable on this box (needs the multi-session contention bench, not yet built). Do it
  per-collection with that bench + the NAT/stress suites green between steps — not in one blind pass.
- **io_uring backend** (Phase 5): **LANDED** — see the io_uring entry above. Built and run on real
  Linux via an OrbStack container (the darwin host can't run it natively); opt-in, fallback-safe, and
  CI-validated by the new `io_uring` job.

## Needs CI / its own environment to MEASURE (code is landed)
- **PGO/BOLT win** — run `.github/workflows/release-optimized.yml` on x86-64 Linux (the local
  toolchain can't emit profiles; see [[pgo-local-llvm22-profile-mismatch]] equivalent note above).
- **QUIC/UDP + nonce + mimalloc deltas** — the macro bench in CI (thermal-stable) + the docker NAT
  16/16 matrix for the transport change (consensus-neutral by construction, but confirm in CI).
