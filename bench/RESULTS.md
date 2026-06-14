# Optimization Sweep — Benchmark Results

Branch: `perf/optimization-sweep` (off merged master). Measurement-driven: every change is
justified by a benchmark delta and gated on the correctness/NAT suites.

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
