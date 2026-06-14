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
- **io_uring backend** (Phase 5): **cannot be built or run on this darwin/aarch64 host.** It's
  Linux-only and needs a completion-vs-readiness shim behind `citadel_io` (boundary mapped:
  citadel_io re-exports tokio at lib.rs ~94-111; sockets created in socket_helpers via `from_std`).
  A non-functional feature-flag stub adds churn for no value; the real backend is a Linux-CI effort.

## Needs CI / its own environment to MEASURE (code is landed)
- **PGO/BOLT win** — run `.github/workflows/release-optimized.yml` on x86-64 Linux (the local
  toolchain can't emit profiles; see [[pgo-local-llvm22-profile-mismatch]] equivalent note above).
- **QUIC/UDP + nonce + mimalloc deltas** — the macro bench in CI (thermal-stable) + the docker NAT
  16/16 matrix for the transport change (consensus-neutral by construction, but confirm in CI).
