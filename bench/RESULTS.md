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

## Remaining (decisions / CI-gated) — see handoff
- **Nonce derivation SHA3-256 → BLAKE3** (Phase 3): biggest remaining per-message win, but
  WIRE/CRYPTO-BREAKING + security-sensitive (nonce uniqueness/unpredictability on the patent-pending
  ratchet) + sub-noise locally. Needs construction sign-off + CI measurement. NOT done autonomously.
- **QUIC transport tuning** (Phase 2): flow-control windows / MTU / BBR — needs the docker NAT 16/16
  matrix to validate (can't run locally), and must not perturb hole-punch timing.
- **mimalloc** (Phase 1): a library must not define `#[global_allocator]` (conflict risk); land it
  in the project's own binaries + an opt-in feature, measured via the macro bench.
- **PGO+BOLT** (Phase 4), **io_uring/Linux** (Phase 5), **StateContainer granularization + bounded
  channels** (Phase 6): larger efforts; PGO/io_uring need a Linux/CI environment to build+measure.
- **Macro throughput/latency bench**: foundation for measuring all of the above in CI + PGO training
  workload. Harness pattern identified (reuse `server_info_reactive` + `SingleClientServerConnectionKernel`
  + the `handle_send_receive_e2e` loop from tests/stress_tests.rs).
