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

### LTO=fat + codegen-units=1 + strip — effect below local noise floor
Root `Cargo.toml [profile.release]`. Expected ~8-15% from cross-crate inlining/vectorization on the
per-packet crypto/serialization/scramble paths that span citadel_crypt/pqcrypto/proto. **Could not
resolve locally** (thermal noise > expected delta; a re-measure showed a uniform ~+45% across all
algos that recovered ~-13% after a 20s cooldown — i.e. throttling, not a real regression). Kept as
standard best-practice; **real effect to be measured on CI / the macro throughput bench**. NOT
`panic=abort` (a server must keep unwinding so one panicking task can't abort the process).

## TODO (this run)
- macro throughput/latency + multi-session bench (less thermal-sensitive; the metric the user cares
  about: msgs/sec, file MiB/s).
- mimalloc allocator; multiversioning; transport tuning; PGO+BOLT; io_uring; concurrency scaling.
