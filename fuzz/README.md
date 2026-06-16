# Citadel Protocol — AFL fuzzing

Coverage-guided fuzzing of the protocol's **untrusted-input parse/validate boundary** with
[AFL](https://github.com/AFLplusplus/AFLplusplus) via [`afl.rs`](https://github.com/rust-fuzz/afl.rs).

This is a standalone crate (not a workspace member — see `exclude = ["fuzz"]` in the root
`Cargo.toml`) so the AFL-instrumented build never touches the main build/CI. The harnesses call thin
wrappers in `citadel_proto::fuzz_targets`, exposed only under that crate's `fuzzing` feature.

## Targets (`fuzz/src/bin/`)

| binary | boundary it fuzzes |
|---|---|
| `hdp_header_parse` | zero-copy `HdpPacket::parse` over arbitrary inbound bytes |
| `header_obfuscator` | header-obfuscator deobfuscation (untrusted 16-byte cipher key + wrapping arithmetic) |
| `group_header_validate` | group-header bincode deser + `GroupReceiverConfig::validate()` (DoS / allocation bound) |
| `file_packet_deser` | file / RE-VFS packet bincode deser (untrusted paths + metadata) |

Seed corpora live in `corpus/<target>/`.

## Run

```bash
# from the repo root:
cargo make fuzz                       # all targets, 60s each (FUZZ_SECONDS), auto-installs cargo-afl
FUZZ_SECONDS=300 FUZZ_TARGETS=hdp_header_parse cargo make fuzz   # one target, longer

# or directly:
cargo install cargo-afl               # the CLI (the `afl` dep is the library/harness only)
cd fuzz && cargo afl build --release
cargo afl fuzz -i corpus/hdp_header_parse -o out/hdp_header_parse -- target/release/hdp_header_parse
```

The `fuzz` task fails if any crash is found (`out/<t>/default/crashes/`) **or** if AFL never actually
ran (no `fuzzer_stats` — a setup problem).

### First-run setup

AFL needs shared memory + a non-piped core pattern:

```bash
cargo afl system-config   # sudo; sets core_pattern / CPU governor (Linux) and SysV shmem (macOS)
```

On **macOS** this is required (otherwise `shmget() failed`); it also unloads the system crash reporter
for the session. On **Linux CI** the `fuzz.yml` workflow runs it automatically.

## CI

`.github/workflows/fuzz.yml` — manual (`workflow_dispatch`) + weekly (Sun 03:00 UTC), Ubuntu. Never on
the PR path (AFL is long-running). Uploads crashes + the minimized queue as artifacts and fails on any
crash. A panic-only smoke test (`citadel_proto`, `fuzz_targets::tests`) runs on the normal PR path.

## A crash?

The reproducer is `out/<target>/default/crashes/id:*`. Replay it:

```bash
cd fuzz && target/release/<target> < out/<target>/default/crashes/id:000000,...
```
