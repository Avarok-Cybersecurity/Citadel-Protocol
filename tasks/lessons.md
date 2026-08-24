
## 2026-08-23 media-udp session
- NEVER `git stash` in the main worktree while subagents are concurrently writing files — their
  edits land between stash and pop. Use a separate `git worktree` for baseline measurements.
- When a bench arm "hangs", suspect a silent task-death path (here: oversize QUIC datagram killed
  the UDP pump on master); make per-packet errors non-fatal and typed before benching.
- Reliable-lane control signals (EOS) race unreliable-lane data: control messages that terminate a
  stream must carry the final sequence/count so the receiver can drain deterministically.
- A jitter buffer must lock its playout start AFTER the hold-back window (lowest buffered seq),
  never on the first-arrived frame.
- wasm-clean tests gated `#[cfg(target_family="wasm")]` are dead code natively — port the same
  logic to a native test too, or run wasm-pack locally before declaring victory (the crate agent's
  wasm test had a real product bug that `cargo check --tests` could not catch).

## 2026-08-24 CI flakiness session
- A flake that survived 5 prior spot-fixes = multiple stacked races. Fix one, RERUN the stress
  loop — do not declare victory on theory. (v1 fix: 4/30→1/30; only v3 reached 60/60.)
- Client request queues do NOT preserve wire order between drop-handler signals and explicit
  calls. Server cleanup keyed on client signal arrival is inherently racy; key on synchronous
  server events (consumption/establishment) instead.
- RUST_LOG=citadel=info in CI hides both test-target logs and trace-level protocol state; for
  protocol forensics use citadel=trace and expect test markers to vanish (different target).
- To raise a reconnect-race repro rate: crank the test's iteration count (3→12 made it 1-in-8
  per run instead of 1-in-40+), isolate in a worktree with its own target dir.
