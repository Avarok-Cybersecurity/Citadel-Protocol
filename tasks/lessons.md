
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
