# Design: Symmetric Forward-Secure Ratchet for Perfect mode (PFS speed-up)

**Status:** DRAFT for review. No code until approved. Security-critical (touches forward secrecy).

## 1. Goal & constraint

`SecrecyMode::Perfect` messaging is ~762 msgs/s vs ~12,752 for `BestEffort` (AES-GCM, DGX 20-core) — a
**~17× throughput cliff** with p50 latency 1859µs vs 484µs. Goal: bring Perfect-mode messaging to
near-`BestEffort` throughput **without weakening forward secrecy**. Wire-breaking changes are allowed.

## 2. Current architecture (verified in source)

- A `StackedRatchet` is a stack of N security layers. Each layer = a `PostQuantumContainer` (holds the
  **AEAD symmetric key**, derived from the ML-KEM shared secret at ratchet construction) + an
  `EntropyBank` (a 32-byte `entropy` that keys the per-message **nonce** PRF). `citadel_crypt/src/
  ratchets/{stacked/ratchet.rs, entropy_bank.rs}`.
- Per message (`entropy_bank.rs:190-200` `wrap_with_unique_nonce_enx`): `transient_id =
  transient_counter.next_id()`; `nonce = BLAKE3_keyed(entropy, transient_id)`; AEAD-seal with the
  **PostQuantumContainer key** + that nonce; append `transient_id` as an 8-byte trailer.
- **Key insight:** within one ratchet *version*, every message uses the **same AEAD key**, only the
  nonce differs. There is **no symmetric per-message key ratchet** (no Signal-style sending chain).
- `SecrecyMode::Perfect` (`messaging.rs:268-283`): triggers a **full ML-KEM rekey per message** → a new
  version → a fresh AEAD key per message. That fresh-key-per-message IS the only source of per-message
  forward secrecy. Old versions are dropped from the `Toolset` `VecDeque` and `Zeroizing`-wiped
  (`toolset.rs:180-198`, `entropy_bank.rs:340`).
- The rekey is a 3-leg handshake `AliceToBob → BobToAlice → LeaderCanFinish` (`ratchet_manager.rs`,
  `RatchetMessage` enum `:165-181`), 1.5 RTT, fully serialized with head-of-line blocking ("200 msgs =
  200 rekeys"). ⇒ Perfect throughput is **network-RTT-bound per message**.
- `BestEffort` (`messaging.rs:246-265`): if a fresh key isn't ready, sends `JustMessage` reusing the
  **current** key (different nonce). No per-message FS; pipelined → 17× faster.

**Root cause of the cliff:** forward secrecy is provided *only* by the per-message KEM rekey, and a KEM
rekey is a sequential network round-trip. There is no cheap local mechanism to give each message a
distinct forward-secure key.

## 3. Proposed design — add a symmetric forward-secure chain (Double-Ratchet sending/receiving chain)

Introduce a **symmetric KDF chain per ratchet version and per direction**, so each message gets a
distinct forward-secure AEAD key from a *local* KDF (no round-trip). The ML-KEM rekey is demoted from
*per-message* to *periodic* (it now provides only post-compromise security / break-in recovery).

### 3.1 Key schedule

At ratchet-version creation (after the ML-KEM handshake establishes the shared secret), derive a
per-direction **chain key** seed:
```
RK            = HKDF-extract(KEM_shared_secret, transcript)          // root key (existing)
CK_send[0]    = BLAKE3::derive_key("citadel chain v1 send", RK || dir)
CK_recv[0]    = BLAKE3::derive_key("citadel chain v1 recv", RK || dir)   // mirror on the peer
```
Per message with chain index `i` (the existing `transient_counter` — already on the wire as the trailer):
```
MK_i          = BLAKE3::derive_key("citadel msgkey v1", CK[i] || i_be)   // 32-byte AEAD key
CK[i+1]       = BLAKE3::derive_key("citadel chain  v1", CK[i])           // ratchet the chain key
zeroize(CK[i])                                                            // immediately after deriving CK[i+1]
// AEAD-seal with key = MK_i; nonce stays BLAKE3_keyed(entropy, i) OR becomes a fixed nonce (unique key ⇒ safe)
zeroize(MK_i)                                                            // after the message is sealed/opened
```
The AEAD key per message becomes `MK_i` (was: the fixed PostQuantumContainer key). The chain advances
one KDF step per message — cheap, local, no network.

### 3.2 Receiver / out-of-order

The AEAD opens per packet as received, *before* `OrderedChannel` reorders, so packets can arrive out of
order (esp. the UDP wave path). Use a **bounded skipped-message-key cache** (Signal-style `MAX_SKIP`,
e.g. 1024): to open message `i` when the recv chain is at `j<i`, derive and cache `MK_j..MK_{i-1}`,
advancing `CK_recv`. Reject gaps `> MAX_SKIP` (DoS bound). On the ordered TCP/QUIC primary stream gaps
are ~0, so the cache is near-unused for messaging; it matters for the unordered UDP file path.

### 3.3 Periodic ML-KEM rekey (post-compromise security)

The existing rekey machinery is **retained**, but triggered **periodically** instead of per-message:
every `rekey_every_n_messages` (and/or `rekey_every_t`) it runs the 3-leg KEM handshake in the
background (overlapped with message flow, exactly like `BestEffort`'s opportunistic rekey) and re-seeds
`CK[*]` from the new root. This restores post-compromise security on that cadence. `Perfect` sets a
small cadence; `n=1` reproduces today's exact behavior (per-message KEM) as a config fallback.

### 3.4 Send path (Perfect, new)

`messaging.rs` Perfect arm: derive `MK_i` from the local chain and send **immediately** (no head-of-line
blocking on a KEM round-trip). The periodic KEM rekey is a separate background task. This makes Perfect
pipeline like BestEffort → throughput approaches the AEAD-bound ceiling (~12k+/s), not the RTT bound.

## 4. Security argument

**Forward secrecy — PRESERVED (the hard constraint).** `MK_i` and `CK[i]` come from a one-way KDF;
`CK[i]` is zeroized immediately after deriving `CK[i+1]`, and `MK_i` after use. An attacker who
compromises state at message `j` learns `CK[j]` (current chain key), from which they can derive
`MK_j, MK_{j+1}, …` up to the next KEM rekey — but **cannot** derive `MK_{<j}` (earlier chain keys are
gone and the KDF is not invertible). ⇒ **all messages before the compromise stay secret** = forward
secrecy, identical to today.

**Post-compromise security — RELAXED in cadence (the only delta).** Today every message heals (fresh
KEM). Under this design, healing happens every `n` messages / `t` seconds. The compromise window for
*future* messages widens from 1 message to the cadence. This is the standard Double-Ratchet trade and
the *only* security property that changes. It is **configurable** (`n=1` = today's behavior); document
it explicitly and pick a conservative default for `Perfect` (e.g. `n` small or `t` short).

**Nonce uniqueness.** Each message has a unique key `MK_i`, so AEAD nonce reuse across messages is
impossible regardless of nonce derivation; we can keep `BLAKE3_keyed(entropy, i)` or move to a fixed
per-key nonce. No reuse within a key (one message per key).

**Replay / ordering / zeroization.** The transient-id trailer + `OrderedChannel` anti-replay/order are
unchanged. `MK_i`/`CK[i]` use `Zeroizing`. The skipped-key cache is bounded (`MAX_SKIP`) to prevent a
memory-exhaustion DoS from a forged large gap.

## 5a. Step-2 integration findings (verified in citadel_pqcrypto)

The AEAD layer is algorithm-dependent (`export.rs:145` `keys_to_aead_store`):
- **AES-GCM-256 → `AesModule`, ChaCha20 → `ChaChaModule`, Ascon → `AsconModule`** — plain symmetric
  ciphers keyed once with a 32-byte (Ascon: 20-byte) key via `impl_basic_aead_module!` (`lib.rs:1279`).
  Send vs recv pick `alice_module`/`bob_module` by orientation (`get_encryption_key`/`get_decryption_key`,
  `lib.rs:505-524`). ⇒ **per-message re-keying is clean here**: construct a fresh cipher from `MK_i`.
- **MlKemHybrid → `KyberModule`** (`lib.rs:154-161`) — per-message KEM-OTP + signature, a heavier
  per-message-asymmetric construction. **OUT OF SCOPE for pipelining v1** (it is already per-message
  asymmetric; pipelining it is a separate effort). `PerfectPipelined` is offered only for the symmetric
  ciphers (AES/ChaCha/Ascon); selecting it with MlKemHybrid falls back to today's per-message KEM.

**Step-2 plan:** add stateless `seal_in_place_with_key(alg, &MK_i, nonce, ad, buf)` /
`open_in_place_with_key(...)` to citadel_pqcrypto (fresh cipher from `MK_i`; per-cipher key length —
AES/ChaCha take `MK_i[..32]`, Ascon `MK_i[..20]`). The per-direction `SymmetricChain` state lives with
the version's crypto state (one chain per layer per direction, seeded from that version's KEM secret);
`entropy_bank.rs`'s `wrap_with_unique_nonce_*` derives `MK_i` (index = the existing `transient_counter`)
and calls the with-key seal instead of the fixed-key module — only on the pipelined path. The fixed-key
path (BestEffort, Perfect n=1) is unchanged.

## 5b. Live-ratchet plumbing constraints (discovered while wiring; SECURITY-REVIEW critical)

Wiring the chain into `EntropyBank` surfaced four constraints the implementation + review MUST handle:

1. **Need a NEW sequential chain index — cannot reuse `transient_counter`.** The transient counter
   starts at a *random 63-bit base* on every construct/deserialize (`entropy_bank.rs:359-378`,
   deliberate anti-nonce-rollback) and is per-instance, so it is neither `0,1,2,…` nor shared as a
   chain position. The pipelined path needs the `SymmetricChain`'s own sequential index (`0,1,2,…`),
   transmitted in the packet (replacing/with the transient-id trailer). The nonce can stay
   `BLAKE3(entropy, chain_index)` (unique key per message makes nonce reuse harmless anyway).

2. **`EntropyBank` is shared across both directions** — `encrypt`/`decrypt` use one `&self` bank and the
   `PostQuantumContainer`'s `PQNode` (Alice/Bob) selects the AEAD key direction (`lib.rs:505-524`). So
   the bank must hold **two** direction-labeled chains (`a2b`/`b2a`) seeded from the shared `entropy`;
   `protect` advances `next_send_key` on the out-direction, `validate` calls `recv_key` on the
   in-direction, chosen by `PQNode`. Direction labels (not send/recv roles) make Alice's send chain
   equal Bob's recv chain.

3. **Chain send-index rollback safety (CRITICAL).** Re-emitting `MK_i` after a rollback reuses a
   forward-secure key — catastrophic. Unlike the nonce counter, the chain index is inherently sequential
   so it CANNOT use a random base. Therefore the chain state must be `#[serde(skip)]` (never persisted)
   **and** the protocol must guarantee a *fresh ratchet version (new KEM root → new chain @ index 0)*
   whenever a bank is restored/reconnected for the pipelined mode — i.e. pipelined sessions must rekey
   on restore, never resume a mid-version send chain. This invariant is a required review item.

4. **Interior mutability** — `encrypt`/`decrypt` are `&self`; the chains advance, so they need a lock
   (mirror `TransientNonceCounter`'s interior-mutable pattern) and must be lazily seeded on first use
   (the `PQNode`/orientation is only known when the `PostQuantumContainer` is passed in).

These are why a security review is mandatory before this path is enabled. The two crypto primitives
(commits a1070901, f6ec7099) are independently safe and unused until this plumbing lands.

## 5c. Resolved integration spec (Step 1 landed; Step 2/3 turnkey)

**Step 1 — LANDED.** `SecrecyMode::PerfectPipelined` (repr 2) added to `citadel_types`; routed to the
existing `Perfect` per-message-rekey send path at the one match site (`messaging.rs`) + the two
queue-drain `matches!` guards. ⇒ the variant is selectable and strictly as secure as `Perfect` (no
silent security change), with the symmetric-chain fast path landing in Step 2/3. Exercised end-to-end by
`test_messenger_racy` (the `PerfectPipelined` case rides the full messenger). Workspace builds clean;
only one exhaustive `match SecrecyMode` exists (the `== Perfect` sites are comparisons, not matches).

The following were verified against source while scoping Step 2 and resolve every open question in §5a/§5b:

1. **Chain seed root (both ends agree).** `PostQuantumContainer::get_shared_secret()` (`lib.rs:603`)
   returns the per-version ML-KEM shared secret — *identical on Alice and Bob* for a version, *fresh* on
   each KEM rekey. Compress to 32 bytes: `root = blake3::hash(ss)`; seed both chains
   `SymmetricChain::new(&root, dir)`. (The variable-length `ss` is hashed, not truncated, so KEM-length
   changes are irrelevant.)
2. **Direction by `PQNode` (not send/recv role).** Alice: send=`b"a2b"`, recv=`b"b2a"`. Bob:
   send=`b"b2a"`, recv=`b"a2b"`. So Alice's send chain ≡ Bob's recv chain. The node is the same one
   `get_encryption_key`/`get_decryption_key` already branch on (`lib.rs:508-524`).
3. **The pipelined seal/open MUST be a new `PostQuantumContainer` method, not entropy_bank-only.**
   `protect_packet_in_place` (`lib.rs:680`) owns three things the chain path must preserve byte-for-byte:
   the anti-replay **PID** (`anti_replay_attack.get_next_pid()`, appended *inside* the AEAD), the
   **header-AAD**, and the `InPlaceBuffer` windowing. Only the *key source* changes — from
   `get_encryption_key()` (fixed module) to `MK_i` via `per_message_aead::seal_in_place_with_key(alg,
   &MK_i, nonce, header_ad, payload_buf)`. So add `protect_packet_in_place_with_key(header_len, buf,
   nonce, &MK_i)` / `validate_packet_in_place_with_key(header, buf, nonce, &MK_i)` mirroring the
   originals with the key swapped. `anti_replay_attack` stays private; no encapsulation break.
4. **Chain state lives on `EntropyBank`, `#[serde(skip)]` + interior-mutable, lazily seeded.**
   `chains: Mutex<Option<DirectionChains{a2b, b2a}>>` (mirror `TransientNonceCounter`'s interior
   mutability; `encrypt`/`decrypt` are `&self`). Seed on first protect/validate from the passed-in
   `PostQuantumContainer` (the only place `ss`/`PQNode` are available). `#[serde(skip)]` is mandatory
   (constraint §5b-3): a restored bank has *no* chain and must not resume one.
5. **Wire trailer = sequential chain index `i`** (replacing the random `transient_id`) on the pipelined
   path only; nonce stays `BLAKE3(entropy, i)` (unique `MK_i` makes nonce reuse harmless regardless).
   Receiver reads `i`, calls `recv_key(i, MAX_SKIP)`. `MAX_SKIP ≈ 1024` (§7-3).
6. **Mode plumbing.** The bank/ratchet must know it is pipelined to take this path. Carry a serializable
   `pipelined: bool` (derived from `SecrecyMode`) on the bank set at construction; the *chains* (not the
   flag) are the serde-skip part. Fixed-key path (BestEffort, Perfect, Perfect n=1) is byte-unchanged.
7. **Rekey-on-restore invariant (§5b-3, REVIEW ITEM).** A `PerfectPipelined` session must force a fresh
   ratchet version (new KEM root → chain @ index 0) on any bank restore/reconnect — never resume a
   mid-version send chain (re-emitting `MK_i` reuses a forward-secure key).

**Step 2 — LANDED.** *Step 2a* (`citadel_pqcrypto`): `PostQuantumContainer::{protect,validate}
_packet_in_place_with_key` + `node()` — mirror the fixed-key methods byte-for-byte (ARA PID +
header-AAD + `InPlaceBuffer`), swapping only the key source to `MK_i` via `per_message_aead`. Tests:
round-trip across 16 keys, wrong-key + header-tamper rejection. *Step 2b* (`citadel_crypt`):
`EntropyBank::{protect_packet_in_place_pipelined, validate_packet_in_place_split_pipelined}` + the
`#[serde(skip)]` interior-mutable per-direction `DirectionChains`, lazily seeded from
`blake3(get_shared_secret())` with `PQNode`-chosen direction labels; chain-index trailer; `recv_key`
out-of-order up to `PIPELINED_MAX_SKIP=1024`. Tests (real ML-KEM pair + twin banks): in-order
round-trip, out-of-order-within-window, replay rejection, per-message key uniqueness (same plaintext →
distinct ciphertext), wrong-direction rejection. Fixed-key path byte-unchanged; serialize round-trip +
nonce tests still green. The crypto datapath of pipelined PFS is now complete + verified in isolation.

**Step 3 — LANDED** (`feat(proto): make SecrecyMode::Perfect pipelined end-to-end`). Maintainer
decision: the enum stays two-variant `{BestEffort, Perfect}` — `Perfect` now *means* pipelined (no
separate `PerfectPipelined`). Routing flag lives on `EntropyBank` (`pipelined`, serde(default));
`protect_packet`/`validate_packet_in_place_split` self-route, so the ~35 craft sites + validation are
untouched. Flag rides `ConstructorOpts` (`set_pipelined_all`), applied at every initial KEX from
`SecrecyMode::is_pipelined()` — c2s server-Bob (`validation.rs`, where banks are created + serialized to
Alice), c2s/p2p Alice (`session.rs`, `peer_cmd_packet.rs`), p2p Bob; rekeys propagate via
`get_next_constructor_opts`. Messaging `Perfect` arm now reuses BestEffort's pipelined send (FS from the
chain, post-compromise from opportunistic KEM rekey) — no new cadence state machine (the §7-1 N/T knob
is deferred; opportunistic rekey is the v1 cadence). MlKemHybrid forced fixed-key (§5a fallback).
`PROTOCOL_VERSION` 10→11.

**Measured (macro bench, AES-GCM, this laptop):** Perfect 1,325 → **23,444 msgs/s (~17.7×)**, p50
1136→814 µs, now ~83% of BestEffort; BestEffort unchanged. The cliff is closed.

**Still open:** the §6 **independent security review (REQUIRED before default-blessed)**; the
rekey-on-restore invariant (§5c-7) is documented (chains are serde-skip) but not yet *enforced* by a
restore-path rekey; `MonoRatchet` doesn't propagate the flag (StackedRatchet is the message ratchet);
the explicit N/T cadence knob (§7-1); DGX 20-core re-measure for a clean number.

## 5. Integration points (no code yet — for scoping)

- `citadel_crypt/src/ratchets/entropy_bank.rs` — replace the fixed-key AEAD seal/open with a
  per-message `MK_i` derived from the chain; keep the nonce trailer (reused as chain index `i`).
- `citadel_crypt/src/ratchets/stacked/ratchet.rs` + the `PostQuantumContainer` — seed `CK_send/CK_recv`
  from the KEM root at construction; source the AEAD key from the chain (per layer in the stack).
- `citadel_crypt/src/messaging.rs` — Perfect arm: local chain advance + immediate send; spawn the
  periodic KEM rekey (reuse `trigger_rekey_with_payload`), drop the per-message head-of-line queue.
- `citadel_crypt/src/ratchets/ratchet_manager.rs` — periodic (counter/timer) rekey trigger.
- `citadel_types` `SessionSecuritySettings` — add the rekey cadence (`n`/`t`) knob; bump
  `PROTOCOL_VERSION` (wire-breaking — old peers can't interop, by design).
- Receiver skipped-key cache lives with the per-direction chain state.

## 6. Validation & gates (before default-on)

- **Crypto unit tests:** chain derivation determinism (sender index `i` ⇒ same `MK_i` on receiver);
  out-of-order open via the cache + `MAX_SKIP` rejection; a **forward-secrecy property test** (given
  `CK[j]`, assert `MK_{<j}` is not derivable / earlier plaintext not recoverable); nonce uniqueness;
  `Zeroizing` drop coverage.
- **Messaging stress:** strict-ordering c2s+p2p in both modes; rekey-then-messaging; reconnection.
- **Throughput bench (DGX):** Perfect → near BestEffort (target ≥8–10× of 762/s); confirm BestEffort
  unchanged.
- **Correctness:** full NAT 16/16 matrix (transport unaffected but verify); file-transfer (the UDP
  out-of-order path exercises the skipped-key cache).
- **Security review:** independent review of the KDF construction (domain separation, BLAKE3
  `derive_key` usage), the FS argument, the cadence default, and the DoS bound — REQUIRED before merge.

## 7. Decisions (LOCKED — approved by maintainer)

1. **Cadence: both** — run the periodic ML-KEM rekey every `N` messages **or** every `T`, whichever
   first. Defaults: `N≈8`, `T≈250ms` (tunable). Forward secrecy is untouched; this only sets the
   post-compromise *healing* window.
2. **Keep `n=1` as a selectable maximum-security sub-mode** — reproduces today's exact per-message-KEM
   behavior; free (a config value).
3. **`MAX_SKIP` tied to the existing UDP/group window** (≈1024) so the out-of-order key-skip bound
   matches what the protocol already allows in flight; near-unused on the ordered TCP/QUIC path.
4. **Keep the existing `BLAKE3_keyed(entropy, i)` nonce derivation** initially (safe, already optimized;
   don't change two crypto things at once). Fixed-nonce simplification is a later micro-opt.
5. **New explicit `SecrecyMode` variant** (working name `PerfectPipelined`) — the relaxed
   post-compromise cadence is made explicit in the API/wire; `Perfect` keeps its exact current meaning
   (heal every message). No silent security change.
6. **One symmetric chain per security layer** of the `StackedRatchet` (mirrors the independent-layer
   design; layers stay decoupled).

Outstanding sign-off before merge/default-on: the concrete post-compromise window (`N`/`T`) and the
independent security review (§6 validation).

## 8. Alternative (smaller, non-security-altering) — for comparison

Keep the exact per-message-KEM guarantee; reduce the 3-leg handshake toward 1 RTT where the
simultaneous-rekey tie-break allows, and trim the messaging-layer per-rekey async-lock/serialization
overhead. ~20–35% improvement, stays RTT-bound (~1000 msgs/s ceiling). No security-model change, no
review needed. This is the fallback if the symmetric-chain change is deemed too invasive.
