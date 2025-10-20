# Barrier Mismatch Analysis: What State is the Receiver In?

## Question
When a client receives an AliceToBob message that triggers a barrier mismatch (off-by-one error), what state is the receiving client in? Is it in the middle of trying to drop the oldest ratchet, or in some other state?

## Answer Summary

**The receiving client has already completed a previous rekey cycle and incremented its `latest_usable_version`.** When it receives the out-of-sync AliceToBob, it's in a **clean idle state** with a newer version than the sender expected.

## Detailed Timeline of Events

### The Race Condition Scenario

```
Time    Peer A (Sender)              Peer B (Receiver)
────────────────────────────────────────────────────────────
T0      Version N                    Version N
        Both idle

T1      trigger_rekey()              trigger_rekey()
        Gets constructor             Gets constructor
        Snapshot: v=N                Snapshot: v=N

T2      Sends AliceToBob(v=N)        Sends AliceToBob(v=N)
        [In flight] ───────>         [In flight] ───────>

T3      Receives B's AliceToBob      Receives A's AliceToBob
        Processes normally           Processes normally
        Calls update_sync_safe()     Calls update_sync_safe()
        
T4      Becomes Loser                Becomes Loser
        Waits for Truncate           Waits for Truncate
        or LoserCanFinish            or LoserCanFinish

T5      Receives LoserCanFinish      Receives LoserCanFinish
        Calls:                       Calls:
        post_alice_stage1...()       post_alice_stage1...()
        ├─ latest_usable_version     ├─ latest_usable_version
        │  increments N → N+1        │  increments N → N+1
        └─ Version now: N+1          └─ Version now: N+1

T6      Sends LeaderCanFinish        Sends LeaderCanFinish
        Role → Idle                  Role → Idle
        Rekey complete ✓             Rekey complete ✓
        VERSION: N+1                 VERSION: N+1

T7      (Later) Another trigger      (Later) Another trigger
        Gets new constructor         Gets new constructor  
        Snapshot: v=N+1              Snapshot: v=N+1
        Sends AliceToBob(v=N+1)      Sends AliceToBob(v=N+1)
                                     [In flight] ───────>

T8      ╔══════════════════════════════════════════════════╗
        ║ RACE: A's old AliceToBob(v=N) finally arrives  ║
        ║ while B is at version N+1!                      ║
        ╚══════════════════════════════════════════════════╝

T9                                   Receives OLD AliceToBob(v=N)
                                     ├─ Local state:
                                     │  - Role: Idle (clean)
                                     │  - State: Running
                                     │  - latest_usable_version: N+1
                                     │  - No rekey in progress
                                     │
                                     ├─ Incoming message claims:
                                     │  - peer_latest: N
                                     │  - peer_earliest: N-29
                                     │
                                     └─ Barrier check:
                                        if N != N+1 {  // FAIL!
                                          ❌ MISMATCH
                                        }
```

## Key Code Path: AliceToBob Reception

### Location: `ratchet_manager.rs` lines 528-608

```rust
Some(RatchetMessage::AliceToBob {
    payload,
    earliest_ratchet_version,  // Sender's earliest at send time
    latest_ratchet_version,     // Sender's latest at send time
    attached_payload,
    metadata: peer_metadata,
}) => {
    // Line 548-549: Fetch LOCAL current version
    let local_latest_ratchet_version =
        self.session_crypto_state.latest_usable_version();
    
    // Line 550-568: Get local earliest version
    let (local_earliest_ratchet_version, next_opts) = {
        let read = self.session_crypto_state.toolset().read();
        // ... fetch local earliest ...
        (read.get_oldest_ratchet_version(), ...)
    };

    // Line 572-579: THE BARRIER CHECK
    if latest_ratchet_version != local_latest_ratchet_version {
        // ❌ MISMATCH OCCURS HERE
        return Err(CryptError::RekeyUpdateError(
            format!(
                "Rekey barrier mismatch (earliest/latest). \
                 Peer: ({earliest_ratchet_version}-{latest_ratchet_version}) \
                 != Local: ({local_earliest_ratchet_version}-{local_latest_ratchet_version})"
            ),
        ));
    }
}
```

## When Version Gets Incremented

### Three locations where `latest_usable_version` increases:

1. **After Truncate** (line 804)
   ```rust
   Some(RatchetMessage::Truncate(version_to_truncate)) => {
       container.deregister_oldest_ratchet(version_to_truncate)?;
       container.post_alice_stage1_or_post_stage1_bob(); // ← Increments
       container.latest_usable_version()
   }
   ```

2. **After LoserCanFinish** (line 844)
   ```rust
   Some(RatchetMessage::LoserCanFinish) => {
       container.post_alice_stage1_or_post_stage1_bob(); // ← Increments
       container.latest_usable_version()
   }
   ```

3. **After LeaderCanFinish** (line 897)
   ```rust
   Some(RatchetMessage::LeaderCanFinish { version }) => {
       container.post_alice_stage1_or_post_stage1_bob(); // ← Increments
       latest_declared_version
   }
   ```

### The Increment Function: `post_alice_stage1_or_post_stage1_bob()`

**Location:** `endpoint_crypto_container.rs` line 283

```rust
pub fn post_alice_stage1_or_post_stage1_bob(&self) {
    let from = self.latest_usable_version();
    let to = from.wrapping_add(1);
    
    // Verify the new ratchet is actually available
    let toolset = self.toolset.read();
    if toolset.get_ratchet(to).is_none() {
        log::error!("Ratchet {} not found, not incrementing!", to);
        return;
    }
    
    log::trace!("Upgrading from {} to {}", from, to);
    let _ = self.latest_usable_version.fetch_add(1, Ordering::Release);
}
```

## What State is NOT Happening

### ❌ NOT in middle of dropping oldest ratchet
- `deregister_oldest_ratchet()` completes **before** version increment
- It's a synchronous operation under write lock
- Version increment only happens **after** truncation succeeds

### ❌ NOT in middle of another rekey
- Receiver has clean `role=Idle` state
- No constructor loaded in `self.constructor`
- `update_in_progress` toggle is **off**
- The rekey that caused the version increment has fully completed

### ❌ NOT waiting for messages
- Receiver is in "ready for next rekey" state
- Previous rekey finished all message exchanges
- Both peers sent `LeaderCanFinish` and completed

## What State IS Happening

### ✅ Clean post-rekey state
- **Role**: `Idle` (no active rekey)
- **State**: `Running` (ready for new rekeys)
- **Version**: `N+1` (successfully incremented)
- **Constructor**: `None` (no pending rekey)
- **Update toggle**: `Off` (ready for updates)

### ✅ Version window has shifted
- **Earliest**: May still be `N-29` or might be `N-28` (depends on truncation)
- **Latest**: Definitely `N+1` (just incremented)
- **Sender's view**: Still thinks receiver is at `N`

## The Core Problem: Version Snapshot Timing

### When AliceToBob version is captured:

```rust
// Line 328 in trigger_rekey_with_payload()
let latest_ratchet_version = self.session_crypto_state.latest_usable_version();
//                            ↑
//                            This is a POINT-IN-TIME snapshot
//                            It does NOT update if the peer's version changes later!
```

### The AliceToBob message is immutable:

```rust
// Line 362-368: Message is sent with snapshot values
self.sender.lock().await.send(RatchetMessage::AliceToBob {
    payload,
    earliest_ratchet_version,  // ← Captured at T1
    latest_ratchet_version,     // ← Captured at T1
    attached_payload,
    metadata,
})
```

### The problem:
1. **T1**: Sender captures `latest_ratchet_version = N`
2. **T2**: Sender sends AliceToBob with `v=N`
3. **T3-T6**: Network delay + Receiver completes its own rekey → `v=N+1`
4. **T9**: AliceToBob arrives, but receiver is now at `N+1`
5. **Barrier check**: `N != N+1` → **FAIL**

## Synchronization Gap

### The gap is in message ordering, not state consistency:

```
Sender's Perspective              Receiver's Perspective
─────────────────────              ─────────────────────
Send AliceToBob(v=N)               Complete rekey → v=N+1
  ↓ [Network delay]                  ↓ Clean idle state
  ↓                                  ↓ Ready for new rekey
  ↓                                  ↓
  └──> Arrives late ──────────────> ❌ Barrier: N != N+1
```

## Why Off-By-One?

### The pattern from logs:
```
Peer: (16-46) != Local: (17-47)
Peer: (27-57) != Local: (28-58)
```

This happens because:
1. **Both peers advance together** during normal rekey
2. **Receiver advances first** in race condition
3. **Sender's message reflects old state**
4. **Difference is exactly 1** because each rekey increments by 1

### The arithmetic:
```
Normal case:
  Both at v=16 → both advance to v=17 simultaneously ✓

Race case:
  Both at v=16
  Receiver completes rekey #1 → v=17
  Sender sends AliceToBob(v=16) from earlier rekey attempt
  Receiver receives stale message: 16 != 17 ❌
```

## Proposed Solutions

### Option 1: Version Range Tolerance (Recommended)
Accept messages within a small version window:

```rust
// Instead of exact match:
if latest_ratchet_version != local_latest_ratchet_version {
    return Err(...);
}

// Allow small backward window:
const VERSION_TOLERANCE: u32 = 2;
if latest_ratchet_version < local_latest_ratchet_version.saturating_sub(VERSION_TOLERANCE)
    || latest_ratchet_version > local_latest_ratchet_version {
    return Err(...);
}
```

**Rationale**: If receiver is at `N+1` and receives AliceToBob claiming `N`, it's likely a race. The receiver should recognize this and either:
- Silently accept it (safe because sender will catch up)
- Return a non-fatal "out of sync" signal

### Option 2: Version Sequence Numbers
Add sequence/epoch tracking:

```rust
RatchetMessage::AliceToBob {
    payload,
    earliest_ratchet_version,
    latest_ratchet_version,
    rekey_epoch: u64,  // ← New field
    ...
}
```

### Option 3: Monotonic Rekey IDs
Track each rekey attempt with a unique ID to detect duplicates/races.

## New CBD Checkpoints Added

With this commit, the following checkpoints now track version state:

1. **`[CBD-RKT-VERSION]` before sending AliceToBob**
   - Shows sender's version snapshot at send time

2. **`[CBD-RKT-VERSION]` when receiving AliceToBob**
   - Shows both peer's claimed version and receiver's actual version
   - Includes role and state

3. **`[CBD-RKT-BARRIER]` on mismatch**
   - Logs the exact mismatch with full context
   - Includes peer ranges, local ranges, role, state

4. **`[CBD-RKT-VERSION]` before/after Truncate**
   - Shows version changes during truncation

5. **`[CBD-RKT-VERSION]` before/after LoserCanFinish**
   - Tracks version increment for Loser role

6. **`[CBD-RKT-VERSION]` before/after LeaderCanFinish**
   - Tracks version increment for Leader role

## Expected Log Output on Mismatch

```
[CBD-RKT-VERSION] Client 20 local snapshot before AliceToBob: earliest=16, latest=16, role=Idle, state=Running
[CBD-RKT-VERSION] Client 10 recv AliceToBob: peer_earliest=16, peer_latest=16, local_earliest=17, local_latest=17, role=Idle, state=Running
[CBD-RKT-BARRIER] Client 10 mismatch: peer=(16-46), local=(17-47), role=Idle, state=Running
WARN citadel: Client 10 rekey error: Rekey barrier mismatch (earliest/latest). Peer: (16-46) != Local: (17-47)
```

This will clearly show:
- ✅ Sender was at v=16 when it sent the message
- ✅ Receiver is at v=17 when it receives the message
- ✅ Both are in Idle state (not mid-rekey)
- ✅ The version drift happened between send and receive

## Conclusion

The receiving client is **NOT** in the middle of any operation when it receives the out-of-sync AliceToBob. It's in a **clean idle state** with a **completed rekey** and an **incremented version**.

The barrier mismatch is a **message ordering issue**, not a state consistency issue. The receiver has legitimately advanced past the version the sender thought it was at when the AliceToBob was created.

The solution needs to account for this legitimate race condition in high-contention scenarios where both peers are rapidly completing rekeys.
