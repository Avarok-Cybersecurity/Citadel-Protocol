# Ratchet Manager Race Condition Fix Log

This document tracks all fixes applied to resolve race conditions and deadlocks in the ratchet manager during simultaneous rekey scenarios.

**Purpose**: Maintain a chronological record of problems discovered, solutions applied, and pipeline outcomes to inform future debugging.

---

## Fix #1: Listener Registration Race

**Commit**: `99e9e4d` - Register listener before sending AliceToBob  
**Date**: 2025-10-20  
**Pipeline**: ✅ **PASSED**

### Problem
When `wait_for_completion=true`, the listener was registered AFTER sending `AliceToBob`. If the rekey completed very quickly in the background loop, it could notify before we registered the listener, causing `trigger_rekey(wait=true)` to timeout waiting for a notification that already happened.

### Solution
Moved listener registration from line 446 to line 403 (before send). Register the listener BEFORE sending `AliceToBob` to ensure we're subscribed to notifications before the rekey can complete.

### Code Changes
- File: `citadel_crypt/src/ratchets/ratchet_manager.rs`
- Lines: Moved listener registration before `AliceToBob` send
- Restructured code to handle `wait_for_completion=false` separately

### Outcome
✅ Pipeline passed - fixed listener notification timing issue

---

## Fix #2: Peer Connection Cancellation

**Commit**: `ca83911` - Fix peer connection callback cancellation  
**Date**: 2025-10-20  
**Pipeline**: ✅ **PASSED**  
**Related Commit**: `844769b` (actual fix)

### Problem
Using `try_join!` in `PeerConnectionKernel` caused premature cancellation of user callbacks. When one branch completed, `try_join!` would cancel the other branch immediately, preventing proper completion.

**Evidence from logs**:
- Connection counts incomplete
- Callbacks terminated mid-execution
- Flaky failures in P2P connection tests

### Solution
Changed from `try_join!` to `join!` to ensure both branches complete regardless of individual completion times. This allows user callbacks to finish naturally without premature cancellation.

### Code Changes
- File: `citadel_sdk/src/prelude/peer_connection.rs`
- Changed: `try_join!` → `join!` in connection kernel

### Tests Fixed
- `peer_to_peer_connect_transient::case_3`
- `peer_to_peer_connect_transient::case_4`
- Other P2P connection tests

### Outcome
✅ Pipeline passed - fixed 6 flaky test instances

---

## Fix #3: C2S Shutdown Panic

**Commit**: `690a3a6` - Gracefully handle connection closure during shutdown  
**Date**: 2025-10-21  
**Pipeline**: ✅ **PASSED**

### Problem
`get_preferred_stream()` panicked with "The C2S virtual connection should always exist" when C2S was dropped before P2P cleanup completed.

**Shutdown sequence**:
1. Rekey shutdown triggered
2. C2S connection dropped
3. P2P cleanup tries to access C2S for fallback
4. Panic: `expect()` on `None` value

### Solution
Changed `get_preferred_stream()` to return `Option<StreamKey>` instead of panicking. Callers check for `None` and handle gracefully (log warning, skip operation, or use alternative).

### Code Changes
- File: `citadel_sdk/src/prefabs/client/single_connection.rs`
- Changed: `expect()` → return `None`
- Updated all callers to handle `Option`

### Tests Fixed
- `stress_test_p2p_messaging` (multiple encryption algorithms)
- Test panics on first try, timeouts on retry (120s)

### Outcome
✅ Pipeline passed - eliminated shutdown panics

---

## Fix #4: Empty Commit for Analysis

**Commit**: `28aab81` - Trigger CI for flaky test analysis  
**Date**: 2025-10-26  
**Pipeline**: ❌ **FAILED** - 3/3 failures on `min_delay_1_0`

### Problem
This was an empty commit to trigger CI and analyze a new critical deadlock discovered in `test_ratchet_manager_racy_with_random_start_lag::min_delay_1_0`.

**Failure Details**:
- Test failed 3/3 retry attempts
- 30-second timeout/deadlock on macOS
- Blocked entire CI pipeline

### Outcome
❌ Pipeline failed - exposed critical deadlock (see Fix #5)

---

## Fix #5: Simultaneous Rekey Deadlock (First Scenario)

**Commit**: `f7dd436` - Resolve ratchet manager deadlock in simultaneous rekey  
**Date**: 2025-10-27  
**Pipeline**: ❌ **FAILED** - Different deadlock scenario exposed

### Problem Discovered
The deadlock occurred when both clients simultaneously initiated rekey:

1. Both send `AliceToBob` messages
2. Leader processes `BobToAlice`, sends `Truncate`
3. Loser processes `Truncate`, sends `LeaderCanFinish`, completes
4. **Leader receives stale `AliceToBob`** from Loser's initial attempt
5. Leader tries to process it but has no constructor → **deadlock**
6. 30-second timeout triggers panic

**Key Insight**: In simultaneous rekey scenarios, the Leader can receive a stale `AliceToBob` from the Loser's initial rekey attempt that was superseded. The code didn't handle this case—it expected to have a constructor but it had already been cleaned up.

### Solution Applied
When Leader receives `AliceToBob` but has no constructor for it, treat it as a stale message from a superseded simultaneous rekey attempt and skip it (continue waiting for `LeaderCanFinish`).

### Code Changes
- File: `citadel_crypt/src/ratchets/ratchet_manager.rs`
- Lines: 665-686 (new stale message detection logic)
- Added check: If Leader role && no constructor → skip as stale

```rust
if self.role() == RekeyRole::Leader {
    let has_constructor = self.constructors.lock().contains_key(&peer_metadata.next_version);
    if !has_constructor {
        stale_message_count += 1;
        log::debug!("ignoring stale AliceToBob...");
        continue; // Skip this stale message
    }
}
```

### Tests Fixed (Locally)
- ✅ `min_delay_1_0`: 5/5 passes
- ✅ `min_delay_2_1`: 5/5 passes
- ✅ All 7 ratchet_manager tests passed

### Outcome
❌ **Pipeline still failed** - Fix was incomplete, exposed second deadlock scenario (see Fix #6)

**Why it failed**: The fix addressed Leader receiving stale messages, but didn't address:
1. Loser retaining unused Alice constructors
2. Overly aggressive Idle role stale message detection

---

## Fix #6: Constructor Cleanup Deadlock (Second Scenario)

**Commit**: `5fb1afc` - Resolve second deadlock by cleaning up unused constructors  
**Date**: 2025-10-27  
**Pipeline**: ⏳ **PENDING** (pushed, awaiting results)

### Problem Discovered
After Fix #5 was applied, a NEW deadlock scenario appeared in CI:

**Causal Chain**:
1. During simultaneous rekey, Loser creates Alice constructor for version N+1
2. Leader's rekey wins, Loser completes via `Truncate` or `LoserCanFinish`
3. **Loser's unused Alice constructor is RETAINED** (because `version > completed_version`)
4. After both go Idle, Loser initiates new rekey using **stale constructor**
5. Leader (now Idle) receives `AliceToBob`, has no constructor
6. Fix #5's logic was TOO AGGRESSIVE: skipped legitimate new rekeys in Idle role
7. **Deadlock**: Loser waits for response, Leader skips and waits for next message

**Root Cause Analysis**:

Looking at line 1112-1115 in `ratchet_manager.rs`:
```rust
self.constructors.lock().retain(|&version, _| version > completed_version);
```

This retains constructors for versions GREATER than completed version. So if we complete version 15, constructor for version 16 is kept. This is intentional (to support concurrent rekey attempts), but causes problems when the version 16 constructor was from a SUPERSEDED simultaneous rekey.

**CI Logs Evidence**:
```
Client 20: recv AliceToBob: peer_earliest=11, peer_latest=15, local_earliest=11, local_latest=15, role=Idle
ERROR: Rekey round timed out after 30 seconds
```

Client 20 completed rekey (version 15), went Idle, then received Client 10's `AliceToBob`. Versions match (both at 15), so it passes barrier check. But Client 20 has no constructor for version 16. Fix #5 skipped it thinking it was stale, but it was actually a NEW legitimate rekey attempt!

### Solution Applied
**Two-part fix**:

#### Part 1: Clean up unused constructors when completing as Loser

Added constructor cleanup in TWO places:

**Location 1**: `Truncate` message handler (lines 915-962)
```rust
// After processing truncate, before sending LeaderCanFinish:
let unused_constructor_version = latest_version + 1;
if let Some(_removed) = self.constructors.lock().remove(&unused_constructor_version) {
    log::debug!("removed unused Alice constructor for version {}", unused_constructor_version);
}
```

**Location 2**: `LoserCanFinish` message handler (lines 964-1013)
```rust
// After processing LoserCanFinish, before sending LeaderCanFinish:
let unused_constructor_version = latest_version + 1;
if let Some(_removed) = self.constructors.lock().remove(&unused_constructor_version) {
    log::debug!("removed unused Alice constructor for version {}", unused_constructor_version);
}
```

**Why this works**: When Loser completes (whether via Truncate or LoserCanFinish), it explicitly removes the Alice constructor that was created during simultaneous rekey but never used. This prevents the stale constructor from being used in future rekey attempts.

#### Part 2: Refine stale message detection logic

Changed from:
```rust
if !has_constructor && (self.role() == RekeyRole::Leader || self.role() == RekeyRole::Idle)
```

To:
```rust
if self.role() == RekeyRole::Leader {
    let has_constructor = ...;
    if !has_constructor {
        // Skip stale message
    }
}
// If Idle: don't skip, process normally as new rekey
```

**Why this works**: 
- **Leader role**: No constructor means stale message from superseded simultaneous rekey → skip it
- **Idle role**: No constructor is NORMAL! Peer is initiating a NEW rekey, and we act as Bob → process it

### Code Changes
- File: `citadel_crypt/src/ratchets/ratchet_manager.rs`
- Lines 953-961: Added constructor cleanup in Truncate handler
- Lines 1013-1019: Added constructor cleanup in LoserCanFinish handler  
- Lines 665-686: Refined stale message detection (Leader only, not Idle)

### Tests Fixed (Locally)
- ✅ `min_delay_1_0`: 5/5 passes
- ✅ `min_delay_2_1`: 5/5 passes
- ✅ **10/10 total passes** (both tests, 5 runs each)
- ✅ All tests complete in <1s (vs 30s timeout)

### Key Insights
1. **Constructor retention policy** (`version > completed_version`) is correct for concurrent rekeys but needs explicit cleanup for superseded simultaneous rekeys
2. **Role-based stale detection** is critical: Leader vs Idle have different semantics
3. **Missing constructor** means different things in different roles:
   - Leader: Stale message from cancelled rekey
   - Idle: Normal - peer initiating new rekey
4. **Two cleanup paths** needed: Both Truncate and LoserCanFinish need constructor removal

### Outcome
⏳ Pending CI results - expecting full pipeline pass

---

## Lessons Learned

### Pattern Recognition
1. **Simultaneous operations create complex message orderings**: Even with Leader/Loser roles, messages from cancelled operations can arrive out of order
2. **Constructor lifecycle is critical**: Must match constructor creation with explicit cleanup in all completion paths
3. **Role semantics matter**: Same situation (no constructor) means different things in different roles

### Debugging Techniques
1. **Log tracing with checkpoints**: CBD-RKT markers made it possible to trace exact execution flow
2. **Version tracking**: Logging earliest/latest versions at each step revealed synchronization issues
3. **Timeout as symptom**: 30s timeout consistently pointed to deadlock, not performance
4. **Local reproduction**: Minimal delay tests (`min_delay_1_0`) reliably triggered races

### Code Quality
1. **Explicit cleanup > implicit cleanup**: Relying on version-based retention wasn't enough
2. **Early validation**: Check role/state before processing to catch invalid scenarios
3. **Stale message detection**: Critical for async protocols with in-flight messages
4. **Comprehensive testing**: Fixed one deadlock, exposed another - iterative process

---

## Future Monitoring

### What to Watch
- ✅ All ratchet manager tests passing consistently
- ✅ No 30-second timeouts in any test
- ✅ No `[CBD-RKT-STALE]` log spam (1-2 is normal, dozens is concerning)
- ✅ All platforms stable (macos/ubuntu/windows)

### Red Flags
- ❌ New timeouts in different rekey tests
- ❌ Version mismatch errors increasing
- ❌ `MAX_STALE_MESSAGES` limit being hit
- ❌ Flaky tests reappearing on specific platforms
- ❌ Constructor map growing unbounded

### Potential Future Improvements
1. **Explicit cancellation messages**: Send "cancel" when Leader wins, acknowledge on Loser side
2. **Sequence numbers**: Add monotonic sequence numbers to rekey rounds for robust stale detection
3. **State machine documentation**: Document all states and valid transitions
4. **Invariant checks**: Add assertions between states to catch bugs earlier
5. **Constructor lifecycle tracing**: Add explicit logging for constructor create/remove/use

---

## Quick Reference

### All Commits in Order
1. `99e9e4d` - Listener registration race (PASSED)
2. `ca83911` / `844769b` - Peer connection cancellation (PASSED)
3. `690a3a6` - C2S shutdown panic (PASSED)
4. `28aab81` - Empty commit for analysis (FAILED - exposed deadlock)
5. `f7dd436` - First deadlock fix (FAILED - incomplete)
6. `5fb1afc` - Second deadlock fix (PENDING)

### Test History
- `min_delay_1_0`: Initially 0/3 → After Fix #5: 5/5 local → After Fix #6: 5/5 local
- `min_delay_2_1`: Initially 0/3 → After Fix #5: 5/5 local → After Fix #6: 5/5 local

### Key Files Modified
- `citadel_crypt/src/ratchets/ratchet_manager.rs` (all fixes)
- `citadel_sdk/src/prelude/peer_connection.rs` (Fix #2)
- `citadel_sdk/src/prefabs/client/single_connection.rs` (Fix #3)

---

**Last Updated**: 2025-10-27  
**Status**: Awaiting CI results for Fix #6  
**Next Steps**: Monitor pipeline, append results when available
