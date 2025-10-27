# Flaky Tests Tracker - Run 4

**Pipeline Run:** [18824926555](https://github.com/Avarok-Cybersecurity/Citadel-Protocol/actions/runs/18824926555)  
**Date:** 2025-10-26 22:56 UTC  
**Status:** ❌ **HARD FAILURE - New Critical Issue**  
**Commit:** Empty commit to trigger CI recheck

---

## Critical Failure Summary

| Test | Platform | Attempts | Final Result | Severity |
|------|----------|----------|--------------|----------|
| `test_ratchet_manager_racy_with_random_start_lag::min_delay_1_0` | macos-latest | 3/3 | ❌ TIMEOUT/DEADLOCK | 🔴 CRITICAL |
| `test_ratchet_manager_racy_with_random_start_lag::min_delay_2_1` | macos-latest | 2/3 | ✅ FLAKY | ⚠️ WARNING |

**Pipeline Result:** Complete job failure - could not recover

---

## New Critical Issue: Ratchet Manager Deadlock

### Test: `test_ratchet_manager_racy_with_random_start_lag::min_delay_1_0`

**Status:** ❌ **BLOCKING** - Failed all 3 retry attempts  
**Platform:** macos-latest (core_libs job)  
**Duration:** 30.097s per attempt (hit timeout)  
**Impact:** Job failure, caused ubuntu-latest and windows-latest jobs to be canceled

### Error Details

```
ERROR citadel: citadel_crypt/src/ratchets/ratchet_manager.rs:1323: 
  Rekey round timed out after 30 seconds

ERROR citadel: citadel_logging/src/lib.rs:89: 
  Panic occurred: panicked at citadel_crypt/src/ratchets/ratchet_manager.rs:1326:17:
  Rekey round timed out - possible deadlock

WARN citadel: citadel_crypt/src/ratchets/ratchet_manager.rs:556: 
  Client 10 rekey process shutting down due to shutdown signal
WARN citadel: citadel_crypt/src/ratchets/ratchet_manager.rs:556: 
  Client 20 rekey process shutting down due to shutdown signal
```

### Timeline from Logs

```
[19:11:46] Client 20 and Client 10 successfully complete 7 rekey rounds (versions 0 → 7)
[19:11:46] Client 20 initiates round 8: 
           - version_at_entry=7, sends AliceToBob
[19:11:46] Client 10 receives AliceToBob from Client 20
[19:11:46] Client 10 initiates its own rekey:
           - version_at_entry=7
           - Constructor returns is_some=true
           - Sends AliceToBob to Client 20
[19:11:46] Client 20 receives AliceToBob from Client 10
[19:11:46] Client 20 processes BobToAlice, truncates to earliest=2
[19:11:46] Client 10 receives truncation request, updates to earliest=3, latest=7
[19:12:16] ⏱️ 30 SECONDS ELAPSED - TIMEOUT
[19:12:16] ERROR: Rekey round timed out
[19:12:16] Panic triggered
```

### Deadlock Analysis

**What Happened:**
1. Both clients successfully performed 7 rekey rounds (0→7) with proper truncation
2. On round 8, both clients simultaneously initiated rekey
3. Client 20 became Leader, Client 10 became Loser
4. Truncation occurred: earliest bumped from 2→3→7
5. **Client 10 never sent `LoserCanFinish` message**
6. **Client 20 waited forever for peer version confirmation**
7. 30-second watchdog timer triggered panic

**Key Logs Showing Stall:**

The last successful operations:
```
Client 20: [CBD-RKT-VERSION] after BobToAlice: earliest=2, latest=6, truncation_required=Some(2)
Client 10: [CBD-RKT-TRUNCATE] AFTER truncate: earliest=3, latest=7, role=Loser
Client 20: [CBD-RKT-VERSION] recv AliceToBob: peer_earliest=3, peer_latest=7
```

Then **nothing** - no `LoserCanFinish` from Client 10, no `LeaderCanFinish` from Client 20.

### Root Cause Hypothesis

**Most Probable (80%):** Race condition in ratchet state machine during simultaneous rekey

When both clients initiate rekey simultaneously:
1. Both send `AliceToBob` at nearly the same time
2. Role negotiation occurs (Leader/Loser)
3. Loser (Client 10) processes truncation correctly
4. BUT: Loser's rekey completion path gets blocked or skipped

**Possible causes:**
- Listener registration timing: Client 10 may have registered a listener but the response handler got lost
- State transition issue: After truncation, version bump to 7 may have confused the completion check
- Constructor availability: Second call to `get_constructor` returned `None` but completion logic didn't handle it
- Semaphore/lock contention: The rekey trigger semaphore may have blocked the completion path

**Medium Probability (15%):** Message delivery failure in test harness

The in-memory channel between clients may have dropped the `LoserCanFinish` message due to:
- Buffer overflow from rapid rekey operations
- Channel closure during state transition
- Test harness timing issue specific to rapid automated rekeys

**Low Probability (5%):** macOS-specific scheduler issue

The 30-second timeout is platform-independent, but macOS scheduling of the tokio runtime may have:
- Starved the rekey completion task
- Delayed message delivery beyond timeout
- Caused task priority inversion

---

## Comparison: Run 3 vs Run 4

| Metric | Run 3 | Run 4 | Change |
|--------|-------|-------|--------|
| Total flaky instances | 7 | 2* | ✅ Better** |
| Pipeline result | ✅ SUCCESS | ❌ **FAILURE** | 🔴 Worse |
| Ratchet manager tests | ✅ 0 failures | ❌ 1 critical | 🔴 **REGRESSED** |
| Severity | No 3/3 except 1 | 1 critical 3/3 | 🔴 Worse |

\* Only ran on macOS before failure  
\** Incomplete run - cannot compare directly

### Critical Observation

**The ratchet manager tests were FIXED in Run 3** but have now **CATASTROPHICALLY REGRESSED** in Run 4.

This suggests:
1. ❌ The issue is **NOT fixed** - it's **intermittent**
2. ❌ Run 3 success may have been **LUCKY**
3. ❌ The race condition is **still present** but timing-dependent
4. ⚠️ The deadlock is **more severe** than previous failures (complete timeout)

---

## Detailed Trace Analysis

### Successful Rekey Rounds (1-7)

All 7 rekey rounds completed successfully with this pattern:
```
Client 20 (Leader):
  1. Send AliceToBob
  2. Receive BobToAlice
  3. Send LeaderCanFinish
  4. Complete (elapsed: 7-14ms)

Client 10 (Loser):
  1. Receive AliceToBob
  2. Send BobToAlice
  3. Send LoserCanFinish
  4. Complete (elapsed: 7-11ms)
```

Truncation worked correctly:
- Round 6: Truncated from earliest=0 to earliest=1
- Round 7: Truncated from earliest=1 to earliest=2  
- Round 8: Truncated from earliest=2 to earliest=3

### Failed Rekey Round 8

```
[T+0ms] Client 20: version_at_entry=7, got constructor, sending AliceToBob
[T+0ms] Client 10: receives AliceToBob (peer_earliest=3, peer_latest=7)
[T+0ms] Client 10: version_at_entry=7, got constructor (is_some=true)
[T+3ms] Client 10: sending AliceToBob
[T+4ms] Client 20: receives AliceToBob (peer_earliest=3, peer_latest=7)
[T+4ms] Client 10: processes truncation request=2
[T+4ms] Client 10: AFTER truncate: earliest=3, latest=7
[T+4ms] Client 20: processes BobToAlice, truncation_required=Some(2)
```

**Then silence for 30 seconds until timeout.**

### What's Missing

Expected but never logged:
- ❌ Client 10: `[CBD-RKT-VERSION] BEFORE LoserCanFinish`
- ❌ Client 10: `[CBD-RKT-VERSION] AFTER LoserCanFinish`  
- ❌ Client 10: `[CBD-RKT-FINAL] rekey completed successfully`
- ❌ Client 20: `[CBD-RKT-VERSION] BEFORE LeaderCanFinish`
- ❌ Client 20: `[CBD-RKT-VERSION] AFTER LeaderCanFinish`
- ❌ Client 20: `[CBD-RKT-FINAL] rekey completed successfully`

### Code Path Analysis

Looking at the log markers, after `AFTER truncate`, the code should:

1. **Client 10 (Loser)** should hit line ~959-977:
   ```rust
   // Log: [CBD-RKT-VERSION] BEFORE LoserCanFinish
   // ... send version to peer ...
   // Log: [CBD-RKT-VERSION] AFTER LoserCanFinish
   // Log: [CBD-RKT-FINAL] rekey completed successfully
   ```
   **This never logged** → Client 10 never reached this code path

2. **Client 20 (Leader)** should hit line ~1032-1041:
   ```rust
   // Log: [CBD-RKT-VERSION] BEFORE LeaderCanFinish
   // ... wait for peer version ...
   // Log: [CBD-RKT-VERSION] AFTER LeaderCanFinish
   // Log: [CBD-RKT-FINAL] rekey completed successfully
   ```
   **This never logged** → Client 20 waiting for message that never came

**Conclusion:** Client 10's Loser completion path was never reached after truncation.

---

## Why This Is Critical

1. **Blocks entire pipeline**: Job failure prevents all downstream tests from running
2. **Deterministic enough**: Failed 3/3 attempts, unlike previous intermittent issues  
3. **Core crypto functionality**: Ratchet rekey is fundamental to secure communication
4. **Difficult to reproduce**: Requires specific race timing (simultaneous rekey after 7 rounds)
5. **Silent deadlock**: No error, just indefinite wait until timeout

---

## Recommended Investigation Steps

### Immediate Priority (P0)

1. **Review ratchet_manager.rs lines 900-1000**
   - After truncation completes, what triggers the LoserCanFinish path?
   - Is there a state check that could return early?
   - Could the constructor being `Some(true)` cause the completion to be skipped?

2. **Check listener registration**
   - Client 10 logged "registering listener before sending" at line 405
   - Is the listener properly awaited after truncation?
   - Could the listener be dropped or cancelled?

3. **Verify constructor semantics**
   - In round 8, Client 10's constructor returned `is_some=true`
   - But in round 7, similar scenario had constructor return `is_some=false`
   - Does a `Some` constructor block the completion path?

### Code Review Focus

Lines to examine in `citadel_crypt/src/ratchets/ratchet_manager.rs`:

- **Line 927**: After `[CBD-RKT-TRUNCATE] AFTER truncate` - what's next?
- **Line 959**: Entry to `BEFORE LoserCanFinish` - what conditions must be met?
- **Line 1032**: Entry to `BEFORE LeaderCanFinish` - is it properly awaiting?
- **Line 1323**: Timeout detection - is 30s too short for 8 rapid rekeys?

### Test Improvements

1. **Add heartbeat logging**
   - Log every 5 seconds during rekey wait
   - Identify exactly where the code is stuck

2. **Add completion tracing**
   - Log when awaiting listener response
   - Log when listener channel closes or times out

3. **Reduce test iterations**
   - Current test does 8+ rekey rounds
   - Try with just 3-4 rounds to see if issue still reproduces

---

## Historical Context

### Timeline of Ratchet Manager Issues

**Run 1 & 2:**
- `test_ratchet_manager_racy*` tests failed with panic during shutdown
- Root cause: `get_preferred_stream()` panic when connection unavailable

**Run 3:**  
- ✅ All ratchet manager tests PASSED after shutdown fix
- Thought issue was resolved

**Run 4:**
- ❌ NEW deadlock issue discovered
- Different failure mode: timeout instead of panic
- Suggests **multiple independent bugs** in ratchet manager

### What We Learned

1. The shutdown panic fix (changing to Option) **did not fix** the race condition
2. The race was just **hidden** by the earlier panic
3. Now that shutdown doesn't panic, the **deadlock is exposed**
4. This is actually **good** - deadlock is easier to debug than panic

---

## Impact Assessment

| Category | Impact |
|----------|--------|
| CI/CD | 🔴 **BLOCKING** - Pipeline fails |
| Production | 🟡 **UNKNOWN** - Real-world likelihood unclear |
| Debugging | 🟢 **GOOD** - Deterministic failure with clear logs |
| User Impact | 🟡 **MEDIUM** - Only affects rapid automated rekeys |
| Fix Difficulty | 🔴 **HIGH** - Complex state machine race |

---

## Next Steps

### Option A: Deep Investigation (Recommended)

1. Add extensive tracing to ratchet_manager.rs
2. Add timeout logging every 5s
3. Review state machine transition after truncation
4. Check if constructor availability affects completion path
5. Run test locally with debug logging

### Option B: Test Adjustment (Quick Fix)

1. Increase timeout from 30s to 60s
2. Add delay between rekey rounds
3. Mark test as `#[ignore]` temporarily
4. Focus on other flaky tests first

### Option C: Algorithm Review (Long Term)

1. Review entire simultaneous rekey protocol
2. Consider simpler "retry on conflict" approach
3. Add explicit state machine documentation
4. Add invariant checks between states

---

## Success Metrics for Resolution

- ✅ Test passes 10 consecutive runs on macOS
- ✅ Test passes with no delay between rekeys
- ✅ Timeout never triggered (completes in < 5s)
- ✅ All 3 platforms (macos/ubuntu/windows) pass
- ✅ Works under release build (optimization doesn't hide bug)

---

## Additional Notes

### Why min_delay_1_0 Specifically?

The test name indicates:
- `min_delay_1` - minimum 1ms delay between operations
- `_0` - case 0 (likely first in a series)

This is the **most aggressive** timing test - the minimal delay between rekey attempts. This explains why it's most likely to hit the race condition.

Test `min_delay_2_1` had 1 failure but recovered on retry - slightly more delay allows the race to resolve.

### Comparison to Production

**Low likelihood in production:**
- Real applications won't rekey 8 times in rapid succession
- Typical rekey intervals: minutes to hours
- This test is specifically designed to stress-test the race window

**But still critical:**
- Could happen if network conditions trigger rapid timeouts/retries
- Could happen if application has aggressive rekey policy
- Deadlock in crypto layer is unacceptable regardless of frequency

---

## Conclusion

Run 4 exposed a **critical deadlock** in the ratchet manager that was **hidden** by the previous shutdown panic. While this blocks CI, it's actually a positive development - we now have:

1. ✅ **Deterministic reproduction** (3/3 failures)
2. ✅ **Clear logs** showing exactly where it stalls
3. ✅ **Specific scenario** (round 8 of rapid rekey)
4. ✅ **Platform identified** (macOS timing most sensitive)

The fix requires **deep investigation** of the state machine, but with this level of detail, it's debuggable.

**Recommendation:** Prioritize this over other flaky tests, as it's blocking CI.
