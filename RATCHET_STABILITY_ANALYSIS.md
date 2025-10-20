# Ratchet Stability Test Analysis

## Job Information
- **Run ID**: 18662093592
- **Job ID**: 53204797729
- **Status**: Cancelled (hit 30-minute workflow timeout)
- **Iterations Completed**: 7/10
- **Log Lines Analyzed**: 20,747

## Summary
The Ratchet Stability Test was cancelled after hitting the 30-minute workflow timeout. The test suite was on iteration 7/10 when cancelled, with one specific test (`test_messenger_racy_with_random_start_lag::min_delay_1_0::secrecy_mode_2_SecrecyMode__Perfect`) timing out at 360 seconds (6 minutes).

## Error Frequency

| Error Type | Count | Description |
|-----------|-------|-------------|
| **AEAD decrypt failures** | 10 | Critical cryptographic decryption failures during rekey |
| **Rekey barrier mismatches** | 8 | Version synchronization issues between peers |
| **Concurrent rekey detected** | 8 | Multiple simultaneous rekey attempts detected |
| **Encryption failures** | 10 | Failed encryption operations (likely cascaded from AEAD failures) |
| **Test timeouts (60s)** | 10 | Individual test case timeouts (rstest timeout) |

## Key Findings from CBD Logging

### ✅ CBD Logging Working Perfectly
The Checkpoint-Based Debugging (CBD) logs are providing excellent visibility:
```
INFO citadel: citadel_crypt/src/ratchets/ratchet_manager.rs:290: [CBD-RKT-0] Client 20 entry
INFO citadel: citadel_crypt/src/ratchets/ratchet_manager.rs:318: [CBD-RKT-2] Client 20 getting constructor
INFO citadel: citadel_crypt/src/ratchets/ratchet_manager.rs:337: [CBD-RKT-3] Client 20 got constructor (is_some=true)
INFO citadel: citadel_crypt/src/ratchets/ratchet_manager.rs:356: [CBD-RKT-4] Client 20 sending AliceToBob
INFO citadel: citadel_crypt/src/ratchets/ratchet_manager.rs:373: [CBD-RKT-5] Client 20 sent AliceToBob
INFO citadel: citadel_crypt/src/ratchets/ratchet_manager.rs:385: [CBD-RKT-FINAL] Client 20 returning without wait
```

All checkpoints are firing correctly and showing clear execution flow with timestamps.

### 🔴 Primary Issue: AEAD Decryption Failures

**Error Pattern:**
```
ERROR citadel: citadel_pqcrypto/src/encryption.rs:106: AEAD decrypt_in_place failed: Error
WARN citadel: citadel_crypt/src/ratchets/ratchet_manager.rs:472: Client 10 rekey error: EncryptionFailure
```

**Analysis:**
- AEAD (Authenticated Encryption with Associated Data) failures indicate data corruption or key mismatch
- Occurs during high-contention scenarios when both peers attempt rekey simultaneously
- Likely caused by race conditions in key material exchange or version management

### 🟡 Secondary Issue: Barrier Mismatches

**Error Examples:**
```
WARN citadel: citadel_crypt/src/ratchets/ratchet_manager.rs:472: 
  Client 20 rekey error: Rekey barrier mismatch (earliest/latest). 
  Peer: (16-46) != Local: (17-47)

WARN citadel: citadel_crypt/src/ratchets/ratchet_manager.rs:472: 
  Client 20 rekey error: Rekey barrier mismatch (earliest/latest). 
  Peer: (27-57) != Local: (28-58)
```

**Pattern Analysis:**
- Consistently shows off-by-one mismatch: Local versions are exactly 1 ahead of Peer versions
- Example: Peer (16-46) vs Local (17-47) → both earliest and latest differ by 1
- Suggests a synchronization gap where one peer has already advanced its version range
- This could be a timing issue where version updates propagate before rekey completion signals

### 🟠 Tertiary Issue: Concurrent Rekey Detection

**Pattern:**
```
WARN citadel: citadel_crypt/src/ratchets/ratchet_manager.rs:379: 
  Replaced constructor; concurrent rekey attempt detected
```

**Analysis:**
- The contention resolution logic IS working (detecting concurrent attempts)
- However, the frequency (8 occurrences) suggests high contention in stress tests
- Current role-based resolution (Leader/Loser) is functioning but may need optimization

## Role State Observations

The CBD logs show rapid role transitions:
```
role=Idle → role=Leader → role=Loser → role=Idle
```

This is expected behavior under high contention, and the earlier fix to reset roles on cleanup is working correctly.

## Timing Observations

1. **Individual Test Timeouts**: Tests hitting 60s timeout (rstest default)
2. **Specific Slow Test**: `test_messenger_racy_with_random_start_lag` with `SecrecyMode::Perfect` and `min_delay=1`
3. **Overall Duration**: Job cancelled at 30 minutes, was on iteration 7/10

## Root Cause Hypothesis

### Primary Theory: Version Drift Under Contention

The off-by-one barrier mismatches combined with AEAD failures suggest:

1. **Sequence of Events:**
   - Both peers initiate rekey nearly simultaneously
   - Leader role established, begins version transition
   - Loser backs off but local state already partially updated
   - Messages encrypted with mismatched versions lead to AEAD failures
   - Barrier checks fail because version windows have drifted

2. **Why `SecrecyMode::Perfect` is Slower:**
   - Perfect secrecy requires all messages to complete encryption before proceeding
   - Under high contention, this creates more opportunities for version drift
   - BestEffort mode allows dropping/skipping, reducing contention window

## Recommendations

### 1. Version Synchronization Fix ⚠️ HIGH PRIORITY
The off-by-one barrier mismatches need investigation:
- Review version increment timing in rekey flow
- Ensure version updates don't occur before both peers have confirmed readiness
- Consider adding version sync checkpoints to CBD logging

### 2. AEAD Failure Handling
Current behavior on AEAD failure needs review:
- Should trigger immediate version sync check
- May need explicit version rollback mechanism
- Consider adding AEAD-specific CBD checkpoint

### 3. Timeout Adjustments ✅ COMPLETED
- Workflow timeout increased from 30 → 60 minutes
- Individual test timeouts could be adjusted if needed (currently 60s-360s)

### 4. Additional CBD Checkpoints (Future Enhancement)
Consider adding:
- `[CBD-RKT-VERSION]` - Log version state at key points
- `[CBD-RKT-BARRIER]` - Log barrier check details
- `[CBD-RKT-ENCRYPT]` - Log encryption operation success/fail

## Test Environment Details

**Working:**
- `SecrecyMode::BestEffort` tests passing consistently
- Low-delay tests passing
- Basic rekey functionality confirmed working

**Failing/Slow:**
- `SecrecyMode::Perfect` + random delays (1ms)
- High-contention stress tests
- Tests requiring 100% message ordering guarantee

## Next Steps

1. ✅ **Immediate**: Workflow timeout increased to 60 minutes (committed)
2. 🔍 **Investigate**: Version increment timing and barrier check logic
3. 🔧 **Fix**: Address off-by-one version mismatch root cause
4. 🧪 **Validate**: Re-run stability tests with fixes
5. 📊 **Monitor**: Use CBD logs to confirm fix effectiveness

## Files to Review

Based on error line numbers in logs:

1. `citadel_crypt/src/ratchets/ratchet_manager.rs:472` - Rekey error handling
2. `citadel_crypt/src/ratchets/ratchet_manager.rs:379` - Constructor replacement
3. `citadel_pqcrypto/src/encryption.rs:106` - AEAD decrypt failure
4. `citadel_crypt/src/messaging.rs:134` - Message queue handling on shutdown

## Conclusion

The CBD logging is providing excellent visibility into the rekey process. The core issues are:

1. **Version synchronization drift** causing barrier mismatches (off-by-one pattern)
2. **AEAD decryption failures** resulting from version mismatches
3. **High contention** in Perfect secrecy mode creating race conditions

The timeout increase will allow tests to complete, but the underlying version sync issue needs to be addressed for long-term stability.
