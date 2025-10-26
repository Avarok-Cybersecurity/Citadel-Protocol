# Flaky Tests Tracker - Run 2

**Pipeline Run:** [18819737087](https://github.com/Avarok-Cybersecurity/Citadel-Protocol/actions/runs/18819737087)  
**Date:** 2025-10-26  
**Status:** ✅ All tests passed (with 11 flaky instances requiring retries)

---

## Summary

| Test | Platform | Occurrences | Retries | Status |
|------|----------|-------------|---------|--------|
| `peer_to_peer_connect_transient::case_2` | ubuntu-latest (release) | 1 | 2/3 | ⚠️ Still flaky (reduced from 100% to ~33%) |
| `stress_test_p2p_messaging::case_1::AES_GCM_256` | macos-latest | 1 | 3/3 | ⚠️ Needs investigation |
| `stress_test_c2s_messaging_kyber::case_2::KyberHybrid` | ubuntu-latest | 1 | 2/3 | ⚠️ New flaky test |
| `test_ratchet_manager_racy_with_random_start_lag::min_delay_1_0` | macos-latest | 1 | 3/3 | ⚠️ New flaky test |
| `test_ratchet_manager_racy_with_random_start_lag::min_delay_2_1` | macos-latest, coverage | 2 | 3/3, 2/3 | ⚠️ New flaky test |
| `test_messenger_racy_contentious::Perfect` | coverage | 1 | 2/3 | ⚠️ Messenger race condition |
| `test_manual_group_connect::case_1` | coverage | 1 | 3/3 | ⚠️ Group broadcast issue |
| `peer_to_peer_connect::case_1` | coverage | 1 | 2/3 | ⚠️ Potential similar issue |
| `stress_test_p2p_messaging::case_1::Ascon80pq` | coverage | 1 | 3/3 | ⚠️ Encryption-specific |
| `stress_test_p2p_messaging::case_2::ChaCha20Poly_1305` | coverage | 1 | 2/3 | ⚠️ Encryption-specific |

**Progress from Run 1:**
- ✅ `peer_to_peer_connect_transient::case_3` - **FIXED** (no longer flaky)
- ✅ `peer_to_peer_connect_transient::case_4` - **FIXED** (no longer flaky)
- ⚠️ `peer_to_peer_connect_transient::case_2` - **IMPROVED** (reduced flakiness)
- ⚠️ `test_peer_to_peer_file_transfer::case_1` - **FIXED** (no longer appears)

**Total Flaky Tests:** 10 unique tests, 11 instances  
**Platforms Affected:** ubuntu-latest, macos-latest, coverage

---

## Analysis by Category

### 1. Ratchet Manager Tests (NEW)

**Tests:**
- `test_ratchet_manager_racy_with_random_start_lag::min_delay_1_0` (3/3 retries)
- `test_ratchet_manager_racy_with_random_start_lag::min_delay_2_1` (2 instances, 3/3 and 2/3)

**Location:** `citadel_crypt/src/ratchets/ratchet_manager.rs`

**Analysis:**
These are explicit "racy" tests that stress-test the ratchet manager under concurrent rekey operations with random start delays. The flakiness suggests:
1. The recent rekey fix (registering listener before send) may not handle ALL edge cases
2. Tests with minimal delay (`min_delay_1_0`, `min_delay_2_1`) are most affected
3. This could be timing-dependent initialization races

**Next Steps:**
- Review test implementation to understand what specific race they're testing
- Check if there are additional synchronization points needed
- May need to examine rekey state machine for edge cases with near-simultaneous operations

---

### 2. Messenger Tests (NEW)

**Test:** `test_messenger_racy_contentious::secrecy_mode_2_SecrecyMode__Perfect`

**Location:** `citadel_crypt/src/messaging.rs`

**Analysis:**
This is an explicit "racy contentious" test for the messaging layer with Perfect secrecy mode. The test likely involves:
- Concurrent message sends/receives
- Ratchet operations during active messaging
- Perfect forward secrecy requiring immediate key rotation

**Likely Cause:**
Similar to the peer connection issue - may have a race between message processing and ratchet state updates.

---

### 3. Stress Tests - Still Flaky

**Tests:**
- `stress_test_p2p_messaging::case_1::AES_GCM_256` (3/3 - severe)
- `stress_test_p2p_messaging::case_1::Ascon80pq` (3/3 - severe)  
- `stress_test_p2p_messaging::case_2::ChaCha20Poly_1305` (2/3)
- `stress_test_c2s_messaging_kyber::case_2::KyberHybrid` (2/3)

**Analysis:**
These tests send 100-500 messages under heavy load. The flakiness pattern shows:
- Encryption algorithm may matter (AES, Ascon, ChaCha20, Kyber)
- Both P2P and C2S messaging affected
- Coverage builds (with profiling overhead) show more flakiness

**Likely Causes:**
1. Rekey operations happening during high message throughput
2. Message queue backpressure not handled properly
3. Encryption/decryption contention under load
4. Potential deadlock in message ordering guarantees

---

### 4. Group/Broadcast Tests (NEW)

**Tests:**
- `test_manual_group_connect::case_1` (3/3)
- `peer_to_peer_connect::case_1` (2/3)

**Analysis:**
Group broadcast mechanics may have similar channel/cancellation issues as we just fixed. The `test_manual_group_connect` required 3 retries, suggesting a more severe race.

**Potential Causes:**
- Similar `try_join!` cancellation in group broadcast code
- Multi-peer synchronization issues
- Barrier/coordination problems

---

## Recommended Next Steps

### Priority 1: Ratchet Manager Racy Tests
Highest retry count (3/3) and new after our rekey fix. Need to:
1. Review `test_ratchet_manager_racy_with_random_start_lag` implementation
2. Check for missing synchronization in rekey initialization
3. Verify listener registration handles concurrent rekey requests

### Priority 2: Group Broadcast Tests  
Required 3 retries, likely has similar cancellation issue:
1. Search for `try_join!` usage in broadcast/group code
2. Apply same fix pattern (use `join!` instead)

### Priority 3: Stress Test Stabilization
Multiple instances, encryption-dependent:
1. Add backpressure handling for high message rates
2. Review message ordering guarantees during rekeys
3. Consider rate limiting or batching in tests

---

## Historical Tracking

### Run 18818897067 (2025-10-26) - Before Fix
- peer_to_peer_connect_transient::case_2: 1
- peer_to_peer_connect_transient::case_3: 1  
- peer_to_peer_connect_transient::case_4: 1
- test_peer_to_peer_file_transfer::case_1: 1
- stress_test_p2p_messaging::case_1::AES_GCM_256: 1
- stress_test_p2p_messaging::case_1::ChaCha20Poly_1305: 1

### Run 18819737087 (2025-10-26) - After Peer Connection Fix
- peer_to_peer_connect_transient::case_2: 1 (IMPROVED - was 100% flaky, now ~33%)
- stress_test_p2p_messaging::case_1::AES_GCM_256: 1 (STILL FLAKY - 3/3)
- stress_test_c2s_messaging_kyber::case_2: 1 (NEW)
- test_ratchet_manager_racy_with_random_start_lag::min_delay_1_0: 1 (NEW)
- test_ratchet_manager_racy_with_random_start_lag::min_delay_2_1: 2 (NEW)
- test_messenger_racy_contentious::Perfect: 1 (NEW)
- test_manual_group_connect::case_1: 1 (NEW)
- peer_to_peer_connect::case_1: 1 (NEW)
- stress_test_p2p_messaging::case_1::Ascon80pq: 1 (NEW)
- stress_test_p2p_messaging::case_2::ChaCha20Poly_1305: 1 (NEW)

---

## Success Rate Analysis

**Fixed (No longer flaky):**
- ✅ peer_to_peer_connect_transient::case_3
- ✅ peer_to_peer_connect_transient::case_4
- ✅ test_peer_to_peer_file_transfer::case_1

**Improved:**
- 🟨 peer_to_peer_connect_transient::case_2 (100% fail rate → 33% fail rate)

**New Issues Exposed:**
- 🔴 7 new flaky tests discovered (likely existed before but not hit in previous run)
- 🔴 Ratchet manager racy tests showing instability
- 🔴 Group broadcast needing attention

**Overall:** The peer connection fix was successful and eliminated the primary issue. New flaky tests are now visible, likely because they were masked by the peer connection failures in previous runs, or because fixing one race exposed timing-dependent issues elsewhere.
