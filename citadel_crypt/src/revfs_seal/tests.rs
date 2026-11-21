use super::*;

const ROOT: [u8; 32] = [7u8; 32];
const DOMAIN: &str = "storage.example";
const CID: u64 = 42;
const OBJECT: u128 = 0x1234_5678_9abc_def0_1122_3344_5566_7788;

fn key() -> RevfsKey {
    RevfsKey::derive(&ROOT, DOMAIN, CID).unwrap()
}

fn code(err: CryptError) -> ErrorCode {
    err.code()
}

fn opened(key: &RevfsKey, group_index: u64, level: SecurityLevel, group: &[u8]) -> Vec<u8> {
    open(Some(key), CID, OBJECT, group_index, level, group).unwrap()
}

fn refused(key: Option<&RevfsKey>, group: &[u8]) -> ErrorCode {
    code(open(key, CID, OBJECT, 0, SecurityLevel::Standard, group).unwrap_err())
}

#[test]
fn a_group_opens_at_every_level_it_was_sealed_at() {
    let key = key();
    let plaintext = b"the bytes the server must not read".to_vec();
    for level in [
        SecurityLevel::Standard,
        SecurityLevel::Reinforced,
        SecurityLevel::Extreme,
        SecurityLevel::Custom(10),
    ] {
        let group = seal(&key, OBJECT, 3, level, &plaintext).unwrap();
        assert_eq!(group.len(), sealed_len(plaintext.len(), level));
        assert_eq!(&group[..4], MAGIC);
        assert_eq!(group[4..12], key.id());
        assert!(!group.windows(plaintext.len()).any(|w| w == plaintext));
        assert_eq!(opened(&key, 3, level, &group), plaintext.clone());
    }
}

#[test]
fn an_empty_group_seals_and_opens() {
    let key = key();
    let group = seal(&key, OBJECT, 0, SecurityLevel::Standard, &[]).unwrap();
    assert_eq!(opened(&key, 0, SecurityLevel::Standard, &group), vec![]);
}

#[test]
fn two_seals_of_the_same_group_differ() {
    let key = key();
    let a = seal(&key, OBJECT, 0, SecurityLevel::Standard, b"same").unwrap();
    let b = seal(&key, OBJECT, 0, SecurityLevel::Standard, b"same").unwrap();
    assert_ne!(a, b);
}

#[test]
fn a_group_moved_to_another_position_or_object_does_not_open() {
    let key = key();
    let level = SecurityLevel::Reinforced;
    let group = seal(&key, OBJECT, 5, level, b"group five").unwrap();
    let moved = open(Some(&key), CID, OBJECT, 6, level, &group).unwrap_err();
    assert_eq!(code(moved), ErrorCode::RevfsSealBroken);
    let other_object = open(Some(&key), CID, OBJECT + 1, 5, level, &group).unwrap_err();
    assert_eq!(code(other_object), ErrorCode::RevfsSealBroken);
}

#[test]
fn every_altered_or_truncated_byte_is_refused() {
    let key = key();
    let level = SecurityLevel::Reinforced;
    let group = seal(&key, OBJECT, 0, level, b"0123456789").unwrap();
    for i in HEADER_LEN..group.len() {
        let mut altered = group.clone();
        altered[i] ^= 0x01;
        let err = open(Some(&key), CID, OBJECT, 0, level, &altered).unwrap_err();
        assert_eq!(code(err), ErrorCode::RevfsSealBroken, "byte {i}");
    }
    for len in HEADER_LEN..group.len() {
        let err = open(Some(&key), CID, OBJECT, 0, level, &group[..len]).unwrap_err();
        assert_eq!(code(err), ErrorCode::RevfsSealBroken, "length {len}");
    }
}

#[test]
fn a_group_naming_another_level_is_refused() {
    let key = key();
    let group = seal(&key, OBJECT, 0, SecurityLevel::Reinforced, b"x").unwrap();
    let err = open(Some(&key), CID, OBJECT, 0, SecurityLevel::Standard, &group).unwrap_err();
    assert_eq!(code(err), ErrorCode::RevfsSealLevelMismatch);
    let mut restated = group.clone();
    restated[HEADER_LEN - 1] = SecurityLevel::Standard.value();
    let err = open(
        Some(&key),
        CID,
        OBJECT,
        0,
        SecurityLevel::Standard,
        &restated,
    )
    .unwrap_err();
    assert_eq!(code(err), ErrorCode::RevfsSealBroken);
}

#[test]
fn a_level_no_ratchet_carries_is_refused_before_any_work() {
    let key = key();
    let err = seal(&key, OBJECT, 0, SecurityLevel::Custom(254), b"x").unwrap_err();
    assert_eq!(code(err), ErrorCode::SecurityLevelAboveMaximum);
    let mut group = seal(&key, OBJECT, 0, SecurityLevel::Standard, b"x").unwrap();
    group[HEADER_LEN - 1] = 254;
    let err = open(
        Some(&key),
        CID,
        OBJECT,
        0,
        SecurityLevel::Custom(254),
        &group,
    )
    .unwrap_err();
    assert_eq!(code(err), ErrorCode::SecurityLevelAboveMaximum);
}

#[test]
fn another_accounts_group_is_refused() {
    let mine = key();
    for theirs in [
        RevfsKey::derive(&ROOT, DOMAIN, CID + 1).unwrap(),
        RevfsKey::derive(&ROOT, "other.example", CID).unwrap(),
        RevfsKey::derive(&[8u8; 32], DOMAIN, CID).unwrap(),
    ] {
        assert_ne!(theirs.id(), mine.id());
        let group = seal(&theirs, OBJECT, 0, SecurityLevel::Standard, b"x").unwrap();
        assert_eq!(
            refused(Some(&mine), &group),
            ErrorCode::RevfsSealedUnderAnotherKey
        );
        // Control: its own key opens it.
        assert_eq!(opened(&theirs, 0, SecurityLevel::Standard, &group), b"x");
    }
}

/// A group stored before the sealed format (no prefix) is refused, with or without a key. The
/// sealed groups above, which open, are the control.
#[test]
fn a_group_without_the_prefix_is_refused_with_or_without_a_key() {
    let unsealed = vec![0xAAu8; 64];
    assert_eq!(
        refused(Some(&key()), &unsealed),
        ErrorCode::RevfsSealUnrecognised
    );
    assert_eq!(refused(None, &unsealed), ErrorCode::RevfsSealUnrecognised);
    assert_eq!(
        refused(Some(&key()), b"RVF"),
        ErrorCode::RevfsSealUnrecognised
    );
}

#[test]
fn a_sealed_group_without_a_key_is_refused_as_missing_key() {
    let group = seal(&key(), OBJECT, 0, SecurityLevel::Standard, b"x").unwrap();
    let err = open(None, CID, OBJECT, 0, SecurityLevel::Standard, &group).unwrap_err();
    assert_eq!(code(err), ErrorCode::RevfsKeyMissing);
}

#[test]
fn a_key_is_derived_deterministically_and_needs_a_domain() {
    assert_eq!(key().id(), key().id());
    let err = RevfsKey::derive(&ROOT, "", CID).unwrap_err();
    assert_eq!(code(err), ErrorCode::RevfsKeyDomainInvalid);
    let long = "a".repeat(usize::from(u16::MAX) + 1);
    let err = RevfsKey::derive(&ROOT, &long, CID).unwrap_err();
    assert_eq!(code(err), ErrorCode::RevfsKeyDomainInvalid);
    assert!(format!("{:?}", key()).starts_with("RevfsKey(id "));
}

#[test]
fn each_layer_and_object_has_its_own_subkey() {
    let key = key();
    assert_ne!(*key.layer_key(OBJECT, 0), *key.layer_key(OBJECT, 1));
    assert_ne!(*key.layer_key(OBJECT, 0), *key.layer_key(OBJECT + 1, 0));
}
