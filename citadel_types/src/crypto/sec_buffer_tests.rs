use super::*;

/// Bytes a buffer once held stay in its allocation after it shrinks; the wipe must reach them.
#[test]
fn a_wipe_reaches_bytes_beyond_the_current_length() {
    let mut b = SecBuffer::from(&[0xAAu8; 32][..]);
    b.handle().truncate(0);
    b.wipe();
    // SAFETY: the allocation holds at least 32 initialised bytes (written above); truncating
    // changed only the length, so reading them through the base pointer stays in bounds.
    let held = unsafe { std::slice::from_raw_parts(b.inner.as_ptr(), 32) };
    assert!(held.iter().all(|byte| *byte == 0), "{held:?}");
}

#[cfg(not(target_family = "wasm"))]
#[test]
fn the_lock_covers_the_whole_allocation() {
    let page = 64 * 1024;
    let mut b = SecBuffer::with_capacity(3 * page);
    b.handle().put_bytes(7, 1);
    let tail = b.inner.as_ptr() as usize + 2 * page;
    assert!(
        utils::mem::holders_of_page(tail) > 0,
        "the spare capacity is locked"
    );
}

#[test]
fn growth_through_the_handle_keeps_the_contents() {
    let mut b = SecBuffer::with_capacity(4);
    {
        let mut h = b.handle();
        h.extend_from_slice(b"secret");
        h.put_bytes(b'!', 3);
        h[0] = b'S';
    }
    assert_eq!(b.as_ref(), b"Secret!!!");
    b.handle().clear();
    assert!(b.is_empty());
}
