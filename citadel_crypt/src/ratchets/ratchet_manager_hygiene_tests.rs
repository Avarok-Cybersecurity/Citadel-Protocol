//! What a ratchet manager keeps of its pre-shared keys is wiped when it drops.
use super::{AttachedPayload, RatchetManager};
use crate::ratchets::Ratchet;
use zeroize::ZeroizeOnDrop;

fn wiped_on_drop<T: ZeroizeOnDrop>(_: &[T]) {}

/// Compiles only while every pre-shared key the manager holds wipes itself on drop.
#[allow(dead_code)]
fn pre_shared_keys_are_wiped<S, I, R: Ratchet, P: AttachedPayload>(
    manager: &RatchetManager<S, I, R, P>,
) {
    wiped_on_drop(&manager.psks[..]);
}

#[test]
fn a_pre_shared_key_wipes_its_passwords_on_drop() {
    let key = citadel_types::crypto::PreSharedKey::from("password");
    wiped_on_drop(std::slice::from_ref(&key));
}
