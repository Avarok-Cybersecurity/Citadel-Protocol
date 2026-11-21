//! The RE-VFS keys of an example node. A node has no key unless it is given a source, and it
//! never generates one. A real application derives each account's key from the account's
//! recovery or identity seed, which it keeps; an example draws a fresh root each run, so what
//! it stores can be read back only during that run.

use citadel_sdk::prelude::{RevfsKey, RevfsKeySource};

pub fn per_run(server_domain: &'static str) -> impl RevfsKeySource {
    let mut root = [0u8; 32];
    getrandom::fill(&mut root).expect("the OS random source is unavailable");
    move |cid: u64| RevfsKey::derive(&root, server_domain, cid).ok()
}
