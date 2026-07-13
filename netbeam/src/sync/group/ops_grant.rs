//! Grant issuance: mints the fence, consumes poison (write grants), and installs
//! the holder entry. Split from `ops.rs` (single caller set: the apply() arms).

use crate::sync::group::op_types::{OpDenied, OpOutcome};
use crate::sync::group::record::{HolderEntry, Holders, LockRecord};
use crate::sync::group::{LockKind, MemberId};

pub(super) fn grant(
    rec: &mut LockRecord,
    member: MemberId,
    nonce: u64,
    kind: LockKind,
) -> Result<OpOutcome, OpDenied> {
    let fence = rec.next_fence().ok_or(OpDenied::CounterExhausted)?;
    let recovered = match kind {
        LockKind::Write => rec.poisoned.take(),
        LockKind::Read => None,
    };
    let entry = HolderEntry {
        member,
        nonce,
        fence,
        lease_seq: 0,
        recovered: recovered.clone(),
    };
    match (&mut rec.holders, kind) {
        (Holders::Readers(hs), LockKind::Read) => hs.push(entry),
        (holders @ Holders::None, LockKind::Read) => *holders = Holders::Readers(vec![entry]),
        (holders, LockKind::Write) => {
            debug_assert!(matches!(holders, Holders::None));
            *holders = Holders::Writer(entry);
        }
        (Holders::Writer(_), LockKind::Read) => {
            unreachable!("admission forbids read grants while a writer holds")
        }
    }
    Ok(OpOutcome::Granted { fence, recovered })
}
