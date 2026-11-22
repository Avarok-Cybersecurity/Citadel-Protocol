//! One session's group broadcasts, handled in the order they arrived.
//!
//! A session handles its inbound packets concurrently, so two packets may finish in either
//! order. For a group that is a reordering the members see: one sender's messages relayed, or
//! read, out of the order they were sent, or a member's Commit acknowledgement handled before a
//! message it sent at the epoch the Commit leaves (which the server would then relay to a joiner
//! that cannot read it). Every group broadcast therefore takes a turn in this lane when the
//! reader pulls it off the stream, which happens in arrival order, waits for every earlier turn,
//! and holds its own until it is handled. Packets that are not group broadcasts take no turn.
//!
//! A turn waits only on turns taken before it, whose packets the reader already pulled, so the
//! lane cannot hold back the packet it waits for.

use citadel_io::tokio::sync::oneshot;
use futures::future::{BoxFuture, FutureExt, Shared};

/// Resolves once a turn and every turn before it are done. A turn given up resolves with the
/// turn before it, so the order holds across it.
type Done = Shared<BoxFuture<'static, ()>>;

/// The order the session's group broadcasts are handled in.
#[derive(Default)]
pub(crate) struct GroupLane {
    last: citadel_io::Mutex<Option<Done>>,
}

/// One packet's place in the lane. The next turn may start once this one is dropped.
pub(crate) struct Turn {
    before: Option<Done>,
    _done: oneshot::Sender<()>,
}

impl GroupLane {
    /// The next turn. Take it in arrival order, before the packet's handling starts.
    pub(crate) fn take(&self) -> Turn {
        let (done, own) = oneshot::channel::<()>();
        let mut last = self.last.lock();
        let before = last.clone();
        let earlier = last.take();
        let finished = async move {
            if let Some(earlier) = earlier {
                earlier.await;
            }
            let _ = own.await;
        }
        .boxed()
        .shared();
        *last = Some(finished);
        Turn {
            before,
            _done: done,
        }
    }
}

impl Turn {
    /// Waits until every earlier turn has been handled.
    pub(crate) async fn wait(&mut self) {
        if let Some(before) = self.before.take() {
            before.await;
        }
    }
}

/// Waits for a group broadcast's turn; the next turn starts once the returned one is dropped.
pub(crate) async fn in_order(turn: Option<Turn>) -> Option<Turn> {
    let mut turn = turn?;
    turn.wait().await;
    Some(turn)
}

/// Whether a packet whose de-obfuscated header starts with `header` is a group broadcast.
pub(crate) fn is_group_broadcast(header: &[u8]) -> bool {
    use crate::proto::packet::packet_flags::cmd::{
        aux::peer_cmd::GROUP_BROADCAST, primary::PEER_CMD,
    };
    header.len() >= 2 && header[0] == PEER_CMD && header[1] == GROUP_BROADCAST
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_io::tokio;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn turns_finish_in_the_order_they_were_taken() {
        let lane = GroupLane::default();
        let order = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::new();
        for n in 0..8u64 {
            let mut turn = lane.take();
            let order = order.clone();
            handles.push(tokio::spawn(async move {
                // Later turns are readier: without the lane they would finish first.
                tokio::time::sleep(std::time::Duration::from_millis(40 - 5 * n)).await;
                turn.wait().await;
                order.lock().unwrap().push(n);
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }
        assert_eq!(*order.lock().unwrap(), (0..8).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn a_turn_that_ends_early_frees_the_next() {
        let lane = GroupLane::default();
        let first = lane.take();
        let mut second = lane.take();
        drop(first);
        second.wait().await;
    }

    #[tokio::test]
    async fn a_turn_waits_for_every_earlier_turn_not_only_the_last() {
        let lane = GroupLane::default();
        let first = lane.take();
        let second = lane.take();
        let third = lane.take();
        // The second ends before the first; the third must still wait for the first.
        drop(second);
        let waiting = tokio::spawn(in_order(Some(third)));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(!waiting.is_finished(), "a turn overtook an earlier one");
        drop(first);
        assert!(waiting.await.unwrap().is_some());
    }

    #[test]
    fn only_group_broadcasts_take_turns() {
        use crate::proto::packet::packet_flags::cmd::{aux::peer_cmd, primary};
        assert!(is_group_broadcast(&[
            primary::PEER_CMD,
            peer_cmd::GROUP_BROADCAST,
            0
        ]));
        assert!(!is_group_broadcast(&[
            primary::PEER_CMD,
            peer_cmd::GROUP_BROADCAST + 1
        ]));
        assert!(!is_group_broadcast(&[
            primary::KEEP_ALIVE,
            peer_cmd::GROUP_BROADCAST
        ]));
        assert!(!is_group_broadcast(&[]));
    }
}
