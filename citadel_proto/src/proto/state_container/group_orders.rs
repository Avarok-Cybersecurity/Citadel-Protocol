//! The order each of this client's replay groups has, as its server described it (see
//! `peer::group_order_view`).

use super::StateContainerInner;
use crate::proto::peer::group_order_view::GroupOrderView;
use citadel_crypt::ratchets::Ratchet;
use citadel_types::proto::{GroupOrderInfo, MessageGroupKey};

impl<R: Ratchet> StateContainerInner<R> {
    /// The cell `key`'s channel reads its order from.
    pub(super) fn group_order_view(&mut self, key: MessageGroupKey) -> GroupOrderView {
        self.group_orders.entry(key).or_default().clone()
    }

    /// The server described `key`'s order as `info`.
    pub(crate) fn record_group_order(&mut self, key: MessageGroupKey, info: GroupOrderInfo) {
        self.group_order_view(key).set(info);
    }
}
