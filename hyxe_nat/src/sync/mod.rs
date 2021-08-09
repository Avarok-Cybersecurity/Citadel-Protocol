use crate::udp_traversal::linear::RelativeNodeType;
use std::future::Future;
use crate::sync::net_select_ok::NetSelectOk;
use crate::reliable_conn::ReliableOrderedConnectionToTarget;
use crate::sync::sync_start::NetSyncStart;
use serde::Serialize;
use serde::de::DeserializeOwned;
use crate::udp_traversal::linear::encrypted_config_container::EncryptedConfigContainer;
use crate::udp_traversal::udp_hole_puncher::UdpHolePuncher;
use crate::sync::net_select::NetSelect;

pub mod net_select_ok;
pub mod net_select;
pub mod sync_start;

pub trait ReliableOrderedConnSyncExt: ReliableOrderedConnectionToTarget + Sized {
    fn net_select<'a, F: 'a, R: 'a>(&'a self, relative_node_type: RelativeNodeType, future: F) -> NetSelect<'a, R>
        where
            F: Future<Output=R> {
        NetSelect::new(self, relative_node_type, future)
    }

    fn net_select_ok<'a, F: 'a, R: 'a>(&'a self, relative_node_type: RelativeNodeType, future: F) -> NetSelectOk<'a, R>
        where
            F: Future<Output=Result<R, anyhow::Error>> {
        NetSelectOk::new(self, relative_node_type, future)
    }

    fn sync(&self, relative_node_type: RelativeNodeType) -> NetSyncStart<()> {
        NetSyncStart::<()>::new_sync_only(self, relative_node_type)
    }

    /// Returns the payload to the adjacent node at about the same time
    fn sync_exchange_payload<'a, R: 'a>(&'a self, relative_node_type: RelativeNodeType, payload: R) -> NetSyncStart<'a, R>
        where
            R: Serialize + DeserializeOwned + Send + Sync {
        NetSyncStart::exchange_payload(self, relative_node_type, payload)
    }

    fn sync_execute<'a, F: 'a, Fx: 'a, P: 'a + Serialize + DeserializeOwned + Send + Sync, R: 'a>(&'a self, relative_node_type: RelativeNodeType, future: Fx, payload: P) -> NetSyncStart<'a, R>
        where
            F: Future<Output=R>,
            F: Send,
            Fx: FnOnce(P) -> F,
            Fx: Send {
        NetSyncStart::new(self, relative_node_type, future, payload)
    }

    fn begin_udp_hole_punch(&self, relative_node_type: RelativeNodeType, encrypted_config_container: EncryptedConfigContainer) -> UdpHolePuncher {
        UdpHolePuncher::new(self, relative_node_type, encrypted_config_container)
    }
}

impl<T: ReliableOrderedConnectionToTarget> ReliableOrderedConnSyncExt for T {}