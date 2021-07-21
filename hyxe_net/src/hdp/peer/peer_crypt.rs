use serde::{Serialize, Deserialize};
use crate::hdp::misc::session_security_settings::SessionSecuritySettings;
use crate::hdp::peer::peer_layer::UdpMode;
use std::net::SocketAddr;


pub const KEP_STAGE0: u8 = 0;
pub const KEP_STAGE1: u8 = 1;
pub const KEP_INIT_REKEY: u8 = 2;
pub const KEP_ACCEPT_REKEY: u8 = 3;


#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum KeyExchangeProcess {
    // alice sends public key
    Stage0(Vec<u8>, SessionSecuritySettings, UdpMode),
    // Bob sends ciphertext, addr
    Stage1(Vec<u8>, Option<SocketAddr>),
    // Alice sends a sync time over. Server takes care of external addr
    Stage2(i64, Option<SocketAddr>),
    // Sends a signal to the other side validating that it established a connection
    // However, the other side must thereafter receiving prove that it's who they claim it is
    // to prevent MITM attacks
    HolePunchEstablished,
    // once the adjacent side confirms that they are who they claim they are, then the local node
    // can update its endpoint container to allow exhange of information
    // the bool determines whether or not the connection was upgraded
    HolePunchEstablishedVerified(bool),
    // The hole-punch failed
    HolePunchFailed
}