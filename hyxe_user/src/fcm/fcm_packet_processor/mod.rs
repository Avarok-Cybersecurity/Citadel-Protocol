use crate::account_manager::AccountManager;
use std::ops::Try;
use crate::fcm::data_structures::{FcmPacket, FCMPayloadType, FcmHeader, FcmTicket, RawFcmPacket};
use std::option::NoneError;
use hyxe_crypt::hyper_ratchet::Ratchet;
use crate::misc::AccountError;
use hyxe_fs::io::SyncIO;
use std::future::Future;
use crate::prelude::ClientNetworkAccountInner;

pub(crate) mod group_header;
pub(crate) mod group_header_ack;
pub(crate) mod truncate;

pub fn blocking_process<T: AsRef<[u8]>>(raw_base64_json: T, account_manager: &AccountManager) -> FcmProcessorResult {
    log::info!("A0");
    let raw_packet = RawFcmPacket::deserialize_from_vector(raw_base64_json.as_ref()).map_err(|err| AccountError::IoError(err.to_string()))?;
    log::info!("A1");
    let packet = FcmPacket::from_raw_fcm_packet(&raw_packet)?;
    log::info!("A2");
    let header = packet.header();
    let local_cid = header.target_cid.get();
    let implicated_cid = header.session_cid.get();
    let ratchet_version = header.ratchet_version.get();

    let (header, mut payload) = packet.split();
    let fcm_client = account_manager.fcm_client();

    account_manager.visit_cnac(local_cid, |cnac| {
        cnac.visit_mut(|mut inner| {
            // get the implicated_cid's peer session crypto. In order to pass this checkpoint, the two users must have registered to each other
            let ClientNetworkAccountInner {
                fcm_crypt_container,
                kem_state_containers,
                ..
            } = &mut *inner;

            log::info!("A3");
            let peer_crypt_container = fcm_crypt_container.get_mut(&implicated_cid)?;
            log::info!("A4");
            let ratchet = peer_crypt_container.get_hyper_ratchet(Some(ratchet_version))?.clone();
            log::info!("A5");
            ratchet.validate_message_packet(None, &header, &mut payload).ok()?;
            log::info!("[FCM] Successfully validated packet. Parsing payload ...");
            let payload = FCMPayloadType::deserialize_from_vector(&payload).ok()?;
            // now, pass to the subprocessor
            Some(match payload {
                FCMPayloadType::GroupHeader { alice_to_bob_transfer, message } => group_header::process(fcm_client, peer_crypt_container, ratchet,FcmHeader::try_from(&header).unwrap(), alice_to_bob_transfer, message),
                FCMPayloadType::GroupHeaderAck { bob_to_alice_transfer } => group_header_ack::process(fcm_client, peer_crypt_container, kem_state_containers, FcmHeader::try_from(&header).unwrap(), bob_to_alice_transfer),
                FCMPayloadType::Truncate { truncate_vers } => truncate::process(peer_crypt_container,  truncate_vers)
            })
        })
    }).ok_or::<AccountError>(AccountError::ClientNonExists(local_cid))?
}

#[allow(variant_size_differences)]
#[derive(Debug)]
pub enum FcmProcessorResult {
    Void,
    Err(String),
    Value(FcmResult)
}

impl Try for FcmProcessorResult {
    type Ok = Self;
    type Error = Self;

    fn into_result(self) -> Result<Self::Ok, Self::Error> {
        match self {
            val @ Self::Err(..) => {
                Err(val)
            }

            val => Ok(val)
        }
    }

    fn from_error(v: Self::Error) -> Self {
        v
    }

    fn from_ok(v: Self::Ok) -> Self {
        v
    }
}

impl From<NoneError> for FcmProcessorResult {
    fn from(_: NoneError) -> Self {
        FcmProcessorResult::Err("Invalid input".to_string())
    }
}

impl<T: Into<String>> From<AccountError<T>> for FcmProcessorResult {
    fn from(err: AccountError<T>) -> Self {
        FcmProcessorResult::Err(err.into_string())
    }
}

#[derive(Debug)]
pub enum FcmResult {
    GroupHeader { ticket: FcmTicket, message: Vec<u8> },
    GroupHeaderAck { ticket: FcmTicket },
    MessageSent { ticket: FcmTicket }
}

#[allow(unused_results)]
pub fn block_on_async<F: Future + Send + 'static>(fx: impl FnOnce() -> F + Send + 'static) -> Result<F::Output, AccountError<String>> where <F as Future>::Output: Send + 'static {
    let (tx, rx) = std::sync::mpsc::sync_channel::<F::Output>(0);
    log::info!("ABC");
    tokio::task::spawn(async move {
        log::info!("block_on_async spawned ...");
        let res = (fx)().await;
        log::info!("block_on_async finished getting value");
        if let Err(err) = tx.send(res) {
            log::error!("[FCM] A/sync: Unable to send result from async to sync code: {:?}", err);
        }
    });

    rx.recv().map_err(|err| AccountError::Generic(err.to_string()))
}