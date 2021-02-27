use crate::account_manager::AccountManager;
use std::ops::Try;
use crate::fcm::data_structures::{FcmPacket, FCMPayloadType, FcmHeader, FcmTicket, RawFcmPacket};
use std::option::NoneError;
use hyxe_crypt::hyper_ratchet::Ratchet;
use crate::misc::AccountError;
use hyxe_fs::io::SyncIO;
use std::future::Future;
use crate::prelude::ClientNetworkAccountInner;
use std::sync::Arc;
use crate::fcm::fcm_packet_processor::peer_post_register::PostRegisterInvitation;

pub(crate) mod group_header;
pub(crate) mod group_header_ack;
pub(crate) mod truncate;
pub(crate) mod peer_post_register;

pub fn blocking_process<T: AsRef<[u8]>>(raw_base64_json: T, account_manager: &AccountManager) -> FcmProcessorResult {
    log::info!("A0");
    let raw_packet = RawFcmPacket::deserialize_from_vector(raw_base64_json.as_ref()).map_err(|err| AccountError::IoError(err.to_string()))?;
    log::info!("A1");
    let packet = FcmPacket::from_raw_fcm_packet(&raw_packet)?;
    log::info!("A2");
    let header = packet.header();
    let use_client_server_ratchet = header.target_cid.get() == 0;
    // if the target cid is zero, it means we aren't using endpoint containers (only client -> server container)
    let local_cid = if use_client_server_ratchet { header.session_cid.get() } else { header.target_cid.get() };
    let implicated_cid = header.session_cid.get();
    let ratchet_version = header.ratchet_version.get();

    let (header, mut payload) = packet.split();
    let fcm_client = account_manager.fcm_client();

    let (res, do_save) = account_manager.visit_cnac(local_cid, |cnac| {
        cnac.visit_mut(|mut inner| {
            // get the implicated_cid's peer session crypto. In order to pass this checkpoint, the two users must have registered to each other
            let ClientNetworkAccountInner {
                fcm_crypt_container,
                kem_state_containers,
                crypt_container,
                fcm_invitations,
                ..
            } = &mut *inner;

            log::info!("A3");

            let res = if use_client_server_ratchet {
                log::info!("A4-CS");
                let ratchet = crypt_container.get_hyper_ratchet(Some(ratchet_version))?.clone();
                log::info!("A5");
                ratchet.validate_message_packet(None, &header, &mut payload).ok()?;
                log::info!("[FCM] Successfully validated packet. Parsing payload ...");
                let payload = FCMPayloadType::deserialize_from_vector(&payload).ok()?;

                match payload {
                    FCMPayloadType::PeerPostRegister { transfer, username } => peer_post_register::process(fcm_invitations, local_cid, transfer, username),
                    _ => {
                        log::warn!("[FCM] Invalid client/server signal received. Signal not programmed to be processed using c2s encryption");
                        FcmProcessorResult::Err("Bad signal, report to developers (X-789)".to_string())
                    }
                }
            } else {
                let crypt_container = fcm_crypt_container.get_mut(&implicated_cid)?;
                log::info!("A4-E2E");
                let ratchet = crypt_container.get_hyper_ratchet(Some(ratchet_version))?.clone();
                log::info!("A5");
                ratchet.validate_message_packet(None, &header, &mut payload).ok()?;
                log::info!("[FCM] Successfully validated packet. Parsing payload ...");
                let payload = FCMPayloadType::deserialize_from_vector(&payload).ok()?;

                match payload {
                    FCMPayloadType::GroupHeader { alice_to_bob_transfer, message } => group_header::process(fcm_client, crypt_container, ratchet,FcmHeader::try_from(&header).unwrap(), alice_to_bob_transfer, message),
                    FCMPayloadType::GroupHeaderAck { bob_to_alice_transfer } => group_header_ack::process(fcm_client, crypt_container, kem_state_containers, FcmHeader::try_from(&header).unwrap(), bob_to_alice_transfer),
                    FCMPayloadType::Truncate { truncate_vers } => truncate::process(crypt_container,  truncate_vers),
                    FCMPayloadType::PeerPostRegister { .. } => FcmProcessorResult::Err("Bad signal, report to developers (X-789)".to_string())
                }
            };

            let do_save = res.implies_save_needed();

            Some((res, do_save.then(|| cnac.clone())))
        })
    }).ok_or::<AccountError>(AccountError::ClientNonExists(local_cid))?;

    if let Some(cnac) = do_save {
        cnac.blocking_save_to_local_fs()?;
    }

    res
}



#[allow(variant_size_differences)]
#[derive(Debug)]
pub enum FcmProcessorResult {
    Void,
    Err(String),
    Value(FcmResult)
}

impl FcmProcessorResult {
    pub fn implies_save_needed(&self) -> bool {
        match self {
            Self::Value(FcmResult::MessageSent { .. } | FcmResult::GroupHeaderAck { .. } | FcmResult::GroupHeader { .. } | FcmResult::PostRegisterInvitation { .. })=> true,
            _ => false
        }
    }
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
    MessageSent { ticket: FcmTicket },
    PostRegisterInvitation { invite: PostRegisterInvitation }
}

#[allow(unused_results)]
/// This constructs an independent single-threaded runtime to allow this to be called invariant to environmental tokio context
pub fn block_on_async<F: Future + Send + 'static>(fx: impl FnOnce() -> F + Send + 'static) -> Result<F::Output, AccountError<String>> where <F as Future>::Output: Send + 'static {
    static RT: parking_lot::Mutex<Option<Arc<tokio::runtime::Runtime>>> = parking_lot::const_mutex(None);

    let mut lock = RT.lock();
    if lock.is_none() {
        log::info!("Constructing current_thread RT ...");
        *lock = Some(Arc::new(tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|err| AccountError::Generic(err.to_string()))?));
    }

    log::info!("RT existent, now spawning ...");
    let rt = lock.clone().unwrap();
    std::mem::drop(lock);
    // call in a unique thread to not cause a panic when running block_on
    std::thread::spawn(move || {
        rt.block_on(async move {
            log::info!("block_on_async spawned ...");
            (fx)().await
        })
    }).join().map_err(|_| AccountError::Generic("Error while joining thread".to_string()))
}