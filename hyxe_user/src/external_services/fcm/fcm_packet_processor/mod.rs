use std::future::Future;
use std::ops::{ControlFlow, FromResidual, Try};
use std::sync::Arc;

use fcm::Client;

use hyxe_crypt::hyper_ratchet::Ratchet;
use hyxe_fs::io::SyncIO;

use crate::account_manager::AccountManager;
use crate::external_services::fcm::data_structures::{FcmHeader, FcmPacket, FCMPayloadType, FcmTicket, RawExternalPacket};
use crate::external_services::fcm::fcm_instance::FCMInstance;
use crate::external_services::fcm::fcm_packet_processor::peer_post_register::{FcmPostRegisterResponse, PostRegisterInvitation};
use crate::misc::AccountError;
use crate::prelude::ClientNetworkAccountInner;
use crate::external_services::ExternalService;
use crate::external_services::service_interface::ExternalServiceChannel;
use crate::external_services::rtdb::{RtdbClientConfig, RtdbInstance};
use hyxe_crypt::endpoint_crypto_container::PeerSessionCrypto;

pub(crate) mod group_header;
pub(crate) mod group_header_ack;
pub(crate) mod truncate;
pub(crate) mod deregister;
pub(crate) mod truncate_ack;
pub mod peer_post_register;

/// If the raw packet was: {"inner": "ABCDEF"}, then, the input here should be simply ABCDEF without quotations.
///
/// Reliability note: Google FCM does NOT guarantee ordered delivery. This is a problem for key exchanges. As such, the higher-level protocol needs to ensure several things.
/// One, that ALL packets returned from the FcmProcessorResult get sent to the central server for redundant delivery. This allows for 2), which is that before calling this on a new
/// inbound FCM packet, the user first FETCH_LOGINS to the server to fetch any pending data that has not yet been processed. The processing will take place sequentially
///
/// NOTE: This implies that sending the re-key payloads is redundant over FCM. We can have notification packets that wake-up the device instead later-on
///
/// Note: This should ONLY be called at the endpoints!!
pub async fn process<T: Into<String>>(base64_value: T, account_manager: AccountManager, send_service_type: ExternalService) -> FcmProcessorResult {
    //let account_manager = account_manager.clone();
    let base64_value = base64_value.into();

    log::info!("A0");
    let raw_packet = RawExternalPacket::from(base64_value);
    log::info!("A1");
    let packet = FcmPacket::from_raw_fcm_packet(&raw_packet)?;
    log::info!("A2");
    let header = packet.header();
    let group_id = header.group_id.get();
    let ticket = header.ticket.get();
    let use_client_server_ratchet = header.target_cid.get() == 0;

    // if the target cid is zero, it means we aren't using endpoint containers (only client -> server container)
    let local_cid = if use_client_server_ratchet { header.session_cid.get() } else { header.target_cid.get() };
    let implicated_cid = header.session_cid.get();
    let ratchet_version = header.ratchet_version.get();

    let (header, mut payload) = packet.split();
    // Due to a bug of the internal connection pool on android/ios, we create a new client each time
    //let fcm_client = account_manager.fcm_client();

    // TODO: Run packet through can_process_packet. If false, then send a REQ packet to request retransmission of last packet in series, and store packet locally

    log::info!("Using {} ratchet (local CID: {} | ratchet vers: {})", use_client_server_ratchet.then(|| "client/server").unwrap_or("FCM endpoint"), local_cid, ratchet_version);
    let cnac = account_manager.get_client_by_cid(local_cid).await?.ok_or(AccountError::<String>::ClientNonExists(local_cid))?;
    let res = cnac.visit_mut(|mut inner| async move {
        // get the implicated_cid's peer session crypto. In order to pass this checkpoint, the two users must have registered to each other
        let ClientNetworkAccountInner {
            persistence_handler,
            fcm_crypt_container,
            kem_state_containers,
            crypt_container,
            fcm_invitations,
            mutuals,
            client_rtdb_config,
            ..
        } = &mut *inner;

        log::info!("A3");

        let res = if use_client_server_ratchet {
            log::info!("A4-CS");
            let ratchet = crypt_container.toolset.get_static_auxiliary_ratchet();
            let persistence_handler = persistence_handler.as_ref().ok_or_else(|| AccountError::Generic("Persistence handler not loaded".into()))?;
            log::info!("A5");
            ratchet.validate_message_packet(None, &header, &mut payload).map_err(|err| AccountError::Generic(err.into_string()))?;
            log::info!("[FCM] Successfully validated packet. Parsing payload ...");
            let payload = FCMPayloadType::deserialize_from_vector(&payload).map_err(|err| AccountError::Generic(err.to_string()))?;
            let source_cid = group_id;
            log::info!("A6");

            match payload {
                // NOTE: Lock being held here across .await
                FCMPayloadType::PeerPostRegister { transfer, username } => peer_post_register::process(persistence_handler, fcm_invitations, kem_state_containers, fcm_crypt_container, mutuals, local_cid, source_cid, ticket, transfer, username).await,
                _ => {
                    log::warn!("[FCM] Invalid client/server signal received. Signal not programmed to be processed using c2s encryption");
                    FcmProcessorResult::Err("Bad signal, report to developers (X-789)".to_string())
                }
            }
        } else {
            let crypt_container = fcm_crypt_container.get_mut(&implicated_cid).ok_or_else(|| AccountError::Generic("FCM Peer session crypto nonexistant".to_string()))?;
            log::info!("A4-E2E");
            let ratchet = crypt_container.get_hyper_ratchet(Some(ratchet_version)).cloned().ok_or_else(|| AccountError::Generic("FCM Ratchet version not found".to_string()))?;
            log::info!("A5");
            ratchet.validate_message_packet(None, &header, &mut payload).map_err(|err| AccountError::Generic(err.into_string()))?;
            log::info!("[FCM] Successfully validated packet. Parsing payload ...");
            let payload = FCMPayloadType::deserialize_from_vector(&payload).map_err(|err| AccountError::Generic(err.to_string()))?;

            let ref fcm_client = match send_service_type { ExternalService::Fcm => Some(Arc::new(Client::new())), _ => None };
            let svc_params = InstanceParameter { client: fcm_client.as_ref(), service_type: send_service_type, rtdb_client_cfg: client_rtdb_config.as_ref() };

            match payload {
                FCMPayloadType::GroupHeader { alice_to_bob_transfer, message } => group_header::process(svc_params, crypt_container, ratchet, FcmHeader::try_from(&header).unwrap(), alice_to_bob_transfer, message).await,
                FCMPayloadType::GroupHeaderAck { bob_to_alice_transfer } => group_header_ack::process(svc_params,crypt_container, kem_state_containers, FcmHeader::try_from(&header).unwrap(), bob_to_alice_transfer).await,
                FCMPayloadType::Truncate { truncate_vers } => truncate::process(svc_params,crypt_container, truncate_vers, FcmHeader::try_from(&header).unwrap()).await,
                FCMPayloadType::TruncateAck { truncate_vers } => truncate_ack::process(crypt_container, truncate_vers),
                FCMPayloadType::PeerPostRegister { .. } => FcmProcessorResult::Err("Bad signal, report to developers (X-7890)".to_string()),
                // below, the implicated cid is obtained from the session_cid, and as such, is the peer_cid
                FCMPayloadType::PeerDeregistered => deregister::process(implicated_cid, local_cid, ticket, fcm_crypt_container, mutuals)
            }
        };

        Ok(res) as Result<FcmProcessorResult, AccountError>
    }).await?;

    log::info!("A7");

    if res.implies_save_needed() {
        cnac.save().await?;
    }

    log::info!("FCM-processing complete");

    res
}

/// The goal of the function is to perform any and all internal updates/re-keys from a set of packets. Most have probably already been processed, and will fail the anti-replay attack stage for being an already received packet
/// This is needed for packets that don't get delivered
///
/// If this receives GROUP_HEADER_ACKS or DO_TRUNCATES
/*
pub fn blocking_process_packet_store(mut raw_fcm_packet_store: RawFcmPacketStore, account_manager: &AccountManager) -> FcmProcessorResult {
    // for each client, perform the inner subroutine
    let cids = raw_fcm_packet_store.inner.keys().map(|r| *r).collect::<Vec<u64>>();
    let mut ret = Vec::new();
    for cid in cids {
        let entry = raw_fcm_packet_store.inner.remove(&cid).unwrap();
        // in the btreemap, entries are already sorted by key (which is optimal for this stage of processing, since any re-keys need to happen in order)
        // we collect each result inside the ret vec
        for (_raw_ticket, raw_packet) in entry {
            match blocking_process(raw_packet.inner, account_manager) {
                FcmProcessorResult::Value(res, packet) => {
                    ret.push((res, packet));
                }

                _ => {}
            }
        }
    }

    FcmProcessorResult::Values(ret)
}
*/

#[allow(variant_size_differences)]
#[derive(Debug)]
pub enum FcmProcessorResult {
    Void,
    Err(String),
    RequiresSave,
    Value(FcmResult),
    Values(Vec<FcmResult>)
}

impl FcmProcessorResult {
    pub fn implies_save_needed(&self) -> bool {
        match self {
            Self::Value(FcmResult::MessageSent { .. } | FcmResult::GroupHeaderAck { .. } | FcmResult::GroupHeader { .. } | FcmResult::PostRegisterInvitation { .. } | FcmResult::PostRegisterResponse { .. } | FcmResult::Deregistered { .. })=> true,
            Self::RequiresSave => true,
            _ => false
        }
    }
}

impl Try for FcmProcessorResult {
    type Output = Self;
    type Residual = Self;

    fn from_output(output: Self::Output) -> Self {
        output
    }

    fn branch(self) -> ControlFlow<Self::Residual, Self::Output> {
        match self {
            val @ Self::Err(..) => {
                ControlFlow::Break(val)
            }

            val => ControlFlow::Continue(val)
        }
    }
}

impl FromResidual for FcmProcessorResult {
    fn from_residual(residual: <Self as Try>::Residual) -> Self {
        residual
    }
}

impl<T> FromResidual<Option<T>> for FcmProcessorResult {
    fn from_residual(residual: Option<T>) -> Self {
        match residual {
            None => FcmProcessorResult::Err("FromResidual::None".into()),
            _ => FcmProcessorResult::Void
        }
    }
}

impl<T> FromResidual<Result<T, AccountError>> for FcmProcessorResult {
    fn from_residual(residual: Result<T, AccountError>) -> Self {
        match residual {
            Err(err) => FcmProcessorResult::Err(err.into_string()),
            _ => FcmProcessorResult::Void
        }
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
    PostRegisterInvitation { invite: PostRegisterInvitation },
    PostRegisterResponse { response: FcmPostRegisterResponse },
    Deregistered { requestor_cid: u64, ticket: u64, peer_cid: u64 }
}

pub struct InstanceParameter<'a> {
    pub(crate) client: Option<&'a Arc<Client>>,
    pub(crate) service_type: ExternalService,
    pub(crate) rtdb_client_cfg: Option<&'a RtdbClientConfig>,
}

impl InstanceParameter<'_> {
    pub async fn create_instance<R: Ratchet>(&self, endpoint_crypto: &PeerSessionCrypto<R>) -> Result<Box<dyn ExternalServiceChannel>, AccountError> {
        match self.service_type {
            ExternalService::Fcm => Ok(Box::new(FCMInstance::new(endpoint_crypto.fcm_keys.clone().ok_or_else(|| AccountError::Generic("FCM Selected, but target does not have FCM keys".to_string()))?, self.client.cloned().ok_or_else(|| AccountError::Generic("FCM selected, but sender is not loaded".to_string()))?)) as Box<dyn ExternalServiceChannel>),
            ExternalService::Rtdb => RtdbInstance::new_maybe_refresh(self.rtdb_client_cfg.ok_or_else(|| AccountError::Generic("RTDB selected, but sender is not loaded".to_string()))?).await.map(|r| Box::new(r) as Box<dyn ExternalServiceChannel>)
        }
    }
}

#[allow(unused_results)]
/// This constructs an independent single-threaded runtime to allow this to be called invariant to environmental tokio context
pub fn block_on_async<F: Future + Send + 'static>(fx: impl FnOnce() -> F + Send + 'static) -> Result<F::Output, AccountError<String>> where <F as Future>::Output: Send + 'static {
    // call in a unique thread to not cause a panic when running block_on
    /*
    std::thread::spawn(move || {
        /*static RT: parking_lot::Mutex<Option<Arc<tokio::runtime::Runtime>>> = parking_lot::const_mutex(None);

        let mut lock = RT.lock();
        if lock.is_none() {
            log::info!("Constructing current_thread RT ...");
            *lock = Some(Arc::new(tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|err| AccountError::Generic(err.to_string()))?));
        }

        log::info!("RT existent, now spawning ...");
        let rt = lock.clone().unwrap();
        std::mem::drop(lock);

         */

        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|err| AccountError::Generic(err.to_string()))?;
        rt.block_on(async move {
            log::info!("block_on_async spawned ...");
            Ok((fx)().await)
        })
    }).join().map_err(|_| AccountError::Generic("Error while joining thread".to_string()))?

     */
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|err| AccountError::Generic(err.to_string()))?;
    rt.block_on(async move {
        log::info!("block_on_async spawned ...");
        Ok((fx)().await)
    })
}