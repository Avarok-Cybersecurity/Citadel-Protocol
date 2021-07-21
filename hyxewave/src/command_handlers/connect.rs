use tokio_stream::StreamExt;

use super::imports::*;
use hyxe_crypt::fcm::keys::FcmKeys;
use hyxe_net::hdp::hdp_server::{ConnectMode, SecrecyMode};
use hyxe_crypt::prelude::SecBuffer;
use hyxe_crypt::prelude::algorithm_dictionary::{KemAlgorithm, EncryptionAlgorithm};
use hyxe_net::hdp::misc::session_security_settings::{SessionSecuritySettingsBuilder, SessionSecuritySettings};
use std::convert::TryFrom;
use hyxe_user::prelude::ConnectionInfo;
use hyxe_user::external_services::{PostLoginObject, RtdbConfig};
use crate::ticket_event::CustomPayload;
use hyxe_net::hdp::peer::peer_layer::UdpMode;

#[derive(Debug, Serialize)]
pub enum ConnectResponse {
    // ticket, implicated cid, message
    Success(#[serde(serialize_with = "string")] u64, #[serde(serialize_with = "string")] u64, String, String, RtdbConfig),
    Failure(#[serde(serialize_with = "string")] u64,#[serde(serialize_with = "string")] u64, String),
}

pub struct ConnectResponseReceived {
    pub success: bool,
    pub message: Option<String>,
    pub login_object: PostLoginObject
}

#[allow(unused_results)]
pub async fn handle<'a>(matches: &ArgMatches<'a>, server_remote: &'a mut HdpServerRemote, ctx: &'a ConsoleContext, ffi_io: Option<FFIIO>) -> Result<Option<KernelResponse>, ConsoleError> {
    let username = matches.value_of("username").unwrap();
    let udp = if matches.is_present("qudp") { UdpMode::Enabled } else { UdpMode::Disabled };
    let force_login = matches.is_present("force");

    let secrecy_mode = matches.is_present("pfs").then(|| SecrecyMode::Perfect);
    let kem = parse_kem(matches)?;
    let enx = parse_enx(matches)?;

    let security_level = parse_security_level(matches)?;
    let fcm_keys = matches.value_of("fcm-token").map(|fcm_token| FcmKeys::new(matches.value_of("fcm-api-key").unwrap(), fcm_token));
    let kat = maybe_parse_uint(matches, "keep_alive_timeout")?;
    let peer_cnac = ctx.account_manager.get_client_by_username(username).await.map_err(|err| ConsoleError::Generic(err.into_string()))?.ok_or(ConsoleError::Default("Username does not map to a local account. Please consider registering first"))?;

    if !peer_cnac.is_personal() {
        return Err(ConsoleError::Generic(format!("Client {} is an impersonal account. Connection requests may only be initiated with personal accounts", username)));
    }

    let read = peer_cnac.read();
    let cid = read.cid;

    if ctx.user_is_connected(Some(cid), None).await {
        return Err(ConsoleError::Generic(format!("User {} is already an active session ...", username)));
    }

    let full_name = read.full_name.clone();
    let adjacent_nac = read.adjacent_nac.clone();
    let conn_info = adjacent_nac.get_conn_info().ok_or(ConsoleError::Default("Adjacent NAC does not have an IP address. Corrupt. Please remove CNAC"))?;
    let connect_mode = matches.is_present("fetch").then(|| ConnectMode::Fetch {force_login}).unwrap_or(ConnectMode::Standard{force_login});
    let params = get_crypto_params(secrecy_mode, kem, enx, security_level);

    std::mem::drop(read);

    let proposed_credentials = get_proposed_credentials(matches, ctx, username, &peer_cnac, conn_info, security_level, cid, full_name).await?;

    let request = HdpServerRequest::ConnectToHypernode(cid, proposed_credentials, connect_mode, fcm_keys, udp, kat, params);
    let ticket = server_remote.send(request).await?;

    let tx = parking_lot::Mutex::new(None);
    if ffi_io.is_none() {
        // display a ticker
        println!();
        let (tx_oneshot, mut rx_oneshot) = tokio::sync::oneshot::channel::<()>();
        tx.lock().replace(tx_oneshot);
        tokio::task::spawn(async move {
            let mut iter = tokio_stream::wrappers::IntervalStream::new(tokio::time::interval(Duration::from_millis(100)));
            while let Some(_) = iter.next().await {
                match rx_oneshot.try_recv() {
                    Ok(_) | Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                        return;
                    }

                    _ => {
                        // still not done
                    }
                }

                colour::yellow!("...");
            }
        });
    }

    let username = username.to_string();
    ctx.register_ticket_custom_response(ticket, DO_CONNECT_EXPIRE_TIME_MS, cid, move |ctx, _, response| {
        tx.lock().take().map(|sender| sender.send(()));
        match response {
            CustomPayload::Connect(ConnectResponseReceived { success, message, login_object }) => {
                if success {
                    if let Some(ref ffi_io) = ffi_io {
                        (ffi_io)(Ok(Some(KernelResponse::DomainSpecificResponse(DomainResponse::Connect(ConnectResponse::Success(ticket.0, cid, message.unwrap_or(String::from("Connect success")), login_object.google_auth_jwt.unwrap_or_default(), login_object.rtdb.unwrap_or_default()))))))
                    } else {
                        log::info!("LoginObject: {:?}", &login_object);
                        printfs!({
                        colour::green_ln!("\nConnection forged for {} ({})! You may now begin message passing within the HyperLAN", &username, cid);
                        if let Some(welcome_message) = message {
                            colour::white!("Hypernode welcome message: ");
                            colour::yellow!("{}\n\n", &welcome_message);
                        } else {
                            println!("\n");
                        }
                    });

                        *ctx.active_user.write() = username.clone();
                        ctx.set_active_cid(cid);

                        ctx.in_personal.store(true, Ordering::SeqCst);
                    }
                } else {
                    if let Some(ref ffi_io) = ffi_io {
                        (ffi_io)(Ok(Some(KernelResponse::DomainSpecificResponse(DomainResponse::Connect(ConnectResponse::Failure(ticket.0, cid, message.unwrap_or(String::from("Unable to connect"))))))))
                    } else {
                        printf_ln!(colour::red!("\nConnection failed: {}\n", message.unwrap_or(String::from("Please try again later"))))
                    }
                }
            }

            _ => {
                log::error!("Invalid custom payload response under connect");

                if let Some(ref ffi_io) = ffi_io {
                    (ffi_io)(Ok(Some(KernelResponse::DomainSpecificResponse(DomainResponse::Connect(ConnectResponse::Failure(ticket.0, cid, String::from("Unable to connect")))))))
                } else {
                    printf_ln!(colour::red!("\nConnection failed. Please try again ...\n\n"));
                }
            }
        }

        CallbackStatus::TaskComplete
    });

    Ok(Some(KernelResponse::ResponseTicket(ticket.0)))
}

async fn get_proposed_credentials(matches: &ArgMatches<'_>, ctx: &ConsoleContext, username: &str, cnac: &ClientNetworkAccount, conn_info: ConnectionInfo, security_level: SecurityLevel, cid: u64, full_name: String) -> Result<ProposedCredentials, ConsoleError> {
    if matches.is_present("ffi") {
        let password = matches.value_of("password").unwrap();
        Ok(cnac.hash_password_as_client(SecBuffer::from(password.as_bytes())).await.map_err(|err| ConsoleError::Generic(err.into_string()))?)
    } else {
        colour::yellow!("\n{} ", &full_name);
        colour::white!("attempting to connect to ");
        colour::green!("{}@", username);
        colour::yellow!("{} ", conn_info);
        colour::white!("with ");
        colour::yellow!("{} ", security_level.value());
        colour::white!("security level (CID: ");
        colour::yellow!("{}", cid);
        colour::white!(")\n\n");

        //colour::white_ln!("{} attempting to connect to {}@{} with {} security level (CID: {})", &full_name, username, adjacent_ip, security_level.value(), cid);
        let password_input = INPUT_ROUTER.read_password(ctx, Some(|| {
            colour::white!("Enter password: ");
        }));

        let password_input = SecBuffer::from(password_input.into_bytes());
        let proposed_credentials = cnac.hash_password_as_client(password_input).await.map_err(|err| ConsoleError::Generic(err.into_string()))?;
        colour::white_ln!("Attempting to connect to HyperNode ...");
        Ok(proposed_credentials)
    }
}

fn maybe_parse_uint(arg_matches: &ArgMatches<'_>, field: &str) -> Result<Option<u32>, ConsoleError> {
    if let Some(val) = arg_matches.value_of(field) {
        let val = u32::from_str(val).map_err(|err| ConsoleError::Generic(err.to_string()))?;
        Ok(Some(val))
    } else {
        Ok(None)
    }
}

pub(crate) fn parse_kem(arg_matches: &ArgMatches<'_>) -> Result<Option<KemAlgorithm>, ConsoleError> {
    if let Some(value) = maybe_parse_uint(arg_matches, "kem")? {
        let kem = KemAlgorithm::try_from(u8::try_from(value)?).map_err(|_| ConsoleError::Default("Invalid KEM selection"))?;
        Ok(Some(kem))
    } else {
        Ok(None)
    }
}

pub(crate) fn parse_enx(arg_matches: &ArgMatches<'_>) -> Result<Option<EncryptionAlgorithm>, ConsoleError> {
    if let Some(value) = maybe_parse_uint(arg_matches, "enx")? {
        let kem = EncryptionAlgorithm::try_from(u8::try_from(value)?).map_err(|_|ConsoleError::Default("Invalid ENX selection"))?;
        Ok(Some(kem))
    } else {
        Ok(None)
    }
}

pub(crate) fn get_crypto_params(mode: Option<SecrecyMode>, kem: Option<KemAlgorithm>, enx: Option<EncryptionAlgorithm>, security_level: SecurityLevel) -> SessionSecuritySettings {
    SessionSecuritySettingsBuilder::default()
        .with_secrecy_mode(mode.unwrap_or_default())
        .with_crypto_params(kem.unwrap_or_default() + enx.unwrap_or_default())
        .with_security_level(security_level)
        .build()
}