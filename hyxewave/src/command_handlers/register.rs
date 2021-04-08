use super::imports::*;
use hyxe_net::hdp::hdp_packet_processor::includes::SocketAddr;
use crate::primary_terminal::parse_custom_addr;
use hyxe_crypt::fcm::keys::FcmKeys;
use hyxe_crypt::prelude::SecBuffer;
use hyxe_net::hdp::hdp_server::UnderlyingProtocol;

#[derive(Debug, Serialize)]
pub enum RegisterResponse {
    Success(#[serde(serialize_with = "string")] u64, String),
    Failure(#[serde(serialize_with = "string")] u64, String)
}

pub async fn handle<'a>(matches: &ArgMatches<'a>, server_remote: &'a HdpServerRemote, ctx: &'a ConsoleContext, ffi_io: Option<FFIIO>) -> Result<Option<KernelResponse>, ConsoleError> {
    let target_addr = get_remote_addr(matches)?;
    let security_level = parse_security_level(matches)?;
    let ffi_mode = matches.is_present("ffi");
    let proposed_credentials = if ffi_mode {
        debug_assert!(ffi_io.is_some());
        handle_ffi(matches).await?
    } else {
        handle_console(ctx, &target_addr, security_level).await?
    };

    let fcm_keys = matches.value_of("fcm-token").map(|fcm_token| FcmKeys::new(matches.value_of("fcm-api-key").unwrap(), fcm_token));

    // check local
    if ctx.account_manager.get_cid_by_username(proposed_credentials.username.as_str()).await.map_err(|err| ConsoleError::Generic(err.into_string()))?.is_some() {
        return Err(ConsoleError::Generic(format!("username {} is already taken", proposed_credentials.username.as_str())));
    }

    let username = proposed_credentials.username.clone();

    // TODO choose between tls/tcp, default tcp
    let request = HdpServerRequest::RegisterToHypernode(target_addr, proposed_credentials, None, fcm_keys, security_level, UnderlyingProtocol::Tcp);
    let ticket = server_remote.unbounded_send(request)?;
    ctx.register_ticket(ticket, DO_REGISTER_EXPIRE_TIME_MS, 0, move |_ctx, _, response| {
        match response {
            PeerResponse::Ok(welcome_message_opt) => {
                if let Some(ref ffi_io) = ffi_io {
                    (ffi_io)(Ok(Some(KernelResponse::DomainSpecificResponse(DomainResponse::Register(RegisterResponse::Success(ticket.0, welcome_message_opt.unwrap_or(String::from("Register success"))))))))
                } else {
                    printfs!({
                        colour::white!("Registration for {}", username.as_str());
                        colour::green!(" SUCCESS!\n\n");
                        colour::green!("You may now login via ");
                        colour::dark_yellow!("connect {}\n", username.as_str());
                        if let Some(welcome_message) = welcome_message_opt {
                            colour::white_ln!("Hypernode welcome message: {}\n", &welcome_message);
                        }
                    });
                }
            }

            PeerResponse::Err(err_opt) => {
                if let Some(ref ffi_io) = ffi_io {
                    (ffi_io)(Ok(Some(KernelResponse::DomainSpecificResponse(DomainResponse::Register(RegisterResponse::Failure(ticket.0, err_opt.unwrap_or(String::from("Register failed"))))))))
                } else {
                    colour::dark_red_ln!("Registration failed. Please try again ... ({})\n", err_opt.unwrap_or(String::from("null")));
                }
            }

            _ => {
                if let Some(ref ffi_io) = ffi_io {
                    (ffi_io)(Ok(Some(KernelResponse::DomainSpecificResponse(DomainResponse::Register(RegisterResponse::Failure(ticket.0, String::from("Timeout on registration attempt. Please ensure that the node can be reached, then try again")))))))
                } else {
                    colour::dark_red_ln!("Registration failed. Please try again ...\n");
                }
            }
        }

        CallbackStatus::TaskComplete
    });

    Ok(Some(KernelResponse::ResponseTicket(ticket.0)))
}

/// Gets the value from the matches, otherwise reads it from stdin
#[allow(unused_results)]
async fn handle_ffi(matches: &ArgMatches<'_>) -> Result<ProposedCredentials, ConsoleError> {
    let full_name: String = matches.values_of("full_name").unwrap().collect::<Vec<&str>>().join(" ");
    let username = matches.value_of("username").unwrap();
    let password = matches.value_of("password").unwrap();

    let username = username.trim().to_string();
    let password = password.trim();

    hyxe_user::misc::check_credential_formatting(&username, Some(&password), &full_name).map_err(|err| ConsoleError::Generic(err.into_string()))?;

    Ok(ProposedCredentials::new_register(full_name.as_str(), username, SecBuffer::from(password)).await.map_err(|err| ConsoleError::Generic(err.into_string()))?)
}

async fn handle_console(ctx: &ConsoleContext, target_addr: &SocketAddr, security_level: SecurityLevel) -> Result<ProposedCredentials, ConsoleError> {
    let mut username = INPUT_ROUTER.read_line(ctx, Some(|| colour::green!("Proposed username: ")));
    username = username.trim().to_string();

    // TODO: Change this to getting cid instead later
    if ctx.account_manager.get_client_by_username(&username).await.map_err(|err| ConsoleError::Generic(err.into_string()))?.is_some() {
        return Err(ConsoleError::Generic(format!("User {} already exists locally", username)))
    }

    let full_name = INPUT_ROUTER.read_line(ctx, Some(|| colour::green!("Full name: ")));

    let password_input_0 = INPUT_ROUTER.read_password(ctx, Some(|| colour::green!("Proposed password: ")));
    let password_input_0 = password_input_0.trim().as_bytes().to_vec();

    let password_input_1_str = INPUT_ROUTER.read_password(ctx, Some(|| colour::green!("Verify password: ")));
    let password_input_1 = password_input_1_str.trim().as_bytes().to_vec();

    if password_input_0 != password_input_1 {
        return Err(ConsoleError::Default("Passwords do not match"));
    }

    hyxe_user::misc::check_credential_formatting(&username, Some(&password_input_1_str), &full_name).map_err(|err| ConsoleError::Generic(err.into_string()))?;

    printf_ln!(colour::yellow!("Server: {}\nFull name: {}\nUsername: {}\nSecurity Level: {:?}", target_addr, &full_name, &username, security_level));

    Ok(ProposedCredentials::new_register(full_name, username, password_input_0.into()).await.map_err(|err| ConsoleError::Generic(err.into_string()))?)
}

/// Now works with ipv6 AND ipv4
fn get_remote_addr(matches: &ArgMatches) -> Result<SocketAddr, ConsoleError> {
    let target_addr = matches.value_of("target").unwrap();
    parse_custom_addr(target_addr)
}