use tokio::stream::StreamExt;

use super::imports::*;

#[derive(Debug, Serialize)]
pub enum ConnectResponse {
    // ticket, implicated cid, message
    Success(u64, u64, String),
    Failure(u64, u64, String),
}

#[allow(unused_results)]
pub fn handle<'a>(matches: &ArgMatches<'a>, server_remote: &'a HdpServerRemote, ctx: &'a ConsoleContext, ffi_io: Option<FFIIO>) -> Result<Option<KernelResponse>, ConsoleError> {
    let username = matches.value_of("username").unwrap();
    let tcp_only = !matches.is_present("qudp");
    let security_level = parse_security_level(matches)?;
    let peer_cnac = ctx.account_manager.get_client_by_username(username).ok_or(ConsoleError::Default("Username does not map to a local account. Please consider registering first"))?;

    if !peer_cnac.is_personal() {
        return Err(ConsoleError::Generic(format!("Client {} is an impersonal account. Connection requests may only be initiated with personal accounts", username)));
    }

    let read = peer_cnac.read();
    let cid = read.cid;

    if ctx.user_is_connected(Some(cid), None) {
        return Err(ConsoleError::Generic(format!("User {} is already an active session ...", username)));
    }

    let full_name = read.full_name.clone();
    let adjacent_nac = read.adjacent_nac.as_ref().ok_or(ConsoleError::Default("Adjacent NAC missing from CNAC. Corrupt. Please remove CNAC"))?;
    let adjacent_socket = adjacent_nac.get_addr_blocking(true).ok_or(ConsoleError::Default("Adjacent NAC does not have an IP address. Corrupt. Please remove CNAC"))?;
    let nonce = read.password_hash.as_slice();
    let proposed_credentials = get_proposed_credentials(matches, ctx, username, nonce,adjacent_socket.ip(), security_level, cid, full_name)?;

    let request = HdpServerRequest::ConnectToHypernode(adjacent_socket, cid, proposed_credentials, security_level, None, None, Some(tcp_only));
    let ticket = server_remote.unbounded_send(request);

    let tx = parking_lot::Mutex::new(None);
    if ffi_io.is_none() {
        // display a ticker
        println!();
        let (tx_oneshot, mut rx_oneshot) = tokio::sync::oneshot::channel::<()>();
        tx.lock().replace(tx_oneshot);
        tokio::task::spawn(async move {
            let mut iter = tokio::time::interval(Duration::from_millis(100));
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
    ctx.register_ticket(ticket, DO_CONNECT_EXPIRE_TIME_MS, cid, move |ctx, _, response| {
        tx.lock().take().map(|sender| sender.send(()));
        match response {
            PeerResponse::Ok(welcome_message_opt) => {
                if let Some(ref ffi_io) = ffi_io {
                    (ffi_io)(Ok(Some(KernelResponse::DomainSpecificResponse(DomainResponse::Connect(ConnectResponse::Success(ticket.0, cid, welcome_message_opt.unwrap_or(String::from("Connect success"))))))))
                } else {
                    printfs!({
                        colour::green_ln!("\nConnection forged for {} ({})! You may now begin message passing within the HyperLAN", &username, cid);
                        if let Some(welcome_message) = welcome_message_opt {
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
            }

            PeerResponse::Err(err_opt) => {
                if let Some(ref ffi_io) = ffi_io {
                    (ffi_io)(Ok(Some(KernelResponse::DomainSpecificResponse(DomainResponse::Connect(ConnectResponse::Failure(ticket.0, cid, err_opt.unwrap_or(String::from("Unable to connect"))))))))
                } else {
                    printf_ln!(colour::red!("\nConnection failed: {}\n", err_opt.unwrap_or(String::from("Please try again later"))))
                }
            }

            _ => {
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

fn get_proposed_credentials(matches: &ArgMatches<'_>, ctx: &ConsoleContext, username: &str, nonce: &[u8], adjacent_ip: IpAddr, security_level: SecurityLevel, cid: u64, full_name: String) -> Result<ProposedCredentials, ConsoleError> {
    if matches.is_present("ffi") {
        let password = matches.value_of("password").unwrap();
        Ok(ProposedCredentials::new_unchecked(full_name, username, SecVec::new(Vec::from(password)), Some(nonce)))
    } else {
        colour::yellow!("\n{} ", &full_name);
        colour::white!("attempting to connect to ");
        colour::green!("{}@", username);
        colour::yellow!("{} ", adjacent_ip);
        colour::white!("with ");
        colour::yellow!("{} ", security_level.value());
        colour::white!("security level (CID: ");
        colour::yellow!("{}", cid);
        colour::white!(")\n\n");

        //colour::white_ln!("{} attempting to connect to {}@{} with {} security level (CID: {})", &full_name, username, adjacent_ip, security_level.value(), cid);
        let password_input = INPUT_ROUTER.read_password(ctx, Some(|| {
            colour::white!("Enter password: ");
        }));

        let password_input = password_input.into_bytes();
        let proposed_credentials = ProposedCredentials::new_unchecked(&full_name, username, SecVec::new(password_input), Some(nonce));
        colour::white_ln!("Attempting to connect to HyperNode ...");
        Ok(proposed_credentials)
    }
}