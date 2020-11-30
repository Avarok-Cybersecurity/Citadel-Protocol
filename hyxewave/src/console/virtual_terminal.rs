use clap::App;
use lazy_static::*;
use parking_lot::{Mutex, MutexGuard};
#[cfg(not(target_os = "windows"))]
use termion::input::TermReadEventsAndRaw;
//use tokio::io::AsyncBufReadExt;
use tokio::stream::StreamExt;

use hyxe_net::hdp::hdp_server::HdpServerRemote;

use crate::console::console_context::ConsoleContext;
use crate::console::input_handler::InputRouter;
use crate::console::virtual_terminal::clap_commands::setup_clap;
use crate::console_error::ConsoleError;
use crate::ffi::{FFIIO, KernelResponse};
use hyxe_crypt::sec_string::SecString;

lazy_static! {
    pub static ref CLAP_APP: AppThreadSafe = AppThreadSafe(Mutex::new(setup_clap()));
}

pub async fn terminal_future(server_remote: HdpServerRemote, ctx: ConsoleContext) -> Result<(), ConsoleError> {
    let (input_tx, mut input_rx) = tokio::sync::mpsc::channel::<SecString>(2);
    INPUT_ROUTER.print_prompt(true, &ctx);
    spawn_input_listener(input_tx, ctx.clone());

    while let Some(input) = input_rx.next().await {
        let trimmed = input.trim();
        let mut was_cleared = false;
        if trimmed.len() != 0 {
            let parts = trimmed.split(" ").collect::<Vec<&str>>();
            was_cleared = parts.get(0).map(|res| *res == "clear").unwrap_or(false);
            if let Err(err) = handle(CLAP_APP.0.lock(), parts, &server_remote, &ctx, None) {
                printf!(colour::white_ln!("\r{}", err.into_string()));
            }
        }

        if !was_cleared {
            INPUT_ROUTER.print_prompt(false, &ctx)
        }
    }

    Ok(())
}

pub static INPUT_ROUTER: InputRouter = InputRouter::new();

#[allow(unused_results)]
#[cfg(target_os = "windows")]
fn spawn_input_listener(input_tx: tokio::sync::mpsc::Sender<SecString>, ctx: ConsoleContext) {
    INPUT_ROUTER.register_clap_sender(&input_tx);
    std::thread::spawn(move || {
        loop {
            if let Ok(key) = crossterm::event::read() {
                match key {
                    crossterm::event::Event::Key(evt) => {
                        match evt.code {
                            crossterm::event::KeyCode::Backspace => {
                                INPUT_ROUTER.backspace(&ctx)
                            }

                            crossterm::event::KeyCode::Enter => {
                                if !INPUT_ROUTER.send_internal_buffer() {
                                    log::warn!("Error sending input. Closing program");
                                    std::process::exit(-1);
                                }
                            }

                            crossterm::event::KeyCode::Up => {
                                INPUT_ROUTER.on_vertical_key_pressed(true, &ctx);
                            }

                            crossterm::event::KeyCode::Down => {
                                INPUT_ROUTER.on_vertical_key_pressed(false, &ctx);
                            }

                            crossterm::event::KeyCode::Right => {
                                INPUT_ROUTER.on_horizantal_key_pressed(true);
                            }

                            crossterm::event::KeyCode::Left => {
                                INPUT_ROUTER.on_horizantal_key_pressed(false);
                            }

                            crossterm::event::KeyCode::Delete => {
                                INPUT_ROUTER.on_delete_key_pressed(&ctx)
                            }

                            crossterm::event::KeyCode::BackTab => {
                                INPUT_ROUTER.on_tab_pressed();
                            }

                            crossterm::event::KeyCode::Char(val) => {
                                if evt.modifiers == crossterm::event::KeyModifiers::CONTROL {
                                    if val == 'c' || val == 'z' {
                                        crate::shutdown_sequence(-1);
                                    }
                                } else {
                                    INPUT_ROUTER.push(val, &ctx);
                                }
                            }

                            _ => {}
                        }
                    }

                    _ => {}
                }
            }
        }
    });
}


#[cfg(not(target_os = "windows"))]
fn spawn_input_listener(input_tx: tokio::sync::mpsc::Sender<SecString>, ctx: ConsoleContext) {
    INPUT_ROUTER.register_clap_sender(&input_tx);
    std::thread::spawn(move || {
        //let stdout = std::io::stdout().into_raw_mode().unwrap();
        //stdout.activate_raw_mode().unwrap();
        // raw mode will allow linux to read the keys one by one
        INPUT_ROUTER.toggle_raw_mode(true);
        let stdin = std::io::stdin();
        let mut iter = stdin.events_and_raw();
        loop {
            while let Some(key) = iter.next() {
                if let Ok(key) = key {
                    match key.0 {
                        termion::event::Event::Key(termion::event::Key::Backspace) => {
                            INPUT_ROUTER.backspace(&ctx)
                        }

                        termion::event::Event::Key(termion::event::Key::Char('\n')) => {
                            if !INPUT_ROUTER.send_internal_buffer() {
                                log::warn!("Error sending input. Closing program");
                                std::process::exit(-1);
                            }
                        }

                        termion::event::Event::Key(termion::event::Key::Up) => {
                            INPUT_ROUTER.on_vertical_key_pressed(true, &ctx);
                        }

                        termion::event::Event::Key(termion::event::Key::Down) => {
                            INPUT_ROUTER.on_vertical_key_pressed(false, &ctx);
                        }

                        termion::event::Event::Key(termion::event::Key::Right) => {
                            INPUT_ROUTER.on_horizantal_key_pressed(true);
                        }

                        termion::event::Event::Key(termion::event::Key::Left) => {
                            INPUT_ROUTER.on_horizantal_key_pressed(false);
                        }

                        termion::event::Event::Key(termion::event::Key::Delete) => {
                            INPUT_ROUTER.on_delete_key_pressed(&ctx)
                        }

                        termion::event::Event::Key(termion::event::Key::BackTab) => {
                            INPUT_ROUTER.on_tab_pressed();
                        }

                        termion::event::Event::Key(termion::event::Key::Ctrl(val)) => {
                            if val == 'c' || val == 'z' {
                                crate::shutdown_sequence(-1);
                            }
                        }

                        termion::event::Event::Key(termion::event::Key::Char(val)) => {
                            INPUT_ROUTER.push(val, &ctx);
                        }

                        _ => {}
                    }
                }
            }
        }
    });
}

pub mod clap_commands {
    use clap::{App, AppSettings, Arg, SubCommand};

    pub fn setup_clap() -> App<'static, 'static> {
        setup_clap_main(setup_subcommands())
    }

    fn setup_subcommands() -> Vec<App<'static, 'static>> {
        let mut subcommands = Vec::new();
        subcommands.push(setup_cd_command());
        subcommands.push(setup_ls_command());
        subcommands.push(setup_send_command());
        subcommands.push(setup_switch_command());
        subcommands.push(setup_list_command());
        subcommands.push(setup_quit_command());
        subcommands.push(setup_connect_subcommand());
        subcommands.push(setup_register_subcommand());
        subcommands.push(setup_list_local_command());
        subcommands.push(setup_disconnect_command());
        subcommands.push(setup_deregister_command());
        subcommands.push(setup_clear_command());
        subcommands.push(setup_peer_command());
        subcommands.push(setup_group_command());
        subcommands
    }

    fn setup_clap_main(subcommands: Vec<App<'static, 'static>>) -> App<'static, 'static> {
        App::new("HyxeWave Virtual Console")
            // Assumes zeroth argument is not the binary name
            .setting(AppSettings::NoBinaryName)
            .setting(AppSettings::TrailingVarArg)
            .version(crate::constants::VERSION)
            .author("Thomas Philip Braun <braun@legionengineering.net>")
            .about("A Virtual CLI for the post-quantum distributed networking protocol (project httpx://)")
            .subcommands(subcommands)
        //.arg(Arg::with_name("command").required(true).index(1))
    }

    fn setup_cd_command() -> App<'static, 'static> {
        SubCommand::with_name("cd").about("Changes directory w.r.t the local filesystem")
            .arg(Arg::with_name("dir").required(true).takes_value(true).multiple(true))
    }

    fn setup_ls_command() -> App<'static, 'static> {
        SubCommand::with_name("ls").about("lists the current directory")
            .alias("dir")
    }

    fn setup_clear_command() -> App<'static, 'static> {
        SubCommand::with_name("clear").alias("cls").help("Clears the screen")
    }

    fn setup_send_command() -> App<'static, 'static> {
        SubCommand::with_name("send")
            .arg(Arg::with_name("security").display_order(1).long("security").short("sl").required(false).takes_value(true).default_value("0").help("Sets the security level for the transmission. 0 is low, 4 is divine"))
            .arg(Arg::with_name("message").required(true).takes_value(true).display_order(2).multiple(true))
    }

    fn setup_list_command() -> App<'static, 'static> {
        SubCommand::with_name("list-sessions")
            .help("Lists all personal and impersonal active sessions connected to this node")
            .arg(Arg::with_name("impersonal").long("impersonal").short("i").required(false).help("Lists only inbound impersonal sessions"))
            .arg(Arg::with_name("personal").conflicts_with("impersonal").long("personal").short("p").required(false).help("Lists only outbound personal sessions"))
    }

    fn setup_list_local_command() -> App<'static, 'static> {
        SubCommand::with_name("list-accounts")
            .help("Lists all impersonal clients registered to this node, as well as personal registrations")
            .arg(Arg::with_name("impersonal").long("impersonal").short("i").required(false).help("Lists only impersonal registrations"))
            .arg(Arg::with_name("personal").conflicts_with("impersonal").long("personal").short("p").required(false).help("Lists only personal registrations"))
    }

    fn setup_quit_command() -> App<'static, 'static> {
        SubCommand::with_name("quit").visible_alias("exit")
            .arg(Arg::with_name("force_quit").long("force").short("f").required(false).help("Force closes the application, without executing the safe disconnect subroutines"))
    }

    fn setup_switch_command() -> App<'static, 'static> {
        SubCommand::with_name("switch").help("Switches the focused session to the desired username. Enables the use of the send and peer commands")
            .arg(Arg::with_name("session").takes_value(true).required(true).help("Session username"))
            .arg(Arg::with_name("command").long("cmd").required(false).takes_value(true).multiple(true).help("An optional command to run after switching to a new CID (runs with new context CID)"))
    }

    fn setup_peer_command() -> App<'static, 'static> {
        SubCommand::with_name("peer")
            .subcommand(SubCommand::with_name("list").about("Fetch the set of peers that exist on the client network account's HyperLAN"))
            .subcommand(SubCommand::with_name("mutuals").about("Fetch the set of peers to whom your client network account is consented to connect with"))
            .subcommand(SubCommand::with_name("channels").about("Returns a list of active channels for the active CID"))
            .subcommand(SubCommand::with_name("disconnect").about("Disconnect from a target peer")
                .arg(Arg::with_name("target_cid").required(true).takes_value(true).help("The target CID/username")))
            .subcommand(SubCommand::with_name("post-register").about("Post a registration request to a target CID")
                .arg(Arg::with_name("target_cid").required(true).takes_value(true).help("The target CID")))
            .subcommand(SubCommand::with_name("post-connect").about("Post a connect request to a target CID/Username")
                .arg(Arg::with_name("target_cid").required(true).takes_value(true)))
            .subcommand(SubCommand::with_name("accept-register").about("Consent to a registration request. Check the mailbox to see a list of registrations requesting consent")
                .arg(Arg::with_name("mail_id").required(true).help("Mail item ID")))
            .subcommand(SubCommand::with_name("accept-connect").about("Consent to a connection request. Check the mailbox to see a list of connections requesting consent")
                .arg(Arg::with_name("mail_id").required(true).help("Mail item ID")))
            .subcommand(SubCommand::with_name("mail").about("Checks the mail (connection/registration consent requests, events, etc)")
                .arg(Arg::with_name("mail_cmd").required(true).possible_values(&["print", "clear"])))
            .subcommand(SubCommand::with_name("deregister").about("Deregistered a target client from the context user")
                .arg(Arg::with_name("target_cid").required(true).takes_value(true)))
            .subcommand(SubCommand::with_name("send").about("Sends a message to a target peer using the context user")
                .arg(Arg::with_name("target_cid").required(true).takes_value(true))
                .arg(Arg::with_name("message").required(true).takes_value(true).multiple(true))
                .arg(Arg::with_name("security").display_order(3).long("security").short("s").required(false).takes_value(true).default_value("0").help("Sets the security level for the transmission. 0 is low, 4 is divine")))
            .subcommand(SubCommand::with_name("transfer").about("Send a target file to a target peer")
                .arg(Arg::with_name("target_cid").required(true).takes_value(true))
                .arg(Arg::with_name("file_path").required(true).takes_value(true).multiple(true))
                .arg(Arg::with_name("chunk_size").long("chunk-size").required(false).takes_value(true).help("Specifies the chunk size (in bytes) of the file. If absent, default is used. Must be at least 1024 bytes in size")))
    }

    fn setup_group_command() -> App<'static, 'static> {
        SubCommand::with_name("group")
            .subcommand(SubCommand::with_name("create").about("Creates a new message group")
                .arg(Arg::with_name("target_cids").required(false).multiple(true).value_delimiter(",")))
            .subcommand(SubCommand::with_name("end").about("Ends a specific group (takes group ID)")
                .arg(Arg::with_name("gid").required(true).takes_value(true)))
            .subcommand(SubCommand::with_name("add").about("Adds a specific set of peers (comma delimited)")
                .arg(Arg::with_name("gid").required(true).takes_value(true))
                .arg(Arg::with_name("target_cids").required(true).multiple(true).value_delimiter(",")))
            .subcommand(SubCommand::with_name("kick").about("Kicks a specific set of peers (comma delimited)")
                .arg(Arg::with_name("gid").required(true).takes_value(true))
                .arg(Arg::with_name("target_cids").required(true).multiple(true).value_delimiter(",")))
            .subcommand(SubCommand::with_name("send").about("Sends a specific message to the target group")
                .arg(Arg::with_name("gid").required(true).takes_value(true))
                .arg(Arg::with_name("message").takes_value(true).required(true).multiple(true)))
            .subcommand(SubCommand::with_name("list").about("List the concurrent group broadcasts"))
            .subcommand(SubCommand::with_name("invites").about("Prints the pending group invites"))
            .subcommand(SubCommand::with_name("accept-invite").about("Accepts an invite (takes invite ID)")
                .arg(Arg::with_name("mid").required(true).takes_value(true)))
            .subcommand(SubCommand::with_name("leave").about("Leaves a specific group")
                .arg(Arg::with_name("gid").required(true).takes_value(true)))
    }

    fn setup_connect_subcommand() -> App<'static, 'static> {
        SubCommand::with_name("connect")
            .after_help("example: connect john.doe")
            .about("Initiate a quantum-secure connection to the target address. Requires registration before connecting")
            .arg(Arg::with_name("security")
                .long("security")
                .short("s")
                .help("sets the session security level (0=lowest, 4=highest)")
                .takes_value(true)
                .default_value("0"))
            .arg(Arg::with_name("username")
                .help("Client username")
                .takes_value(true)
                .required(true))
            // The remaining arguments are for the FFI
            .arg(Arg::with_name("ffi")
                .required(false)
                .takes_value(false)
                .long("ffi")
                .requires_all(&["password"]))
            .arg(Arg::with_name("password")
                .long("password")
                .takes_value(true)
                .required(false))
            .arg(Arg::with_name("qudp")
                .long("qudp")
                .takes_value(false)
                .required(false)
                .help("Enables the use of the experimental MQ-UDP for messaging"))
    }

    fn setup_register_subcommand() -> App<'static, 'static> {
        SubCommand::with_name("register")
            .after_help("example: register 192.168.2.1 OR register 192.168.2.1:1234")
            .about("Register to a target address using advanced post-quantum cryptography")
            .arg(Arg::with_name("target")
                .help("Destination address")
                .takes_value(true)
                .required(true))
            // The remaining arguments are for the FFI
            .arg(Arg::with_name("ffi")
                .required(false)
                .takes_value(false)
                .long("ffi")
                .requires_all(&["full_name", "username", "password"]))
            .arg(Arg::with_name("full_name")
                .long("fullname")
                .takes_value(true)
                .required(false)
                .multiple(true))
            .arg(Arg::with_name("username")
                .long("username")
                .takes_value(true)
                .required(false))
            .arg(Arg::with_name("password")
                .long("password")
                .takes_value(true)
                .required(false))
    }


    fn setup_deregister_command() -> App<'static, 'static> {
        SubCommand::with_name("deregister")
            .long_about("Deregisters a CNAC between a HyperLAN Client and HyperLAN Server, or deregisters a mutually-agreed-connection between a HyperLAN Client and a HyperLAN Peer")
            .after_help("Example: 'deregister cnac john.doe'. If you wish to deregister from a peer: 'deregister peer john.doe john.does.friend`")
            .arg(Arg::with_name("purge").long("purge").required(false).takes_value(false).help("Removes all the accounts locally"))
            .arg(Arg::with_name("account").help("The username that will be removed, or, the account from which a peer will be removed").takes_value(true).required_unless("purge"))
            .arg(Arg::with_name("peer_target").takes_value(true).required_if("type", "peer").help("The target peer"))
            .arg(Arg::with_name("force").long("force").short("f").required(false).help("Force removes the account locally even if the proper deregistration sequence failed"))
    }

    fn setup_disconnect_command() -> App<'static, 'static> {
        SubCommand::with_name("disconnect").alias("dc")
            .arg(Arg::with_name("account").required_unless("all").takes_value(true).help("The username of the session that ought to be disconnected"))
            .arg(Arg::with_name("all").long("all").short("a").required(false).takes_value(false).help("disconnect all concurrent sessions"))
    }
}

pub fn handle<'a, A: AsRef<[&'a str]>>(mut clap: MutexGuard<'_, App<'static, 'static>>, parts: A, server_remote: &'a HdpServerRemote, ctx: &'a ConsoleContext, ffi_io: Option<FFIIO>) -> Result<Option<KernelResponse>, ConsoleError> {
    let matches = clap.get_matches_from_safe_borrow(parts.as_ref()).map_err(|err| ConsoleError::Generic(err.message))?;

    if let Some(_matches) = matches.subcommand_matches("clear") {
        INPUT_ROUTER.print_prompt(true, ctx);
        return Ok(None);
    }

    if let Some(matches) = matches.subcommand_matches("cd") {
        return crate::command_handlers::os::cd::handle(matches, ctx, ffi_io);
    }

    if let Some(_matches) = matches.subcommand_matches("ls") {
        return crate::command_handlers::os::ls::handle(ctx, ffi_io);
    }

    if let Some(matches) = matches.subcommand_matches("send") {
        return crate::command_handlers::send::handle(matches, server_remote, ctx);
    }

    if let Some(matches) = matches.subcommand_matches("quit") {
        return crate::command_handlers::quit::handle(matches, server_remote, ctx);
    }

    if let Some(matches) = matches.subcommand_matches("list-sessions") {
        return crate::command_handlers::list_sessions::handle(matches, server_remote, ctx, ffi_io);
    }

    if let Some(matches) = matches.subcommand_matches("switch") {
        return crate::command_handlers::switch::handle(matches, server_remote, ctx, ffi_io, clap);
    }

    if let Some(matches) = matches.subcommand_matches("connect") {
        return crate::command_handlers::connect::handle(matches, server_remote, ctx, ffi_io);
    }

    if let Some(matches) = matches.subcommand_matches("register") {
        return crate::command_handlers::register::handle(matches, server_remote, ctx, ffi_io);
    }

    if let Some(matches) = matches.subcommand_matches("list-accounts") {
        return crate::command_handlers::list_accounts::handle(matches, server_remote, ctx, ffi_io);
    }

    if let Some(matches) = matches.subcommand_matches("deregister") {
        return crate::command_handlers::deregister::handle(matches, server_remote, ctx)
            .map(|_| Some(KernelResponse::Confirmation));
    }

    if let Some(matches) = matches.subcommand_matches("disconnect") {
        return crate::command_handlers::disconnect::handle(matches, server_remote, ctx)
            .map(|_| Some(KernelResponse::Confirmation));
    }

    if let Some(matches) = matches.subcommand_matches("peer") {
        return crate::command_handlers::peer::handle(matches, server_remote, ctx, ffi_io);
    }

    if let Some(matches) = matches.subcommand_matches("group") {
        return crate::command_handlers::group::handle(matches, server_remote, ctx)
            .map(|_| Some(KernelResponse::Confirmation));
    }

    Ok(None)
}

pub struct AppThreadSafe(pub Mutex<App<'static, 'static>>) where Self: Send + Sync;

unsafe impl Send for AppThreadSafe {}
unsafe impl Sync for AppThreadSafe {}