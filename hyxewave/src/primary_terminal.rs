//! Parses the arguments from the initial terminal, used to parse arguments after "hyxewave"

use clap::{App, Arg, AppSettings, ArgMatches};

use hyxe_user::account_manager::AccountManager;

use crate::app_config::AppConfig;
use crate::console_error::ConsoleError;
use crate::ffi::FFIIO;
use hyxe_net::constants::PRIMARY_PORT;
use std::str::FromStr;
use std::net::{SocketAddr, IpAddr};

/// The arguments, if None, will default to std::env::args, with the zeroth element removed (the binary name)
/// Is some,
pub async fn parse_command_line_arguments_into_app_config(cmd: Option<String>, ffi_io: Option<FFIIO>) -> Result<(AppConfig, AccountManager), ConsoleError> {
    let arg_matches = if let Some(cmd) = cmd {
        setup_clap().get_matches_from_safe(cmd.split_whitespace().collect::<Vec<&str>>())
            .map_err(|err| ConsoleError::Generic(err.to_string()))?
    } else {
        let mut args = std::env::args().collect::<Vec<String>>();
        args.remove(0); // remove binary name
        setup_clap().get_matches_from(args)
    };
    let mut app_config = AppConfig::default();

    app_config.is_ffi = ffi_io.is_some();
    app_config.ffi_io = ffi_io;
    app_config.daemon_mode = arg_matches.is_present("daemon");

    parsers::parse_all_primary_commands(&arg_matches, &mut app_config)?;
    let account_manager = AccountManager::new(app_config.local_bind_addr.clone().unwrap(), app_config.home_dir.clone()).await.map_err(|err| ConsoleError::Generic(err.to_string()))?;

    Ok((app_config, account_manager))
}

fn setup_clap<'a>() -> App<'a, 'a> {
    App::new("Lusna")
        .version(crate::constants::VERSION)
        .author("Thomas Philip Braun <thomas@satorisocial.com>")
        .about("A CLI for the post-quantum distributed networking protocol")
        .setting(AppSettings::NoBinaryName)
        .arg(Arg::with_name("bind")
            .long("bind")
            .short("b")
            .help("Sets local bind address")
            .takes_value(true)
            .required(false))
        .arg(Arg::with_name("daemon")
            .long("daemon")
            .short("d")
            .help("Disables terminal input. Useful if running SatoriNET through nohup or as a background service")
            .takes_value(false)
            .required(false))
        .arg(Arg::with_name("node_type")
            .long("type")
            .required(true)
            .takes_value(true)
            .default_value("residential")
            .possible_values(&["pure_server", "residential", "cellular"]))
        .arg(Arg::with_name("home")
            .long("home")
            .required(false)
            .takes_value(true)
            .help("Overrides the default home directory for saving critical application files"))
        //.arg(Arg::with_name("command").required(true).index(1))
        .arg(Arg::with_name("pipe").long("pipe").takes_value(true).required(false).help("include a locally-running TCP socket address to communicate with local processes. The following argument must be a loopback socket address"))
}

pub mod parsers {
    use std::str::FromStr;

    use clap::ArgMatches;

    use hyxe_net::hdp::hdp_packet_processor::includes::SocketAddr;

    use crate::app_config::AppConfig;
    use crate::console_error::ConsoleError;
    use hyxe_net::re_imports::HyperNodeType;
    use crate::primary_terminal::try_get_local_addr;

    pub fn parse_all_primary_commands(matches: &ArgMatches, app_config: &mut AppConfig) -> Result<(), ConsoleError> {
        if let Some(node_type) = matches.value_of("node_type") {
            let node = match node_type {
                "pure_server" => HyperNodeType::GloballyReachable,
                "residential" => HyperNodeType::BehindResidentialNAT,
                "cellular" => HyperNodeType::BehindSymmetricalNAT,
                _ => panic!("unreachable?")
            };

            app_config.hypernode_type = Some(node);
        }

        if let Some(pipe_addr) = matches.value_of("pipe") {
            let tcp_socket_addr = SocketAddr::from_str(pipe_addr)?;
            if !tcp_socket_addr.ip().is_loopback() {
                return Err(ConsoleError::Default("The supplied TCP address is not a loopback address. Must be within 127.0.0.0/8 (IPv4) OR ::1 (IPv6)"));
            }

            app_config.pipe = Some(tcp_socket_addr);
        }

        app_config.local_bind_addr = Some(try_get_local_addr(matches)?);


        if let Some(home_addr) = matches.value_of("home") {
            app_config.home_dir = Some(home_addr.to_string());
        }


        Ok(())
    }
}

fn try_get_local_addr(matches: &ArgMatches) -> Result<SocketAddr, ConsoleError> {
    if let Some(target_addr) = matches.value_of("bind") {
        if target_addr.contains(":") {
            // custom bind, custom port
            SocketAddr::from_str(target_addr).map_err(|err| ConsoleError::Generic(err.to_string()))
        } else {
            // custom bind, default port
            let ip_addr = IpAddr::from_str(target_addr)?;
            Ok(SocketAddr::new(ip_addr, PRIMARY_PORT))
        }
    } else {
        // default bind, default port
        Ok(SocketAddr::new(IpAddr::from_str("127.0.0.1").unwrap(), PRIMARY_PORT))
    }
}