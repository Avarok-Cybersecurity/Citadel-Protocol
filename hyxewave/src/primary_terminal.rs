//! Parses the arguments from the initial terminal, used to parse arguments after "hyxewave"

use clap::{App, Arg, AppSettings, ArgMatches};

use crate::app_config::{AppConfig, TomlConfig};
use crate::console_error::ConsoleError;
use hyxe_net::constants::PRIMARY_PORT;
use std::str::FromStr;
use std::net::{SocketAddr, IpAddr};


/// The arguments, if None, will default to std::env::args, with the zeroth element removed (the binary name)
/// Is some,
pub fn parse_command_line_arguments_into_app_config(loaded_config: Option<TomlConfig>, cmd: Option<String>) -> Result<AppConfig, ConsoleError> {
    let arg_matches = if let Some(cmd) = cmd {
        setup_clap().get_matches_from_safe(cmd.split_whitespace().collect::<Vec<&str>>())
            .map_err(|err| ConsoleError::Generic(err.to_string()))?
    } else {
        let mut args = std::env::args().collect::<Vec<String>>();
        args.remove(0); // remove binary name
        setup_clap().get_matches_from(args)
    };

    if let Some(millis) = arg_matches.value_of("argon-autotuner") {
        let millis = u16::from_str(millis).map_err(|_| ConsoleError::Generic(format!("Invalid input: {}. Choose a value between 0 < millis < 65535", millis)))?;
        let rt = tokio::runtime::Builder::new_multi_thread().enable_io().enable_time().build().map_err(|err| ConsoleError::Generic(err.to_string()))?;
        rt.block_on(async move {
            match hyxe_crypt::argon::autotuner::calculate_optimal_params(millis, None, None).await {
                Ok(cfg) => {
                    println!("\n\n\r***Optimal settings obtained***\nMem cost: {} | Time cost: {} | Lanes: {}", cfg.mem_cost, cfg.time_cost, cfg.lanes)
                }

                Err(err) => {
                    eprintln!("\n\rUnable to execute argon autotuner: {:?}", err);
                }
            }
        });

        std::process::exit(0);
    }

    // check to see if there is a toml config
    if let Some(toml_cfg) = loaded_config {
        let default_alias: Option<String> = if let Some(values) = arg_matches.values_of("alias") {
            Some(values.into_iter().collect::<Vec<&str>>().join(" "))
        } else {
            None
        };

        return toml_cfg.parse_config(default_alias.as_ref().map(|r| r.as_str()));
    }

    let mut app_config = AppConfig::default();

    #[cfg(any(feature = "enterprise-lite", feature = "enterprise"))]
        {
            use hyxe_user::backend::BackendType;
            app_config.backend_type = arg_matches.value_of("backend").map(|r| BackendType::sql(r));
        }

    app_config.daemon_mode = arg_matches.is_present("daemon") || app_config.is_ffi;
    app_config.kernel_threads = try_get_kthreads(&arg_matches)?;

    parsers::parse_all_primary_commands(&arg_matches, &mut app_config)?;

    Ok(app_config)
}

fn setup_clap<'a>() -> App<'a, 'a> {
    App::new("SatoriNET")
        .version(crate::constants::VERSION)
        .author("Thomas Philip Braun <thomas@satorisocial.com>")
        .about("A CLI for the post-quantum distributed networking protocol")
        .setting(AppSettings::NoBinaryName)
        .setting(AppSettings::TrailingVarArg)
        .arg(Arg::with_name("bind")
            .long("bind")
            .short("b")
            .help("Sets local bind address")
            .takes_value(true)
            .required(false))
        .arg(Arg::with_name("ipv6")
            .long("ipv6")
            .help("Enables IPv6 mode (shorthand for --bind [::])")
            .takes_value(false)
            .required(false))
        .arg(Arg::with_name("daemon")
            .long("daemon")
            .short("d")
            .help("Disables terminal input. Required if running SatoriNET through nohup or as a background service")
            .takes_value(false)
            .required(false))
        .arg(Arg::with_name("public")
            .long("public")
            .help("Binds to the public facing address 0.0.0.0 (w/ default port)")
            .takes_value(false)
            .required(false))
        .arg(Arg::with_name("node_type")
            .long("type")
            .required(true)
            .takes_value(true)
            .default_value("residential")
            .possible_values(&["pure_server", "residential", "cellular"]))
        .arg(Arg::with_name("alias")
            .long("alias")
            .help("Overrides the default used alias inside the config (requires a settings.toml in the application directory). Ignores all other console inputs")
            .takes_value(true)
            .multiple(true)
            .required(false))
        .arg(Arg::with_name("home")
            .long("home")
            .required(false)
            .takes_value(true)
            .help("Overrides the default home directory for saving critical application files"))
        .arg(Arg::with_name("kernel_threads")
            .long("kthreads")
            .short("kt")
            .help("Specifies the number of kernel threads. Defaults to # of CPU cores")
            .takes_value(true)
            .required(false))
        // the below is called from the launcher. It will cause the program to default to binding on 0.0.0.0
        .arg(Arg::with_name("launcher")
            .long("launcher")
            .required(false)
            .takes_value(false)
            .hidden(true))
        .arg(Arg::with_name("backend")
            .long("backend")
            .required(false)
            .takes_value(true)
            .help("Specifies a backend for storing peer account information. Stores to the local filesystem as default. Enter a url in the format: mysql://username:password@ip/database"))
        //.arg(Arg::with_name("command").required(true).index(1))
        .arg(Arg::with_name("pipe").long("pipe").takes_value(true).hidden(true).required(false).help("include a locally-running TCP socket address to communicate with local processes. The following argument must be a loopback socket address"))
        .arg(Arg::with_name("tls")
            .long("tls")
            .required(false)
            .requires("tls-domain")
            .takes_value(true)
            .help("Enables the use of TLS for this node. Requires an input path to a PKCS-12 file. Self-signed certs are not allowed in production mode. If a password is required, specify tls-pass <path/to/file>"))
        // https://www.netmeister.org/blog/passing-passwords.html
        .arg(Arg::with_name("tls-pass")
            .long("tls-pass")
            .required(false)
            .takes_value(true)
            .display_order(2)
            .multiple(true)
            .hidden_long_help(true)
            .help("A path to a file containing a password for the TLS certificate. Every byte in the file will be interpreted as the password"))
        .arg(Arg::with_name("tls-domain")
            .long("tls-domain")
            .default_value("")
            .takes_value(true)
            .help("Specifies a domain"))
        .arg(Arg::with_name("argon-autotuner")
            .long("argon-autotuner")
            .required(false)
            .takes_value(true)
            .help("Used to determine the optimal argon-2id password hashing parameters. Expects an input of a value of a target minimum calculation time in milliseconds"))
}

pub mod parsers {
    use std::str::FromStr;

    use clap::ArgMatches;

    use hyxe_net::hdp::hdp_packet_processor::includes::SocketAddr;

    use crate::app_config::AppConfig;
    use crate::console_error::ConsoleError;
    use hyxe_net::re_imports::HyperNodeType;
    use crate::primary_terminal::try_get_local_addr;
    use hyxe_net::hdp::misc::underlying_proto::UnderlyingProtocol;
    use std::fs::File;
    use std::io::Read;

    pub fn parse_all_primary_commands(matches: &ArgMatches, app_config: &mut AppConfig) -> Result<(), ConsoleError> {
        if let Some(node_type) = matches.value_of("node_type") {
            let node = match node_type {
                "pure_server" => HyperNodeType::Server,
                "residential" => HyperNodeType::BehindResidentialNAT,
                "cellular" => HyperNodeType::BehindSymmetricalNAT,
                _ => return Err(ConsoleError::Default("Invalid node type"))
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

        if let Some(path) = matches.value_of("tls") {
            let password_path: Option<String> = matches.values_of("tls-pass").map(|r| r.collect::<Vec<&str>>().join(" "));
            let mut buf = String::new();

            if let Some(path) = password_path {
                let _ = File::open(path)?.read_to_string(&mut buf)?;
            }

            let tls_domain = matches.value_of("tls-domain").map(|r| r.to_string()).unwrap();
            app_config.underlying_protocol = Some(UnderlyingProtocol::load_tls(path, buf.trim(), tls_domain).map_err(|err| ConsoleError::Generic(err.to_string()))?);
        } else {
            app_config.underlying_protocol = Some(UnderlyingProtocol::Tcp)
        }


        Ok(())
    }
}

fn try_get_local_addr(matches: &ArgMatches) -> Result<SocketAddr, ConsoleError> {
    // if bind is specified, this will override the --launcher flag, allowing users running the launcher to specify custom bind addrs
    if let Some(target_addr) = matches.value_of("bind") {
        parse_custom_addr(target_addr)
    } else {
        // if the --launcher flag is passed, default to 0.0.0.0
        // global
        if matches.is_present("launcher") || matches.is_present("public") {
            if matches.is_present("ipv6") {
                Ok(SocketAddr::new(IpAddr::from_str("::").unwrap(), PRIMARY_PORT))
            } else {
                Ok(SocketAddr::new(IpAddr::from_str("0.0.0.0").unwrap(), PRIMARY_PORT))
            }
        } else {
            // local
            if matches.is_present("ipv6") {
                Ok(SocketAddr::new(IpAddr::from_str("::1").unwrap(), PRIMARY_PORT))
            } else {
                Ok(SocketAddr::new(IpAddr::from_str("127.0.0.1").unwrap(), PRIMARY_PORT))
            }
        }
    }
}

pub fn parse_custom_addr<T: AsRef<str>>(target_addr: T) -> Result<SocketAddr, ConsoleError> {
    // try ipv6
    let target_addr = target_addr.as_ref();
    if target_addr.contains("::") {
        if target_addr.eq("[::]") || target_addr.eq("::") {
            // [ipv6] custom bind, default port
            Ok(SocketAddr::new(IpAddr::from_str("::").unwrap(), PRIMARY_PORT))
        } else {
            // user may type: [::1], in which case, we have custom bind, default port
            // thus, we need another check
            if target_addr.contains("]:") {
                // [ipv6] custom bind, custom port
                SocketAddr::from_str(target_addr).map_err(|err| ConsoleError::Generic(err.to_string()))
            } else {
                // [ipv4] custom bind, default port. User may type: [::1] OR ::1
                let ip_addr = IpAddr::from_str(&*target_addr.replace("[", "").replace("]", ""))?;
                Ok(SocketAddr::new(ip_addr, PRIMARY_PORT))
            }
        }
    } else {
        if target_addr.contains(":") {
            // [ipv4] custom bind, custom port
            SocketAddr::from_str(target_addr).map_err(|err| ConsoleError::Generic(err.to_string()))
        } else {
            // [ipv4] custom bind, default port
            let ip_addr = IpAddr::from_str(target_addr)?;
            Ok(SocketAddr::new(ip_addr, PRIMARY_PORT))
        }
    }
}

fn try_get_kthreads(matches: &ArgMatches) -> Result<Option<usize>, ConsoleError> {
    if let Some(val) = matches.value_of("kernel_threads") {
        let count = u16::from_str(val).map_err(|_| ConsoleError::Default("Invalid kernel thread value"))?;
        if count != 0 {
            Ok(Some(count as usize))
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}