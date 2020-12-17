use hyxewave::hdp_initiator::execute;
use hyxewave::primary_terminal::parse_command_line_arguments_into_app_config;
use hyxewave::console_error::ConsoleError;
use hyxewave::{shutdown_sequence, setup_shutdown_hook, setup_log};
use hyxewave::console::virtual_terminal::INPUT_ROUTER;

fn main() -> Result<(), ConsoleError> {
    verify_permissions();
    setup_log();
    setup_shutdown_hook();

    match parse_command_line_arguments_into_app_config(None, None) {
        Ok(cfg) => {
            print_welcome();
            INPUT_ROUTER.init(cfg.daemon_mode)?;
            log::info!("Obtained information from console. Now beginning instantiation of HdpServer ...");
            match execute(cfg).map_err(|err| ConsoleError::Generic(err.to_string())) {
                Ok(_) => {
                    shutdown_sequence(0);
                    Ok(())
                }

                Err(err) => {
                    INPUT_ROUTER.deinit()?;
                    Err(err)
                }
            }
        },

        Err(err) => {
            colour::dark_red_ln!("Unable to proceed: {}", err.into_string());
            Ok(())
        }
    }
}

fn print_welcome() {
    colour::green!("Welcome to SatoriNET");
    colour::red!(" v{}\n", hyxe_net::constants::BUILD_VERSION);
    print!("\x1B[2J\x1B[1;1H");
}


#[cfg(not(target_os = "windows"))]
fn verify_permissions() {
    if !nix::unistd::Uid::effective().is_root() {
        println!("Please run the program with sudo, then try again");
        std::process::exit(-1);
    }
}

#[cfg(target_os = "windows")]
fn verify_permissions() {}
