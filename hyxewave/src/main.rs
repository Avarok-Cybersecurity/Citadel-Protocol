use hyxewave::hdp_initiator::execute;
use hyxewave::primary_terminal::parse_command_line_arguments_into_app_config;
use hyxewave::console_error::ConsoleError;
use hyxewave::{shutdown_sequence, setup_shutdown_hook, setup_log};
use hyxewave::console::virtual_terminal::INPUT_ROUTER;

#[tokio::main(core_threads = 4)]
async fn main() -> Result<(), ConsoleError> {
    colour::green!("Welcome to SatoriNET");
    colour::red!(" v{}\n", hyxe_net::constants::BUILD_VERSION);
    setup_log();
    setup_shutdown_hook();

    match parse_command_line_arguments_into_app_config(None, None).await {
        Ok((cfg, account_manager)) => {
            INPUT_ROUTER.init(cfg.daemon_mode)?;
            log::info!("Obtained information from console. Now beginning instantiation of HdpServer ...");
            execute(cfg, account_manager).await.map_err(|err| ConsoleError::Generic(err.to_string()))
                .and_then(|_| {
                    shutdown_sequence(0);
                    Ok(())
                })
        },

        Err(err) => {
            colour::dark_red_ln!("Unable to proceed: {}", err.into_string());
            Ok(())
        }
    }
}