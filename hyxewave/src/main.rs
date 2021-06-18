use hyxewave::hdp_initiator::execute;
use hyxewave::primary_terminal::parse_command_line_arguments_into_app_config;
use hyxewave::console_error::ConsoleError;
use hyxewave::{shutdown_sequence, setup_shutdown_hook, setup_log};
use hyxewave::console::virtual_terminal::INPUT_ROUTER;
use hyxewave::app_config::TomlConfig;

fn main() -> Result<(), ConsoleError> {
    deadlock_detection();
    setup_log();
    setup_shutdown_hook();
    let cfg = TomlConfig::load_default()?;

    match parse_command_line_arguments_into_app_config(cfg,None) {
        Ok(cfg) => {
            print_welcome();
            INPUT_ROUTER.init(cfg.daemon_mode)?;
            log::info!("Obtained information from console. Now beginning instantiation of HdpServer ...");
            match execute(cfg).map_err(|err| ConsoleError::Generic(err.into_string())) {
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
    colour::red!(" v{} ({}/{})\n", hyxe_net::constants::BUILD_VERSION, hyxe_net::build_tag(), hyxe_net::re_imports::build_tag());
    print!("\x1B[2J\x1B[1;1H");
}

#[allow(dead_code)]
fn deadlock_detection() {
    #[cfg(debug_assertions)]
    {
        println!("Deadlock function called ...");
        use std::thread;
        use std::time::Duration;
        use parking_lot::deadlock;
// Create a background thread which checks for deadlocks every 10s
        thread::spawn(move || {
            println!("Deadlock detector spawned ...");
            loop {
                thread::sleep(Duration::from_secs(10));
                let deadlocks = deadlock::check_deadlock();
                if deadlocks.is_empty() {
                    continue;
                }

                println!("{} deadlocks detected", deadlocks.len());
                for (i, threads) in deadlocks.iter().enumerate() {
                    println!("Deadlock #{}", i);
                    for t in threads {
                        println!("Thread Id {:#?}", t.thread_id());
                        println!("{:#?}", t.backtrace());
                    }
                }
            }
        });
    }
}