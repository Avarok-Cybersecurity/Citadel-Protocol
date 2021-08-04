#![feature(test, rustc_private, async_closure, const_fn_trait_bound)]

#[macro_use]
pub mod macros {
    macro_rules! printf {
        ($function:expr) => {
            crate::console::virtual_terminal::INPUT_ROUTER.print(|| {$function;})
        };
    }

    macro_rules! printfs {
        ($function:block) => {
            crate::console::virtual_terminal::INPUT_ROUTER.print(|| $function)
        };
    }

    macro_rules! printf_ln {
        ($function:expr) => {
            crate::console::virtual_terminal::INPUT_ROUTER.print(|| {print!("\n\r"); $function;})
        };
    }
}


pub mod re_exports {
    pub use parking_lot::{const_mutex, Mutex};
    pub use tokio::runtime::{Builder, Runtime};
    pub use tokio::task::spawn;

    pub use hyxe_user::account_manager::AccountManager;
    pub use hyxe_user::backend::mysql_backend::SqlConnectionOptions;
    pub use hyxe_user::backend::BackendType;
    pub use hyxe_user::misc::AccountError;
    pub use hyxe_user::external_services::fcm::fcm_packet_processor;
    pub use hyxe_net::constants::PRIMARY_PORT;
    pub use hyxe_net::hdp::misc::panic_future::AssertSendSafeFuture;
    pub use hyxe_user::external_services::ExternalService;

    pub use hyxe_net::hdp::hdp_server::Ticket;
    pub use hyxe_net::re_imports::{BufMut, unbounded, UnboundedReceiver, UnboundedSender};
}

pub mod app_config;

pub mod hdp_initiator;

pub mod kernel;

pub mod primary_terminal;

pub mod console_error;

pub mod constants;

pub mod ticket_event;

pub mod console;

pub mod command_handlers;

pub mod mail;

pub mod ffi;

pub fn shutdown_sequence(exit_status: i32) {
    println!("\n\rSatoriNET::Shutdown Hook initiated ...\n\r");
    #[cfg(target_os= "windows")]
        hyxe_net::hdp::hdp_server::atexit();
    if let Err(_) = crate::console::virtual_terminal::INPUT_ROUTER.deinit() {
        std::process::exit(-2)
    } else {
        std::process::exit(exit_status)
    }
}

pub fn setup_log() {
    std::env::set_var("RUST_LOG", "info,error,warn,trace");
    env_logger::init();
    //env_logger::Builder::new().target(env_logger::Target::Stderr).format_timestamp_secs().init();
}

pub fn setup_shutdown_hook() {
    ctrlc::set_handler(|| {
        shutdown_sequence(-1);
    }).expect("We were unable to setup the system shutdown hooks. Please report this to the developers");

    // finally, setup shutdown hooks inside the networking module
    if !shutdown_hooks::add_shutdown_hook(hyxe_net::hdp::hdp_server::atexit) {
        log::error!("Unable to set shutdown hook subroutine");
    }
}
