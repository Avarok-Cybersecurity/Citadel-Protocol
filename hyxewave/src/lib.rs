#![feature(test, rustc_private, const_fn)]

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
    pub use hyxe_net::re_imports::{UnboundedSender, UnboundedReceiver, BufMut, unbounded};
    pub use tokio::task::spawn;
    pub use parking_lot::{Mutex, const_mutex};
    pub use hyxe_net::hdp::ThreadSafeFuture;
    pub use tokio::runtime::{Builder, Runtime};
    pub use hyxe_net::hdp::hdp_server::Ticket;
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
    }).expect("We were unable to setup the system shutdown hooks. Please report this to the developers")
}