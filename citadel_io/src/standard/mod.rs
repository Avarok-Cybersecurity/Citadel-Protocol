pub mod locks;

// Linux-only io_uring inbound-UDP backend. Gated by target + the opt-in `io-uring` feature so a
// default build compiles nothing here.
#[cfg(all(target_os = "linux", feature = "io-uring"))]
pub mod udp_io_uring;
