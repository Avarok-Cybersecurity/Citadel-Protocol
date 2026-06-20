//! Linux io_uring inbound-UDP receive backend.
//!
//! This replaces the *read half* of a raw UDP socket with an io_uring `recvmsg` loop running on a
//! dedicated OS thread, bridged to the async world through an unbounded channel. The write half is
//! untouched — it keeps using the standard tokio path. The motivation is to cut the per-datagram
//! syscall/readiness round-trip on the hot UDP data channel by batching submissions and completions
//! through a single ring.
//!
//! ## Safety & lifetime model
//! - The thread owns a `dup(2)`'d copy of the socket fd, so its lifetime is fully decoupled from the
//!   tokio `UdpSocket` that owns the original fd: either side can close without dangling the other.
//! - Each in-flight `recvmsg` references a heap-pinned [`RecvSlot`] (boxed, never moved). A slot is
//!   only re-armed *after* its completion is observed, so the kernel never writes into a buffer that
//!   is concurrently read or freed.
//! - Shutdown is cooperative: dropping [`IoUringUdpReceiver`] flips an `AtomicBool` and drops the
//!   channel receiver. The loop polls the flag on every wait-timeout tick (and notices the closed
//!   channel on the next send), then exits and closes its `dup`'d fd.
//!
//! This is the single-shot (re-armed) `recvmsg` variant. A provided-buffer multishot variant
//! (`RecvMsgMulti` + buf_ring) is a possible future optimization; the single-shot loop already
//! removes the per-recv readiness round-trip, which is the dominant cost.

use bytes::BytesMut;
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::tokio::net::UdpSocket;
use crate::tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use io_uring::{opcode, types, IoUring};

/// Ring depth. Must be >= `RECV_SLOTS` so every slot can have an SQE outstanding.
const RING_ENTRIES: u32 = 64;
/// Number of concurrently-armed `recvmsg` operations (= in-flight receive buffers).
const RECV_SLOTS: usize = 16;
/// Per-datagram buffer size. Matches `citadel_proto`'s `CODEC_BUFFER_CAPACITY` (`u16::MAX`).
const DGRAM_CAP: usize = u16::MAX as usize;
/// Wait-tick used to bound shutdown latency when no datagrams are arriving (250ms).
const WAIT_TIMEOUT_NS: u32 = 250_000_000;

type RecvItem = io::Result<(BytesMut, SocketAddr)>;

/// Async-side handle to the io_uring UDP receive loop. Yields `(datagram, source_addr)` pairs that
/// mirror exactly what `UdpFramed`'s `recv_from`-based stream would produce.
pub struct IoUringUdpReceiver {
    rx: UnboundedReceiver<RecvItem>,
    shutdown: Arc<AtomicBool>,
}

impl IoUringUdpReceiver {
    /// Attempt to start the io_uring receive loop for `socket`. Returns `None` if io_uring is
    /// unavailable (old kernel, restricted sandbox, fd dup failure, thread spawn failure), in which
    /// case the caller must fall back to the standard tokio recv path.
    pub fn try_spawn(socket: &UdpSocket) -> Option<Self> {
        let dup_fd = dup_socket(socket.as_raw_fd())?;
        // IoUring::new performs the io_uring_setup(2) syscall; this is where unsupported kernels and
        // seccomp-restricted sandboxes fail, triggering the caller's fallback.
        let ring = IoUring::new(RING_ENTRIES).ok()?;
        let (tx, rx) = mpsc::unbounded_channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_thread = shutdown.clone();

        std::thread::Builder::new()
            .name("citadel-iouring-udp".into())
            .spawn(move || recv_loop(ring, dup_fd, tx, shutdown_thread))
            .ok()?;

        Some(Self { rx, shutdown })
    }

    /// Poll for the next received datagram. Mirrors a `Stream::poll_next` of `RecvItem`.
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<RecvItem>> {
        self.rx.poll_recv(cx)
    }
}

impl Drop for IoUringUdpReceiver {
    fn drop(&mut self) {
        // Signal the loop to stop; it also notices the dropped `rx` on its next send.
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

/// `dup(2)` the socket fd into an independently-owned descriptor.
fn dup_socket(fd: RawFd) -> Option<OwnedFd> {
    // SAFETY: `dup` on a valid fd returns a fresh fd (>= 0) or -1 on error. `fd` is borrowed from a
    // live `UdpSocket` for the duration of this call.
    let new_fd = unsafe { libc::dup(fd) };
    if new_fd < 0 {
        return None;
    }
    // SAFETY: `new_fd` is a freshly-allocated descriptor we now exclusively own.
    Some(unsafe { OwnedFd::from_raw_fd(new_fd) })
}

/// A pinned receive slot: its `msghdr` holds raw pointers into its own `iov`/`name`, so it must
/// never move after [`arm_slot`]. Always heap-boxed to guarantee a stable address.
struct RecvSlot {
    buf: Vec<u8>,
    iov: libc::iovec,
    name: libc::sockaddr_storage,
    msghdr: libc::msghdr,
}

fn make_slot() -> Box<RecvSlot> {
    let mut slot = Box::new(RecvSlot {
        buf: vec![0u8; DGRAM_CAP],
        // SAFETY: iovec/sockaddr_storage/msghdr are plain-old-data; all-zero is a valid init state.
        iov: unsafe { std::mem::zeroed() },
        name: unsafe { std::mem::zeroed() },
        msghdr: unsafe { std::mem::zeroed() },
    });
    arm_slot(&mut slot);
    slot
}

/// (Re)point a slot's `msghdr` at its own buffer + address storage and reset the source-address
/// length. Called once at construction and again before every re-submission (the kernel mutates
/// `msg_namelen` to the received source-address length on completion).
fn arm_slot(slot: &mut RecvSlot) {
    slot.iov.iov_base = slot.buf.as_mut_ptr() as *mut libc::c_void;
    slot.iov.iov_len = slot.buf.len();
    slot.msghdr.msg_iov = &mut slot.iov as *mut libc::iovec;
    slot.msghdr.msg_iovlen = 1;
    slot.msghdr.msg_name = &mut slot.name as *mut libc::sockaddr_storage as *mut libc::c_void;
    slot.msghdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as _;
    slot.msghdr.msg_control = std::ptr::null_mut();
    slot.msghdr.msg_controllen = 0;
    slot.msghdr.msg_flags = 0;
}

/// Submit a `recvmsg` SQE for `slot`. Returns `false` if the submission queue is full.
fn push_recv(ring: &mut IoUring, fd: types::Fd, slot: &mut RecvSlot, user_data: u64) -> bool {
    let entry = opcode::RecvMsg::new(fd, &mut slot.msghdr as *mut libc::msghdr)
        .build()
        .user_data(user_data);
    // SAFETY: `slot` outlives the in-flight op (it lives in `slots` for the whole loop and is boxed,
    // so its address is stable). The slot is only re-armed after its completion is observed, so the
    // kernel never aliases a buffer that is concurrently read. The temporary SubmissionQueue guard
    // syncs the ring tail on drop.
    unsafe { ring.submission().push(&entry).is_ok() }
}

/// Owned-thread io_uring receive loop. Exits when shutdown is signalled, the channel closes, or the
/// ring errors. On exit the `dup`'d fd is closed (via `OwnedFd` drop) and `tx` is dropped, ending
/// the async-side stream.
fn recv_loop(
    mut ring: IoUring,
    dup_fd: OwnedFd,
    tx: UnboundedSender<RecvItem>,
    shutdown: Arc<AtomicBool>,
) {
    let fd = types::Fd(dup_fd.as_raw_fd());
    let mut slots: Vec<Box<RecvSlot>> = (0..RECV_SLOTS).map(|_| make_slot()).collect();

    // Prime: arm a recvmsg for every slot.
    for (idx, slot) in slots.iter_mut().enumerate() {
        if !push_recv(&mut ring, fd, slot, idx as u64) {
            return; // cannot even prime the ring → let the caller's fallback path take over
        }
    }
    if ring.submit().is_err() {
        return;
    }

    let ts = types::Timespec::new().nsec(WAIT_TIMEOUT_NS);
    let args = types::SubmitArgs::new().timespec(&ts);
    let mut completed: Vec<(u64, i32)> = Vec::with_capacity(RECV_SLOTS);

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        match ring.submitter().submit_with_args(1, &args) {
            Ok(_) => {}
            // Wait-tick elapsed with no completion: loop back to re-check the shutdown flag.
            Err(ref e) if e.raw_os_error() == Some(libc::ETIME) => {}
            Err(_) => break, // unrecoverable ring error
        }

        completed.clear();
        {
            let mut cq = ring.completion();
            cq.sync();
            for cqe in &mut cq {
                completed.push((cqe.user_data(), cqe.result()));
            }
        }

        let mut closed = false;
        for &(user_data, result) in &completed {
            let idx = user_data as usize;
            let Some(slot) = slots.get(idx) else { continue };

            if result >= 0 {
                let n = result as usize;
                match parse_addr(&slot.name, slot.msghdr.msg_namelen) {
                    Some(addr) => {
                        let mut bytes = BytesMut::with_capacity(n);
                        bytes.extend_from_slice(&slot.buf[..n]);
                        if tx.send(Ok((bytes, addr))).is_err() {
                            closed = true;
                        }
                    }
                    None => {
                        let _ = tx.send(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "io_uring recvmsg: unparseable source address",
                        )));
                        closed = true;
                    }
                }
            } else {
                // Negative result is `-errno`. Surface it and stop, matching the standard stream's
                // behavior of ending the listener loop on a recv error.
                let _ = tx.send(Err(io::Error::from_raw_os_error(-result)));
                closed = true;
            }

            // Re-arm this slot for the next datagram.
            let slot = &mut slots[idx];
            arm_slot(slot);
            if !push_recv(&mut ring, fd, slot, idx as u64) {
                // Submission queue momentarily full: flush and retry once.
                let _ = ring.submit();
                if !push_recv(&mut ring, fd, slot, idx as u64) {
                    closed = true;
                }
            }
        }

        if closed {
            break;
        }
        if ring.submit().is_err() {
            break;
        }
    }
}

/// Decode a kernel-populated `sockaddr_storage` (with its post-recv `msg_namelen`) into a
/// `SocketAddr`. Returns `None` for unexpected families or truncated addresses.
fn parse_addr(storage: &libc::sockaddr_storage, len: libc::socklen_t) -> Option<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            if (len as usize) < std::mem::size_of::<libc::sockaddr_in>() {
                return None;
            }
            // SAFETY: family is AF_INET, so the storage is a valid `sockaddr_in`.
            let sin = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            Some(SocketAddr::new(ip.into(), u16::from_be(sin.sin_port)))
        }
        libc::AF_INET6 => {
            if (len as usize) < std::mem::size_of::<libc::sockaddr_in6>() {
                return None;
            }
            // SAFETY: family is AF_INET6, so the storage is a valid `sockaddr_in6`.
            let sin6 = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            Some(SocketAddr::new(ip.into(), u16::from_be(sin6.sin6_port)))
        }
        _ => None,
    }
}
