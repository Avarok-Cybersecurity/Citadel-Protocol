use std::collections::VecDeque;
use crate::connection::stream_wrappers::old::RawInboundItem;
use hyxe_netdata::packet::{PacketStage, ProcessedPacketHeader, RawInboundPacket, StageDriverPacket};
use crate::packet::inbound::stage1::Stage1Sink;

use futures2::Sink;
use zerocopy::LayoutVerified;
use crate::packet::inbound::PacketDriver;
use crate::packet::inbound::stage2::Stage2Sink;
use crate::packet::misc::ConnectError;
use std::marker::PhantomPinned;
use chashmap::CHashMap;
use hashbrown::HashMap;
use crate::packet::inbound::object_expectancy::{ObjectExpectancy, ExpectancyStatus};
use crate::packet::inbound::singleton_expectancy::SingletonExpectancy;
use futures2::compat::{Future01CompatExt, Stream01CompatExt};
use crate::packet::definitions::{OBJECT_HEADER, OBJECT_PAYLOAD, SINGLETON_PACKET};
use hyxe_crypt::drill_impls::DrillType;
use hyxe_crypt::drill::{Drill, SecurityLevel};
use futures::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio_threadpool::ThreadPool;
use crate::packet::inbound::expectancy::{ExpectancyRequest, Expectancy, ExpectancyResponse};
use std::sync::atomic::{AtomicUsize, Ordering, AtomicPtr};
use crate::connection::server::Server;
use std::mem::MaybeUninit;
use tokio::timer::Interval;
use std::time::{Instant, Duration};
use std::pin::Pin;
use std::ops::{Deref, DerefMut};
use std::borrow::Borrow;
use crate::packet::inbound::null_expectancy::NullExpectancy;
use std::sync::Arc;
use hyxe_user::account_manager::AccountManager;
use parking_lot::Mutex;
use async_std::task::{Context, Poll};
use futures2::{SinkExt, Stream, StreamExt, TryStream, TryStreamExt};
use hyxe_crypt::prelude::DrillStandard;
use futures::{Async, Sink};

/// The constant which determines how pany packets are prel
pub const MAX_PACKETS_PER_MAP: usize = 10000;

/// Everytime a packet comes inbound, the timer should be reset. If a packet doesn't come within this timeframe, and the buffer hasn't
/// finished filling, then an error is thrown which propagates to the API layer
pub const TIMEOUT_MS: u64 = 2000;

/// Packets from the stream wrapper's output get sent here (this is the destination that is forwarded to by the inbound_rx).
///
/// The job of the StageDriver is to receive RawInboundPackets<B> and then transform them into properly formatted ProcessedInboundPackets<B>
/// before sending them off into the next sink
pub struct StageDriver<'next_stage, 'driver: 'next_stage, 'server: 'driver> where Self: 'driver {
    /// Used for getting the drills
    account_manager: AccountManager,
    /// This is necessary for the storing of packets. Once a packet no longer needs to exist, the supplied global packet ID can
    /// be used to delete the entry within `tmp_store`.
    global_packet_id: AtomicUsize,
    /// This is where packets remain until driven to completion through all stages
    /// If a packet with a nonzero and unique eid_oid arrives that was expected, it is delivered
    /// into the appropriate [Expectancy] within `expectancies`.
    object_expectancies: CHashMap<u64, ObjectExpectancy<'next_stage, 'driver>>,
    singleton_expectancies: CHashMap<u64, SingletonExpectancy>,
    /// Only packets which will be forwarded or packets which have an end trajectory at the local node will go here.
    /// The key is the global packet ID. It is obtained by the atomically-backed `get_and_increment_packet_id` subroutine
    null_expectancies: CHashMap<u64, NullExpectancy>,
    /// Receives mutable references of the ProcessedInboundPackets
    stage1: Stage1Sink<'next_stage, 'driver>,
    stage2: Stage2Sink<'next_stage, 'driver>,
    /// Without `to_internal_server`, the StageDriver won't be able send data to the internal_server, meaning that the
    /// [Session] level wont be able to receive anything. [StageDriverPacket]'s are pointers to heap-pinned data.
    to_internal_server: UnboundedSender<StageDriverPacket>,
    stream_to_stage_driver_rx: Option<UnboundedReceiver<RawInboundItem>>,
    /// Toggled to `true` if the internal server is receiving resultant packets from this [StageDriver]
    is_connected_to_internal_server: bool,
    /// Obtained from the [Server] to help reduce the number of pointer operations
    local_nid: u64
}

/// The purpose of this struct to allow external access into the [StageDriver]'s fields. Particularly, this is
/// used to access the concurrent hashmaps which relate to expectancies in order to inject asynchronous callbacks.
///
/// Using this becomes UB if the [StageDriver] drops from the scope, or, if the internal pointer is used
pub struct StageDriverHandle<'next_stage, 'driver: 'next_stage, 'server: 'driver> {
    atomic_ptr: *const StageDriver<'next_stage, 'driver, 'server>
}

unsafe impl Send for StageDriverHandle {}
unsafe impl Sync for StageDriverHandle {}

impl Clone for StageDriverHandle<'_, '_, '_> {
    fn clone(&self) -> Self {
        Self { atomic_ptr: self.atomic_ptr }
    }
}

impl<'next_stage, 'driver: 'next_stage, 'server: 'driver> StageDriverHandle<'next_stage, 'driver, 'server> {
    pub(crate) fn new(stage_driver: Pin<&'driver mut StageDriver<'next_stage, 'driver, 'server>>) -> Self {
        Self { atomic_ptr: &*stage_driver as *const StageDriver<'next_stage, 'driver, 'server> }
    }

    /// Creates an expectancy. Known callers: [BridgeHandler]; [ServerBridgeHandler]. This uses unsafe, but is safe because:
    /// [1] The [StageDriver] is pinned to the heap, and;
    /// [2] This interacts with a concurrent hashmap which does not require exclusive access; it requires only &self
    pub fn request_expectancy(&self, request: ExpectancyRequest) -> Result<Pin<Box<ExpectancyResponse>>, ConnectError> {
        unsafe { &**self.atomic_ptr }.create_expectancy(request)
    }
}

/*
impl<'next_stage, 'driver: 'next_stage, 'server: 'driver> Deref for StageDriverHandle<'next_stage, 'driver, 'server> {
    type Target = StageDriver<'next_stage, 'driver, 'server>;

    fn deref(&self) -> &Self::Target {
        unsafe { &**self.atomic_ptr }
    }
}
*/

impl<'next_stage, 'driver: 'next_stage, 'server: 'driver> StageDriver<'next_stage, 'driver, 'server> {
    /// Creates a new [StageDriver]. There should only be 1 in existence during runtime
    pub fn new(local_nid: u64, stream_to_stage_driver_rx: UnboundedReceiver<RawInboundItem>, to_internal_server: UnboundedSender<StageDriverPacket>, account_manager: &AccountManager) -> Pin<Box<Self>> {
        Box::pin(Self { account_manager: AccountManager.clone(), global_packet_id: AtomicUsize::new(0), object_expectancies: CHashMap::new(), singleton_expectancies: CHashMap::new(), null_expectancies: CHashMap::new(), stage1: Stage1Sink::new(), stage2: Stage2Sink::new(), to_internal_server, stream_to_stage_driver_rx: Some(stream_to_stage_driver_rx), is_connected_to_internal_server: false, local_nid})
    }

    /// This helps solve the problem of: "How can the StageDriver asynchronously callback to any arbitrary .await point in memory?".
    /// This should be created by the higher-level [Server] within the constructor closure, that way the handle can be distributed throughout
    /// the program
    pub(crate) fn create_atomic_handle(mut self: Pin<&'driver mut Self>) -> StageDriverHandle {
        StageDriverHandle::new(self)
    }

    /// Returns an .awaitable ExpectancyResponse. It must be transported over channels to the [SessionManager]
    fn create_expectancy(&self, request: ExpectancyRequest) -> Result<Pin<Box<ExpectancyResponse>>, ConnectError> {
        println!("Creating expectancy: {}", &request);
        match request {
            ExpectancyRequest::Singleton(cid, eid_oid, timeout, security_level) => {
                self.inject_singleton_expectancy(cid, eid_oid, timeout, security_level)
            },

            ExpectancyRequest::Object(cid, eid_oid, payload_size_expected, timeout, security_level) => {
                self.pseudo_inject_object_expectancy(cid, eid_oid, Some(payload_size_expected), timeout, security_level)
            },

            ExpectancyRequest::Auto(cid, eid_oid, timeout, security_level) => {
                unimplemented!()
            }
        }
    }

    /// Injects an asynchronous expectancy into the system. This is usually called by the BridgeHandler layer
    /// `cid_local`: This should be the CID of the caller, and NOT the adjacent endpoint. If CID "X" expects
    /// a response from CID "Y", then `cid_local` should be "X".
    fn inject_singleton_expectancy(&self, cid_local: u64, eid_oid: u64, timeout_ms: u64, security_level: SecurityLevel) -> Result<Pin<Box<ExpectancyResponse>>, ConnectError> {
        let mut exp = SingletonExpectancy::new(eid_oid, timeout_ms);
        let response = exp.generate_callback();
        match self.singleton_expectancies.insert(eid_oid, exp) {
            Some(_) => {
                Err(ConnectError::ExpectancyExists)
            },

            _ => {
                Ok(response)
            }
        }
    }

    /// Delivers the final packet to the expectancy, and then notifies the future causing a result to be yielded at the .await waypoint
    fn deliver_singleton_expectancy(&'driver mut self, packet: RawInboundItem) -> Result<(), ConnectError> {
        let header = packet.get_header();
        match self.singleton_expectancies.get_mut(&header.oid_eid.get()) {
            Some(mut exp) => {
                exp.deliver_packet(packet)?;
                exp.notify(); // For letting any .await waypoints to continue asynchronously
                Ok(())
            },

            None => {
                Err(ConnectError::None)
            }
        }
    }

    /// Injects an asynchronous expectancy into the system. This can be called by either:
    /// [1] The bridge handler/Session locally (this requires that the payload contain the values as expected (SEE: Definitions))
    /// [2] The stage driver as it detects an [OBJECT_HEADER] packet
    /// `drill`: For verifying the PID and WID
    /// `object_header`: The packet which is to be extended upon as data comes inbound
    /// `packet_id`: This may be used in the case that a pseudo packet is being injected - in which case, the system already has already
    /// required a packet ID
    fn inject_object_expectancy<Drx: DrillType>(&self, timeout_ms: u64, packet_id: Option<usize>, mut object_header: RawInboundItem) -> Result<Pin<Box<ExpectancyResponse>>, ConnectError> {
        let header = object_header.get_header();

        debug_assert_eq!(header.command_flag, OBJECT_HEADER);
        object_header.global_packet_id = Some(packet_id.unwrap_or(self.get_and_increment_global_packet_id()));

        match self.get_drill(header.cid_needed_to_undrill.get(), Some(header.drill_version_needed_to_undrill.get())) {
            Some(drill) => {
                match ObjectExpectancy::new(object_header, drill, timeout_ms) {
                    Some(mut exp) => {
                        let eid_oid = exp.eid_oid;
                        let response = exp.generate_callback();
                        match self.object_expectancies.insert(exp.eid_oid, exp) {
                            Some(_) => {
                                Err(ConnectError::ExpectancyExists)
                            },
                            None => {
                                // Expectancy has been successfully loaded. We will no longer directly await it, as this was triggered by an external inbound packet,
                                // and now it is up to the program to poll each to check for timeouts. However,
                                Ok(response)
                            }
                        }
                    },
                    None => {
                        Err(ConnectError::None)
                    }
                }
            },

            None => {
                Err(ConnectError::DrillAbsent)
            }
        }
    }

    /// Unlike `inject_object_header`, this function is not asynchronous and does not need to store the data into `tmp_store`. The expectancies' packet reconstructor
    /// performs a manual pointer copy, and as such, only needs a temporary borrow of the object payload.
    fn deliver_object_payload<Drx: DrillType>(&'driver mut self, timeout_ms: u64, drill: &Drill<Drx>, object_payload: &'driver mut RawInboundItem) -> Result<(), ConnectError> {
        let header = object_payload.get_header();
        debug_assert_eq!(header.command_flag, OBJECT_PAYLOAD);

        let cid = header.cid_needed_to_undrill.get(); // The last hop
        let eid_oid = header.oid_eid.get();

        match self.object_expectancies.get_mut(&eid_oid) {
            Some(mut exp) => {
                if let Ok(true) = exp.deliver_packet(object_payload).map_err(|_| ConnectError::Generic("unable to deliver packet".to_string())) {
                    // If the reconstructor propagates that it is finished, then we ought to notify any internal wait points
                    exp.notify();
                }

                Ok(())
            },

            None => {
                Err(ConnectError::None)
            }
        }
    }

    /// Whereas `inject_object_expectancy` is for creating an expectancy from an external inbound packet, this function is for creating an
    /// expectancy before an [OBJECT_HEADER] packet arrives. The pseudo-[OBJECT_HEADER] will get replaced once the external inbound
    /// [OBJECT_HEADER] is received.
    ///
    /// `expected_payload_size`: The size of the payload, in bytes, that is necessarily expected. If `None` is specified, then the size is
    /// set to 0 in the pseudo-[OBJECT_HEADER]; this implies that there is no expected size upon return.
    fn pseudo_inject_object_expectancy(&self, cid_local: u64, eid_oid: u64, expected_payload_size: Option<usize>, timeout_ms: u64, security_level: SecurityLevel) -> Result<Pin<Box<ExpectancyResponse>>, ConnectError> {
        let global_packet_id = self.get_and_increment_global_packet_id();
        self.inject_object_expectancy(timeout_ms, Some(global_packet_id), RawInboundPacket::create_pseudo_expectancy_packet(global_packet_id))
    }

    /// Stores the packet, and returns the global packet id
    /// This is inlined to reduce JMP's. This is not for pseudo packets; this is for either:
    /// [A] Packets that will be forwarded (implies no local expectancy), or;
    /// [B] Packets that have reached the end of their trajectories
    ///
    /// This also immediately forwards the packet to stage 2
    #[inline]
    fn inject_null_expectancy(&mut self, packet: RawInboundItem) -> usize {
        let global_packet_id = self.get_and_increment_global_packet_id();
        let mut null_exp = NullExpectancy::new(packet);
        self.stage2.start_send(unsafe { null_exp.get_packet_unchecked() });
        let res = self.null_expectancies.insert(global_packet_id as u64, null_exp).is_none();
        debug_assert!(res);

        global_packet_id
    }

    /// Without starting this subroutine, the stage driver wouldn't be able to add expectancies to its internal layer. This makes it easy
    /// for the [Session] layer to communicate with the server. This takes-in a receiver, of which, is tethered to one producer within each
    /// [Session]. If an API-user expects a response, all they have to do is send an [ExpectancyRequest] through the the sender where thereafter
    /// it is received here.
    ///
    /// This is for local creation of expectancies. As such, we cannot use `inject_object_expectancy` per usual, because that function requires an
    /// inbound external packet. However, we can pass a pseudo-packet to it via `pseudo_inject_object_expectancy`.
    ///
    /// This should be executed by the higher-level [Server] and future-selected() with the parallel [SessionManager].
    ///
    /// [Panics]: if the stream_to_stage_driver_rx is empty, then this will panic. It is up to the higher-level [Session] to ensure that if this function is stopped,
    /// that the stream_to_stage_driver_rx is reloaded
    pub async fn execute(mut self: Pin<&'server mut Self>) -> Result<(), ConnectError> {
        self.is_connected_to_internal_server = true;
        let stream_to_stage_driver = self.stream_to_stage_driver_rx.unwrap();

        // While the below code is unsafe, the mutable pointer's pointee exists as pinned to the heap and cannot move.
        // So long as I follow the Pin contract, the pointer should remain valid in terms of memory location. However,
        // where it may not necessarily remain valid is the lifetime. To ensure the pointer is valid across its lifetime,
        // I need to ensure the shut-down sequence places this closure prior to the shutdown of the calling closure
        // (in this case, the calling closure it belongs to the higher-level [Server] type); this closure must exit before
        // the calling closure, and this will all be safe
        let mut self_ptr: Arc<Mutex<*mut Self>> = Arc::new(Mutex::new(*self as *mut Self));
        let mut self_ptr2: Arc<Mutex<*mut Self>> = self_ptr.clone();
        // This merges packets from all underlying stream to here (MP -> SC)
        let stream_to_stage_driver_future = stream_to_stage_driver.compat().map(move |raw_packet| unsafe {
            self_ptr.raw_lock();
            let stage_mut = (&mut **self_ptr.get_mut());
            stage_mut.process_raw_packet(raw_packet.unwrap());
            self_ptr.force_unlock();
        }).and_then(|_| Ok(())).map_err(|_| Err(()));

        // This ensures no expectancy gets left for too long within the concurrent hashmap
        let expectancy_driver = self_ptr2.periodic_expectancy_cleanup();

        expectancy_driver
            .map(|_| ())
            .select(stream_to_stage_driver_future)
            .map(|_| ())
            .map_err(|err| err.0)
            .and_then(|_| Ok(()))
    }

    /// This should be ran AFTER running start_connection_with_internal_server b/c of the take_while predicate and its dependency upon the inner boolean.
    /// This runs as long as there's a connection into the internal local server
    pub unsafe async fn periodic_expectancy_cleanup(mut self: Arc<Mutex<*mut Self>>) -> Result<(), ConnectError> {
        Interval::new(Instant::now(), Duration::from_millis(TIMEOUT_MS))
            .map_err(|err| ConnectError::Timeout)
            .take_while(|_| self.lock().is_connected_to_internal_server)
            .for_each(|_| {
                let this = self.lock();

                this.singleton_expectancies.retain(|eid_oid, exp| {
                    exp.notify();
                    !exp.needs_delete()
                });

                this.object_expectancies.retain(|eid_oid, exp| {
                    exp.notify();
                    !exp.needs_delete()
                });

                this.null_expectancies.retain(|eid_oid, exp| {
                    // No need to notify() null expectancies, but still, they need to be cleaned-up from RAM
                    !exp.needs_delete()
                });
            })
            .and_then(|_| Ok(())).compat()
    }

    /// Returns the running global packet count for this driver
    fn get_and_increment_global_packet_id(&self) -> usize {
        self.global_packet_id.fetch_add(1, Ordering::SeqCst)
    }

    /// This is the replacement for start_send
    fn process_raw_packet(&mut self, mut raw_packet: RawInboundItem) {
        if let Some(header) = LayoutVerified::<&[u8], ProcessedPacketHeader>::new(&raw_packet.data.as_ref()[0..std::mem::size_of::<ProcessedPacketHeader>()]) {
            let id = self.get_and_increment_global_packet_id();
            match header.packet_type {
                OBJECT_HEADER => {
                    let _ = self.inject_object_expectancy(TIMEOUT_MS, None, raw_packet);
                    // The object header was consumed, and nothing else has to be done here
                },

                OBJECT_PAYLOAD => {
                    // TODO: Optimize this process because the speed of the process is very low and causes unnecessary queries against the hashmap each iteration.
                    // IDEA: Create a CacheMap that returns a constant pointer to an address in memory
                    match self.get_drill(header.cid_needed_to_undrill.get(), Some(header.drill_version_needed_to_undrill.get())) {
                        Some(drill) => {
                            let _ = self.deliver_object_payload(TIMEOUT_MS, drill, &mut raw_packet);
                            // this packet is now delivered into the object expectancy, and will be dropped here
                        },

                        None => {}
                    }
                },

                SINGLETON_PACKET => {
                    if header.expects_response == 1 {
                        // This implies that this node must REBOUND the packet back !FALSE!. The rule for this to be implemented in the system
                        // is that the packet router must know when to switch from 0 to 1, and 1 to 0.
                        // A singleton that expects a response does not need to fulfill any local expectancy, and as such, should be stored
                        // in `tmp_store`, and then be given a global packet ID for traversal
                        //
                        // implied rule about rebound packets: They never have a local expectancy! (E.g., a DO_CONNECT reaching a central
                        // server is a rebound packet)
                        raw_packet.stage = PacketStage::Stage1Rebound;
                        let global_packet_id = self.inject_null_expectancy(raw_packet);
                        // This packet is now stored, and will be driven later by advance_drive()
                    } else {
                        // If the packet does not expect a response, yet is a singleton, that implies that this particular node is not meant
                        // to rebound the packet; this implies one of two things instead. Either the packet needs to be forwarded, or, this packet
                        // is to fulfill a local PRE-EXISTING expectancy
                        if raw_packet.needs_forwarding(self.local_nid) {
                            raw_packet.stage = PacketStage::Stage1Forward;
                            let global_packet_id = self.inject_null_expectancy(raw_packet);
                            // This packet is now stored in the temporary hashmap, and will be driven later by advance_drive()
                        } else {
                            let _ = self.deliver_singleton_expectancy(raw_packet);
                            // This packet is now stored in the expectancy, and will be driven later by advance_drive() after fulfilled (instant for singletons)
                        }
                    }
                }
            }
        }
    }

    /// Accesses the [AccountManager] for access to the concurrent hashmap which represents the drill
    fn get_drill(&self, cid: u64, drill_version: Option<u32>) -> Option<&Drill<DrillStandard>> {
        self.account_manager.borrow().get_drill(cid, drill_version)
    }
}

impl<'next_stage, 'driver: 'next_stage, 'server: 'driver> PacketDriver<'next_stage, 'driver> for StageDriver<'next_stage, 'driver, 'server> {
    fn drive(&mut self) -> Result<Async<()>, Self::SinkError> {
        // Expectancies no longer need to be checked. They automatically notify their calling .await waypoint upon packet-arrival, and will trigger
        // the .await automatically if completed, or will trigger the .await if a timeout occurs
        // Drive stage 1 to completion
        self.stage1.poll_complete()
    }
}