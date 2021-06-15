pub const BUILD_VERSION: usize = 5318;
/// Signal for closing the stream_wrapper
pub const STREAM_SHUTDOWN: u8 = 0;
/// Signal for restarting the stream_wrapper
pub const STREAM_RESTART: u8 = 1;
/// Each [HdpSession] will be polled twice per second to ensure validity of connection
pub const CONNECTION_HANDLER_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(1000);
/// If NoDelay is set, then wave packets are sent outbound immediately
pub const HDP_NODELAY: bool = false;
/// by default, TCP_ONLY is true since the MQ-UDP is experimental
pub const TCP_ONLY: bool = true;
/// Setting this option to zero will imply an RST gets sent once close() is called. This will lead to packets possibly being undelivered
pub const DEFAULT_SO_LINGER_TIME: std::time::Duration = std::time::Duration::from_millis(1000);
/// Id HDP_NODELAY is false, then the payload of a wave is sent after HDP_WAVE_PAYLOAD_DELAY time
pub const HDP_WAVE_PAYLOAD_DELAY: std::time::Duration = std::time::Duration::from_millis(250);
/// For calculating network latency
pub const NANOSECONDS_PER_SECOND: i64 = 1_000_000_000;
/// The length of an ethernet header. Source: https://app.netrounds.com/static/2.24/support/defs-notes/l2-eth-frame-sizes.html
pub const LAYER2_ETHERNET_HEADER_BYTE_LEN: usize = 18;
/// The IPv4 Header len
pub const LAYER3_IPV4_HEADER_BYTE_LEN: usize = 20;
/// The IPv6 Header len
pub const LAYER3_IPV6_HEADER_BYTE_LEN: usize = 40;
/// The UDP header len
pub const UDP_HEADER_BYTE_LEN: usize = 8;
/// The HDP header len
pub const HDP_HEADER_BYTE_LEN: usize = 52; // was 44, moved to 52
/// Assuming IPv6, this is the smallest MTU possible
pub const MTU: usize = 1280;
/// Total length of a packet's header
pub const BASE_HEADER_LEN_IPV4: usize = LAYER2_ETHERNET_HEADER_BYTE_LEN + LAYER3_IPV4_HEADER_BYTE_LEN + UDP_HEADER_BYTE_LEN + HDP_HEADER_BYTE_LEN;
/// Total length of a packet's header
pub const BASE_HEADER_LEN_IPV6: usize = LAYER2_ETHERNET_HEADER_BYTE_LEN + LAYER3_IPV6_HEADER_BYTE_LEN + UDP_HEADER_BYTE_LEN + HDP_HEADER_BYTE_LEN;
/// This is the maximum size an IPv4's packet can be
pub const MAX_PAYLOAD_SIZE_IPV4: usize = MTU - BASE_HEADER_LEN_IPV4;
/// This is the maximum size an IPv6's packet can be
pub const MAX_PAYLOAD_SIZE_IPV6: usize = MTU - BASE_HEADER_LEN_IPV6;
/// the initial reconnect delay
pub const INITIAL_RECONNECT_LOCKOUT_TIME_NS: i64 = NANOSECONDS_PER_SECOND;
///
pub const KEEP_ALIVE_INTERVAL_MS: u64 = 15000;
/// The keep alive max interval
pub const KEEP_ALIVE_TIMEOUT_NS: i64 = (KEEP_ALIVE_INTERVAL_MS * 3 * 1_000_000) as i64;
// 1ms = 1 million ns
/// Timeout for the drill update subroutine
pub const DRILL_UPDATE_TIMEOUT_NS: i64 = KEEP_ALIVE_TIMEOUT_NS;
/// For setting up the GroupReceivers
pub const GROUP_TIMEOUT_MS: usize = KEEP_ALIVE_INTERVAL_MS as usize;
///
pub const INDIVIDUAL_WAVE_TIMEOUT_MS: usize = GROUP_TIMEOUT_MS / 2;
///
pub const DO_DEREGISTER_EXPIRE_TIME_NS: i64 = KEEP_ALIVE_TIMEOUT_NS;

/// The frequency at which KEEP_ALIVES need to be sent through the system
pub const FIREWALL_KEEP_ALIVE_UDP: std::time::Duration = std::time::Duration::from_secs(60);
/// The largest size, in bytes, that a single group can hold (~8 Megs)
pub const MAX_GROUP_SIZE_BYTES: usize = 1_000_000 * 8;
/// How many bytes are stored
pub const CODEC_BUFFER_CAPACITY: usize = u16::MAX as usize;
/// The minimum number of bytes allocated in the codec
pub const CODEC_MIN_BUFFER: usize = 8192;
/// After the time defined below, any incomplete packet groups will be discarded
pub const GROUP_EXPIRE_TIME_MS: std::time::Duration = std::time::Duration::from_millis(60000);
/// After this time, the registration state is invalidated
pub const DO_REGISTER_EXPIRE_TIME_MS: std::time::Duration = std::time::Duration::from_millis(10000);
/// After this time, the connect state is invalidated
pub const DO_CONNECT_EXPIRE_TIME_MS: std::time::Duration = std::time::Duration::from_millis(8000);
/// After this timeout,
pub const UPNP_FIREWALL_LOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(1500);
pub const MULTIPORT_START: u16 = 25000;
///
//pub const MULTIPORT_END: u16 = hyxe_crypt::drill::PORT_RANGE as u16 + MULTIPORT_START;
pub const MULTIPORT_END: u16 = 1 + MULTIPORT_START;
///
pub const PRIMARY_PORT: u16 = 25021;
/// The minimum time (in nanoseconds) per drill update (nanoseconds per update)
pub const DRILL_UPDATE_FREQUENCY_LOW_BASE: u64 = 1 * 480 * 1_000_000_000;
/// The minimum time (in nanoseconds) per drill update (nanoseconds per update)
pub const DRILL_UPDATE_FREQUENCY_MEDIUM_BASE: u64 = 1 * 480 * 1_000_000_000;
/// The minimum time (in nanoseconds) per drill update (nanoseconds per update)
pub const DRILL_UPDATE_FREQUENCY_HIGH_BASE: u64 = 1 * 480 * 1_000_000_000;
/// The minimum time (in nanoseconds) per drill update (nanoseconds per update)
pub const DRILL_UPDATE_FREQUENCY_ULTRA_BASE: u64 = 1 * 480 * 1_000_000_000;
/// The minimum time (in nanoseconds) per drill update (nanoseconds per update)
pub const DRILL_UPDATE_FREQUENCY_DIVINE_BASE: u64 = 1 * 480 * 1_000_000_000;
/// For ensuring that the hole-punching process begin at about the same time (required)
/// this is applied to the ping. If the ping is 200ms, the a multiplier of 2.0 will mean that in 200*2.0 = 400ms,
/// the hole-punching process will begin
pub const HOLE_PUNCH_SYNC_TIME_MULTIPLIER: f64 = 2.0f64;
/// The maximum number of signals per peer mailbox
pub const PEER_EVENT_MAILBOX_SIZE: usize = 50;
///
pub const TIMED_TICKET_LIFETIME: std::time::Duration = std::time::Duration::from_secs(30);
/// the preconnect + connect stage will be limited by this duration
pub const LOGIN_EXPIRATION_TIME: std::time::Duration = std::time::Duration::from_secs(8);
/// Every 30 minutes, resync the clocks. This was to fix bugs related to long-lasting connections and reconnections
pub const NTP_RESYNC_FREQUENCY: std::time::Duration = std::time::Duration::from_secs(60*30);
///
pub const TCP_CONN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(4);
///
#[cfg(feature = "single-threaded")]
pub const PACKET_PROCESS_LIMIT: Option<usize> = Some(1);
///
#[cfg(not(feature = "single-threaded"))]
pub const PACKET_PROCESS_LIMIT: Option<usize> = None;
