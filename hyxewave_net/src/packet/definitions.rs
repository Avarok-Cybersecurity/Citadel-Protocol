use hyxe_netdata::connection::{ProtocolConfig, EncodingConfig, IpVersion};

/// IPv4 is hereby deprecated for use within this program, including its API layer. If I want to take the lead into the IoT, then I will need to change
/// the lower-level API to reflect that mission. One quick way is by deprecating the use of IPv4, and preferring IPv6 when available.
pub const PREFER_IPV6: bool = true;
/// The default IpVersion, reflected by the reasoning above
pub const DEFAULT_IP_VERSION: IpVersion = IpVersion::V6;
/// We also need to reflect this in our local binding address for the server listener
pub const LOCAL_BIND_ADDR: &str = get_bind_addr();
const fn get_bind_addr() -> &'static str {
    if PREFER_IPV6 {
        "[::]"
    } else {
        "0.0.0.0"
    }
}

/// The start port. This should be constant between all nodes in the HyperLAN
pub const PORT_START: u16 = 25000;

/// The end port (up to this value, but not inclusive of this value)
pub const PORT_END: u16 = 25020;

/// These ports are used for asynchronous routines like the login service [25020] or the registration service [25021]
pub const DEFAULT_AUXILIARY_PORTS: &[u16; 2] = &[25020, 25021];

/// The login port (for clients which already are registered)
pub const LOGIN_PORT: u16 = DEFAULT_AUXILIARY_PORTS[0];

/// The registration port (for client which are not yet registered)
pub const REGISTRATION_PORT: u16 = DEFAULT_AUXILIARY_PORTS[1];

/// This will change in the conceivable future. Once the MVP of HyxeWave is completed, I'll make a custom layer 3/4 networking program
pub const DEFAULT_NETWORK_STACK_PROTOCOL: ProtocolConfig = ProtocolConfig::TCP;

/// The encoder/decoder used for safely transmitting data across the web. Unlike standard Base64, we use a custom line terminator `\n`. For this
/// reason, higher-level programs that transmit plaintext data will need to transform all `\n`s into a new character
pub const DEFAULT_ENCODING_SCHEME: EncodingConfig = EncodingConfig::Base64;



/// The wave header is a packet type which has the sole function of alerting a receiving node that a wave of data with a fixed `eid_oid` is expected.
/// As such, the [OBJECT_HEADER] creates an expectancy at stage2. NOTE: IT IS NECESSARY THAT THIS PACKET REACHES THE RECIPIENT NODE BEFORE THE WAVE
/// COMPONENTS GET SENT OUTBOUND.
///
/// Requirements:
/// [1] The header must have a nonzero `eid_oid` which is equivalent to the eid_oid of the incoming wave
/// [2] The header must have a wid and pid which inversely map to the number of waves and total number of packets
///     [2] => [DEV NOTE] With the total number of packets known, this gives the information needed for stage 2 to know "when" to reconstruct the data
/// [3] the `command_flag` in the header must be set to `OBJECT_HEADER` below
///     [3] => This signals the stage 2 handler to
/// [4] The payload's first value should be the total number of bytes of the dataset in the entire wave. This is for allocating the proper amount of data. IT should be a [u64 big-endian] value
/// [5] The payload must have an array values (e.g., 0,1,2,4,6...) which correspond to the total number of packets per layer. We need
/// this information because the drill may be changed midway through the encryption stage, and as such, the packet layout may change too. Each value should be a [u16 big-endian] value.
///
/// Payload example: 7777,10,4,2,11,19, (no commas; just BE-encoded u16's side-by-side-by-side)...
pub const OBJECT_HEADER: u8 = 200;

/// Every packet following the [OBJECT_HEADER] should be marked with an [OBJECT_PAYLOAD] command flag in the headers
pub const OBJECT_PAYLOAD: u8 = 201;

/// A singleton packet is a packet which is either going to fulfill a local expectancy or trigger an expectancy.
/// Examples of singletons:
/// [1] Signals (KEEP_ALIVE's, DO_LOGINS)
pub const SINGLETON_PACKET: u8 = 202;

/// This determines when a singleton expectancy is to be timed-out.
/// There is no defined timeout for objects because they may be arbitrarily large. Instead, the timeout is a function
/// of the world-wide average download speed
///
/// Used in: [BridgeHandler], [ServerBridgeHandler]
pub const SINGLETON_EXPECTANCY_TIMEOUT: u64 = 2000;

/// (As of 2019) in bytes per second (22Mbps/s * 1/8 = 2.75 Mb/s = 2,750,000 bytes/second)
pub const AVERAGE_WORLDWIDE_DOWNLOAD_RATE: usize = 2_750_000;
/// TODO: DO_LOGINs need to be parsed for a NetworkAccount, because when a local CNAC is loaded, Serde skips the nac field. Before Session::new_client(..) is called, a NAC is needed

/// Pinned IP mode is especially useful for LAN networks such as a enterprise or small business settings. In pinned-IP mode, connected clients are necessarily expected to have the same
/// IP address as their previous connection. This adds an additional layer of security. If pinned-IP mode is disabled, then a client may connect from different IP addresses between logins.
/// (The rule of 1 IP per LOGIN still always holds regardless of the state of this setting)
pub const PINNED_IP_MODE: bool = true;

/// Contains the definitions needed to construct the registration mechanism. The causal chain, in its larger steps, is n=8 steps long.
///
/// Registration is what allows a new client to log-in to either a HyperLAN or HyperWAN server. While the two are very similar with an unregistered client,
/// the difference is that registering to a HyperLAN server implies a direct connection, whereas registering to a HyperWAN Server implies a client connection via
/// a HyperLAN server
///
/// For each packet header, the `oid_eid` is the stage value as given below. Specifically, it points to the next stage that must be executed by the receiving node
///
/// § Reserved Section 50s
pub mod registration {
    /// This is not counted as a step, but is the state in which the client loads tubing to prepare for stage0_client
    pub const STAGE0_CLIENT_PENDING: u8 = 10;

    /// The client initiates the registration process by sending a [DO_HYPERLAN_CLIENT_REGISTER] or a [DO_HYPERWAN_CLIENT_REGISTER] signal to the target server. This signal must have
    /// the payload in the following format: is_hyperlan (0 or 1), username, password, full_name
    pub const STAGE0_CLIENT: u8 = 0;

    /// Stage 0 for the server involves receiving either a stream at the server-loopback [BridgeHandler] level, and thereafter, injecting the tubing into a [TemporaryBridge] at the [RegistrationHandle] level.
    /// This primes it for Stage 1, but must first await a packet before it may proceed
    pub const STAGE0_SERVER: u8 = 1;

    /// The server then immediately receives a packet in the form of either a [DO_HYPERLAN_CLIENT_REGISTER] or a [DO_HYPERWAN_CLIENT_REGISTER]. It performs a lookup in both the [NetworkMap] and [AccountManager]
    /// to ensure that both: 1) a new client can be accommodated, and; 2) that the client's requested username is possible. If either 1) or 2) fails, then a [DENY_HYPERLAN_CLIENT_REGISTER] is sent outbound with
    /// the appropriate reason in the payload of the packet. Else... then the registration is entirely possible. As such, a [ACCEPT_HYPERLAN/WAN_CLIENT_REGISTER] is sent with a NONCE, thus triggering an expectancy within the
    /// adjacent client and causing [STAGE1_CLIENT] to occur. During this period of time, the server asynchronously generates the serializable CNAC with its local [NetworkAccount]. The server will enter [STAGE2_SERVER]
    /// once the CNAC is generated.
    pub const STAGE1_SERVER: u8 = 2;

    /// The client receives either an accept or deny signal of a [DO_HYPERLAN/WAN_CLIENT_REGISTER]. In the case of a DENY, the causal chain ends. Else, then the client creates an [ObjectExpectancy] to await for the
    /// serialized [ClientNetworkAccount]
    pub const STAGE1_CLIENT: u8 = 3;

    /// The server has generated the CNAC with a cæsarian cipher applied thereto equal to the NONCE generated back in [STAGE1_SERVER]. This is sent ontop of a TLS socket, and is thus doubly encrypted. The only way to
    /// break it is by snooping-in during [STAGE1_SERVER] to receive the ACCEPT packet, break the TLS layer, and thereafter, obtain the raw cæsarian key. This implies knowledge of the elliptical curve used, as this is
    /// what is implied by breaking an (asymmetric) public key system like TLS. As such, only members of the government, the cabal, etc can hack this layer.
    ///
    /// The server, having sent the object, now injects a [SingletonExpectancy] into the [StageDriver], awaiting for a valid zero-index PID and WID in a [DO_HYPERLAN/WAN_CLIENT_REGISTER] signal
    pub const STAGE2_SERVER: u8 = 4;

    /// Once the CNAC is generated, it sends an acknowledgement back to the HyperLAN/WAN central server. The acknowledgement is a [DO_HYPERLAN/WAN_CLIENT_REGISTER] with a correct
    /// zero-index PID and WID. A [SingletonExpectancy] is injected to await the final response from the server. The client is now complete with [STAGE2_CLIENT]
    pub const STAGE2_CLIENT: u8 = 5;

    /// The server receives the correct zero-index PID and WID in a [DO_HYPERLAN/WAN_CLIENT_REGISTER] signal. If the zero-indexes are wrong, then the registration process is aborted and the causal chain ends. Else, the server
    /// can now locally serialize the CNAC via the [AccountManager], and thereafter, update the records in the [NetworkMap], and finally, updates both to the local filesystem.
    ///
    /// The server concludes the registration process by sending the final [ACCEPT_HYPERLAN/WAN_CLIENT_REGISTER] signal, followed by a custom welcome message as set in the server.hfg file
    pub const STAGE3_SERVER: u8 = 6;

    /// Upon success, the client's [SingletonExpectancy] is received, and thereafter, can now login to the system as needed. The registration is now 100% complete
    pub const STAGE3_CLIENT: u8 = 7;

    /// For internally signalling the receiving client that the registration process is complete
    pub const REGISTRATION_COMPLETE: u8 = 8;

    /// For internally denoting that a [RegistrationProcess] was unsuccessful
    pub const REGISTRATION_FAILURE: u8 = 9;
}