//! Herein, each mod is categorized by action type

/// This is a fundamental flag category that encompasses most traffic on the HyperNetwork.
/// § Reserved Section 0 - 9
pub mod send_data {
    /// A flag that alerts the central server or client that a raw encrypted data transmission is taking place.
    /// This is used for sending data in these directions:
    /// [0] HyperLAN Client -> HyperLAN Server
    /// [1] HyperLAN Client -> HyperLAN Server -> HyperWAN Server
    /// [2] HyperLAN Client -> HyperLAN Server -> HyperWAN Server -> HyperWAN Client
    /// [3] HyperLAN Server -> HyperLAN Client
    /// [4] HyperLAN Server -> HyperWAN Server
    /// [5] HyperLAN Server -> HyperWAN Server -> HyperWAN Client
    /// Before this is sent, it is necessary that the two nodes are CONNECTED to each other. If they are not connected,
    /// then this signal will be negatively rebounded upon arrival at the central server.
    pub const SEND_DATA: u8 = 0;

    /// This flag implies that data is to be uploaded to the sending client's HyperLAN server. This is useful for syncing
    /// data. This is one of the fundamental signals used to construct the metaphor of the [Baker's Stand].
    pub const UPLOAD_DATA: u8 = 1;
    /// This is rebounded to the client once the data has been successfully uploaded
    pub const UPLOAD_DATA_SUCCESS: u8 = 2;
    /// This is rebounded to the client if the server did not successfully reconstruct and store the data
    pub const UPLOAD_DATA_FAILURE: u8 = 3;
}

/// connect signals
/// § Reserved Section 10-29
pub mod connect {
    /// The signal sent by a client. The DO_LOGIN packet must have a complete header coupled with a payload
    /// that is equal to the big-endian ordered bytes of the username, comma, password. Furthermore, the PID and WID must be
    /// equal to the Zeroth Index value of the drill
    pub const DO_LOGIN: u8 = 10;
    /// The signal returned by the server in the case of a successful connect
    pub const DO_LOGIN_SUCCESS: u8 = 11;
    /// The signal returned by the client in the case of a failed connect (e.g., bad credentials)
    pub const DO_LOGIN_FAILURE: u8 = 12;

    /// Used to connect to a HyperLAN client. The client sends a signal to the server, and then the server sends a
    /// HYPERLAN_CLIENT_CONNECT_REQUEST to the target HyperLAN client. If the HyperLAN client accepts, then a
    /// HYPERLAN_CLIENT_CONNECT_ACCEPT signal is sent to the server, and then forwarded to the initial client.
    pub const HYPERLAN_CLIENT_CONNECT: u8 = 13;
    /// See: [HYPERLAN_CLIENT_CONNECT]. A signal sent from the central server to the target HyperLAN client
    pub const HYPERLAN_CLIENT_CONNECT_REQUEST: u8 = 14;
    /// A signal sent from the target HyperLAN client back to the central server where the signal is propagated therefrom
    pub const HYPERLAN_CLIENT_CONNECT_ACCEPT: u8 = 15;
    /// A signal sent from the target HyperLAN client back to the central server where the signal is propagated therefrom
    pub const HYPERLAN_CLIENT_CONNECT_REJECT: u8 = 16;

    /// Used to connect to a HyperWAN client. The client sends a signal to the server, and then the server sends a
    /// HYPERLAN_CLIENT_CONNECT_REQUEST to the target HyperWAN client's central server. The central server then
    /// propagates this signal to the target HyperWAN client. If the HyperWAN client accepts, then a
    /// HYPERWAN_CLIENT_CONNECT_ACCEPT signal is sent to the HyperWAN server, then forwarded to the HyperLAN server,
    /// and then forwarded to the initial client.
    pub const HYPERWAN_CLIENT_CONNECT: u8 = 17;
    /// See: [HYPERWAN_CLIENT_CONNECT]. A signal sent from the central server to the target HyperWAN client's central server
    pub const HYPERWAN_CLIENT_CONNECT_REQUEST: u8 = 18;
    /// A signal sent from the target HyperLAN client back to the central server where the signal is propagated therefrom
    pub const HYPERWAN_CLIENT_CONNECT_ACCEPT: u8 = 19;
    /// A signal sent from the target HyperLAN client back to the central server where the signal is propagated therefrom
    pub const HYPERWAN_CLIENT_CONNECT_REJECT: u8 = 20;
}

/// drill update flags
/// § Reserved Section 30-39
pub mod drill_update {
    /// A signal sent from the server to the client. It is imprinted upon an OBJECT_HEADER or PACKET_SINGLETON type (depends
    /// on size).
    pub const DO_DRILL_UPDATE: u8 = 30;
    /// There is no longer a need for DO_DRILL_UPDATE_SUCCESS, because it is redundant when all the client has to do is send
    /// a packet with the updated drill version to prove that the client received the new version
    /// pub const DO_DRILL_UPDATE_SUCCESS: u8 = 31;

    /// This is useful for verifying that the locally stored toolset contains the correct versioning sequence relative to the
    /// server
    pub const GET_DRILL_STATS: u8 = 31;
}

/// client scan flags
/// § Reserved Section 40-49
pub mod scan {
    /// A request sent from a HyperLAN client to the HyperLAN server looking for available clients to connect-to.
    /// This only shows mutually-agreed relationships. For scanning potential relationships that the HyperLAN Server
    /// contains, use SCAN_POTENTIAL_HYPERLAN. This used for checking the status of connections before running the step
    /// HYPERLAN_CLIENT_CONNECT
    pub const SCAN_HYPERLAN: u8 = 40;

    /// Scans for potential clients within the client's HyperLAN. The server will only return a list of HyperLAN clients that
    /// the requesting client has not yet entered into a mutually-agreed relationship. A client who wishes to enter a relationship
    /// with a potential HyperLAN client must enter into an agreement via DO_HYPERLAN_CLIENT_REGISTER.
    pub const SCAN_POTENTIAL_HYPERLAN: u8 = 41;
    /// A request sent from a HyperLAN client to the HyperLAN server looking for available clients to connect-to but in the HyperWAN
    /// This only shows mutually-agreed relationships. For scanning potential relationships that the HyperLAN Server
    /// contains, use SCAN_POTENTIAL_HYPERWAN. This used for checking the status of connections before running the step
    /// HYPERWAN_CLIENT_CONNECT
    pub const SCAN_HYPERWAN: u8 = 42;

    /// Scans potential peers out in the HyperWAN
    pub const SCAN_POTENTIAL_HYPERWAN: u8 = 43;
    /// A signal sent from the HyperLAN server signalling that the scan was a success. This may come in an OBJECT_HEADER if the scan returns
    /// a list that is larger than 1 packet
    pub const SCAN_SUCCESS: u8 = 44;
    /// Used to signify that the scan was a failure. In this case, the payload is empty unless a [Cause] is specified
    pub const SCAN_FAILURE: u8 = 45;
}

/// HyperLAN registration flags
/// § Reserved Section 50-59
pub mod registration {
    /// This is the signal that a client sends to the central server invoking it to send a REQUEST_HYPERLAN_CLIENT_REGISTER to the proposed
    /// HyperLAN client
    pub const DO_HYPERLAN_CLIENT_REGISTER: u8 = 50;

    /// This is the signal that a client sends to the central server invoking it to send a REQUEST_HYPERWAN_CLIENT_REGISTER signal to the
    /// proposed HyperWAN client's central server
    pub const DO_HYPERWAN_CLIENT_REGISTER: u8 = 51;

    /// This is the signal sent from the HyperLAN central server to the proposed client asking for mutual permission to enter into a relationship
    pub const REQUEST_HYPERLAN_CLIENT_REGISTER: u8 = 52;

    /// This is the signal sent from the HyperWAN central server to the proposed HyperWAN client asking for mutual permission with the HyperLAN client
    /// to into a relationship
    pub const REQUEST_HYPERWAN_CLIENT_REGISTER: u8 = 53;

    /// This is the signal sent from the HyperLAN client back to the HyperLAN server, and in turn forwarded to the original HyperLAN client to check
    /// signal that the relationship is now forged, and data is now transmittable between both nodes with guidance of the shared central server
    pub const ACCEPT_HYPERLAN_CLIENT_REGISTER: u8 = 54;

    /// This is the signal sent from the HyperWAN client back to the HyperWAN server, then forwarded to the HyperLAN server, and in turn forwarded to
    /// the original HyperLAN client to signal that the relationship is now forged, and data is now transmittable between both nodes with guidance of
    /// the chained central servers
    pub const ACCEPT_HYPERWAN_CLIENT_REGISTER: u8 = 55;

    /// The negation of [ACCEPT_HYPERLAN_CLIENT_REGISTER]
    pub const DENY_HYPERLAN_CLIENT_REGISTER: u8 = 56;

    /// The negation of [ACCEPT_HYPERWAN_CLIENT_REGISTER]
    pub const DENY_HYPERWAN_CLIENT_REGISTER: u8 = 57;
}

/// network map update flags
/// § Reserved Section 60-69
pub mod network_map_update {
    /// This is ran once a client makes their first registration + connection to a server. This can also be called
    /// if the user has a corrupt local network map
    pub const REQUEST_FRESH_MAP: u8 = 50;

    /// Called by the central server when it causes a [ClientViewport] synchronization with one of its clients.
    pub const MAP_UPDATE: u8 = 51;

    /// Called when a HyperLAN server wants to connect to an HyperWAN client, and then the HyperLAN Server determines that
    /// the map is out-of-date. This can also be called when the server starts-up, and then polls nearby servers for a version
    /// update (if necessary).
    pub const INTERSERVER_MAP_UPDATE: u8 = 52;
}