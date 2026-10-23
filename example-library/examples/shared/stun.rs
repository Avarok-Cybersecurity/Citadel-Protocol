//! The STUN servers an example node uses. They are required configuration: the SDK has no
//! default list. Set `CITADEL_STUN_SERVERS` to three or more distinct comma-separated
//! `host:port` endpoints.

use citadel_sdk::prelude::StunServers;

pub fn from_env() -> StunServers {
    std::env::var("CITADEL_STUN_SERVERS")
        .expect(
            "CITADEL_STUN_SERVERS not set: three or more comma-separated host:port STUN servers",
        )
        .parse()
        .expect("CITADEL_STUN_SERVERS is not a valid STUN server list")
}
