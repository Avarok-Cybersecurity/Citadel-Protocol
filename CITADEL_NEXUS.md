# SPECIFICATION for Citadel Nexus

### Overview

We want to abstract I/O operations from the Citadel Protocol. This will allow us to use different I/O backends for different use cases. Namely, we want to be able to compile to WASM target, for full web support. If we build to a normal target, however, we will just use the normal implementation that is already implemented in most cases. For IO, most code we need to look for is the networking-related code. A good portion of it can be found in @citadel_proto/src/proto/node.rs. Though, it is dotted around in a handful of places, such as @citadel_wire and the other portions of @citadel_proto. 

### Architecture Overview

The architecture of the Citadel Nexus is as follows:

```
citadel_io -> (citadel_wire + citadel_crypt + citadel_user) -> citadel_nexus -> citadel_proto -> citadel_sdk
```

The idea is that we have citadel_nexus as a middleman between the Citadel SDK and the I/O layer - so it is moreso on the same level hierarchically as citadel_wire, citadel_crypt, and citadel_user. This will allow us to use different I/O backends for different use cases. Namely, we want to be able to compile to WASM target, for full web support. If we build to a normal target, however, we will just use the normal implementation that is already implemented in most cases. 

### Example of the flow we want

The naming should be improved. In your plan, you should come up with better naming conventions for this. I primarily mean the Trait name and potentially the structs. For example, the trait could be more like `CitadelNexusInterface`, `CitadelIOInterface`, or something similar. 

```rust
#[auto_impl(Arc)]
#[async_trait]
pub trait CitadelProtocolIOFunctions<R: Ratchet> {
    // Types for C2S
    type OrderedReliableListener: Stream<Item=Self::OrderedReliableListener> + Send + Sync + 'static;
    type OrderedReliableNetworkStream: Send + Sync + 'static;
    type UnorderedUnreliableNetworkStream: Send + Sync + 'static;

    // Types for p2p
    type OrderedReliableListenerP2P: Stream<Item=Self::OrderedReliableListenerP2P> + Send + Sync + 'static;
    type OrderedReliableNetworkStreamP2P: Send + Sync + 'static;
    type UnorderedUnreliableNetworkStreamP2P: Send + Sync + 'static;

    async fn create_unreliable_unordered_stream(bind_addr: SocketAddr) -> Result<Self::UnorderedUnreliableNetworkStream, Error>;
    // Functions for the Citadel Protocol that interface with I/O
    async fn get_ip_address_info() -> Result<IpAddressInfo, CitadelError>;

    async fn determine_nat_type(&self, stun_servers: Option<Vec<String>>) -> Result<NatType, FirewallError>;
    async fn get_listener(&self) -> Result<Self::OrderedReliableListener, FirewallError>;

    // Arc<dyn ReliableOrderedStreamToTarget>
    // Note: this is meant for constructing a NetworkEndpoint for the netbeam crate that helps
    // facilitate hole-punching with UDP
    // NOTE: TBD if should exist here or if elsewhere in the code, or, composed differently
    // async fn create_reliable_ordered_stream_to_target(&self) -> Arc<dyn ReliableOrderedStreamToTarget>;
    async fn create_udp_hole_puncher<T: ReliableOrderedStreamToTarget + 'static>(&self, node_type: RelativeNodeType, config: HolePunchConfigContainer, stream: T) -> UdpHolePuncher<'_, Self::UnorderedUnreliableNetworkStream> {
        let network_application = netbeam::sync::network_application::NetworkApplication::new(node_type, stream);
        let hole_puncher = UdpHolePuncher::new(&network_application, config);
        Ok(hole_puncher)
    }

    // Note: in citadel_proto/src/proto/node.rs, you will find required functions
    async fn listen(&self) {
        let listener = self.get_listener().await.unwrap();
        while let Some(incoming) = listener.next().await {
            let incoming = incoming.unwrap();
        }
    }
}

pub struct CitadelStd;

impl<R: Ratchet> CitadelProtocolIOFunctions<R> for CitadelStd {
    type OrderedReliableListener = citadel_io::tokio::net::TcpListener;
    type OrderedReliableNetworkStream = citadel_io::tokio::net::TcpStream;
    type UnorderedUnreliableNetworkStream = citadel_io::tokio::net::UdpSocket;

    // NOTE: The GenericNetworkListener/Stream types will need to be moved out of citadel_proto
    type OrderedReliableListenerP2P = citadel_proto::GenericNetworkListener;
    type OrderedReliableNetworkStreamP2P = citadel_proto::GenericNetworkStream;
    type UnorderedUnreliableNetworkStreamP2P = citadel_proto::UdpChannel<R>;

    async fn determine_nat_type(&self, stun_servers: Option<Vec<String>>) -> Result<NatType, FirewallError> {
        NatType::identify(stun_servers).await
    }
}
```