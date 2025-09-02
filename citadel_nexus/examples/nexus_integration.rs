use std::net::SocketAddr;
use citadel_nexus::std::StdIOProvider;
use citadel_nexus::traits::{CitadelIOInterface, NetworkListener, DatagramSocket};

#[citadel_io::tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Citadel Nexus Integration Example");
    
    // Create a standard IO provider
    let io_provider = StdIOProvider::new().await?;
    
    // Test basic TCP functionality
    let bind_addr: SocketAddr = "127.0.0.1:0".parse()?;
    let listener = io_provider.bind_tcp(bind_addr).await?;
    let local_addr = listener.local_addr()?;
    
    println!("TCP Listener bound to: {}", local_addr);
    
    // Test UDP functionality  
    let udp_socket = io_provider.bind_udp(bind_addr).await?;
    let udp_local_addr = udp_socket.local_addr()?;
    
    println!("UDP Socket bound to: {}", udp_local_addr);
    
    // Get platform info
    let platform_info = io_provider.platform_info();
    println!("Platform: {} with features: {:?}", platform_info.name, platform_info.features);
    
    // Test IP info
    let ip_info = io_provider.get_local_ip_info().await?;
    println!("Local IP info: {:?}", ip_info);
    
    println!("✓ Citadel Nexus integration working successfully!");
    
    Ok(())
}