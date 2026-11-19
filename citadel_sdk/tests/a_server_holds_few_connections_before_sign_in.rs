#![cfg(not(target_family = "wasm"))]
//! A server holds at most its limit of connections from one address that have not signed in:
//! one more is closed at once, while those it holds stay open.

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use citadel_io::tokio;
    use citadel_io::tokio::io::AsyncReadExt;
    use citadel_sdk::prefabs::server::empty::EmptyKernel;
    use citadel_sdk::prelude::*;
    use citadel_sdk::test_common::{localhost_server_limits, server_test_node};
    use std::num::NonZeroUsize;
    use std::time::Duration;

    const PER_ADDRESS: usize = 2;

    /// Whether the server closed `stream` within `wait` (it sends its first packet either way).
    async fn closed_within(stream: &mut tokio::net::TcpStream, wait: Duration) -> bool {
        let mut sink = Vec::new();
        matches!(
            tokio::time::timeout(wait, stream.read_to_end(&mut sink)).await,
            Ok(Ok(_)) | Ok(Err(_))
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn one_connection_past_the_per_address_limit_is_closed() {
        citadel_logging::setup_log();
        let (server, addr) = server_test_node(EmptyKernel::<StackedRatchet>::default(), |b| {
            let _ = b.with_server_limits(ServerLimits {
                provisional_per_ip: NonZeroUsize::new(PER_ADDRESS).unwrap(),
                ..localhost_server_limits()
            });
        });
        let probe = async move {
            let mut held = Vec::new();
            for _ in 0..PER_ADDRESS {
                held.push(tokio::net::TcpStream::connect(addr).await.unwrap());
                // Accepted one at a time, in order.
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let mut extra = tokio::net::TcpStream::connect(addr).await.unwrap();
            assert!(
                closed_within(&mut extra, Duration::from_secs(5)).await,
                "a connection past the limit was held"
            );
            for stream in &mut held {
                assert!(
                    !closed_within(stream, Duration::from_millis(500)).await,
                    "a connection within the limit was closed"
                );
            }
        };
        tokio::select! {
            _ = server => panic!("the server ended"),
            () = probe => {}
        }
    }
}
