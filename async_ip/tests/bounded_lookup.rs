//! An IP lookup ends on its own bounds, whatever the service does: an answer longer than one
//! address is refused as soon as it is, and a service that never answers is given up on.
#![cfg(not(target_family = "wasm"))]

use async_ip::{get_ip_from, EXTERNAL_IP_LOOKUP_TIMEOUT, MAX_IP_RESPONSE_BYTES};
use citadel_io::tokio;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Serves one connection: reads the request, then writes `head` and, when `endless`, body
/// bytes until the client hangs up.
async fn serve_once(head: &'static str, endless: bool) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let _server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 1024];
        let _ = stream.read(&mut request).await;
        if stream.write_all(head.as_bytes()).await.is_err() {
            return;
        }
        while endless && stream.write_all(&[b'1'; 1024]).await.is_ok() {}
        // A non-endless server holds the connection open without answering further.
        std::future::pending::<()>().await;
    });
    url
}

#[tokio::test]
async fn an_endless_answer_is_refused_at_the_size_bound() {
    let url = serve_once("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", true).await;
    let err = get_ip_from(None, &url).await.unwrap_err().to_string();
    assert!(
        err.contains(&format!("longer than {MAX_IP_RESPONSE_BYTES} bytes")),
        "{err}"
    );
}

#[tokio::test]
async fn a_declared_length_past_the_bound_is_refused_before_reading() {
    let url = serve_once(
        "HTTP/1.1 200 OK\r\nContent-Length: 1000000000\r\n\r\n",
        false,
    )
    .await;
    let err = get_ip_from(None, &url).await.unwrap_err().to_string();
    assert!(
        err.contains(&format!("longer than {MAX_IP_RESPONSE_BYTES} bytes")),
        "{err}"
    );
}

/// A service that accepts and never answers. On the paused clock the wait for its answer
/// advances straight to whichever deadline comes first: the lookup's own, or the test's.
#[tokio::test(start_paused = true)]
async fn a_silent_service_is_given_up_on_at_the_lookup_timeout() {
    let url = serve_once("", false).await;
    let outcome = tokio::time::timeout(
        EXTERNAL_IP_LOOKUP_TIMEOUT + Duration::from_secs(1),
        get_ip_from(None, &url),
    )
    .await
    .expect("the lookup outlived its timeout");
    assert!(outcome.is_err(), "{outcome:?}");
}
