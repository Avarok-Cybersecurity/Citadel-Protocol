pub mod response;

pub use crate::client::response::*;

use futures::stream::StreamExt;
use http::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, RETRY_AFTER};
use hyper::{
    client::{Client as HttpClient, HttpConnector},
    Body, Request, StatusCode,
};
use hyper_tls::{self, HttpsConnector};
use crate::message::Message;
use serde_json;

/// An async client for sending the notification payload.
pub struct Client {
    http_client: HttpClient<HttpsConnector<HttpConnector>>,
}

impl Client {
    /// Get a new instance of Client.
    pub fn new() -> Client {
        let mut http_client = HttpClient::builder();
        http_client.pool_max_idle_per_host(std::usize::MAX);

        Client {
            http_client: http_client.build(HttpsConnector::new()),
        }
    }

    /// Try sending a `Message` to FCM.
    pub async fn send(&self, message: Message<'_>) -> Result<FcmResponse, FcmError> {
        let payload = serde_json::to_vec(&message.body).unwrap();

        let builder = Request::builder()
            .method("POST")
            .header(CONTENT_TYPE, "application/json")
            .header(
                CONTENT_LENGTH,
                format!("{}", payload.len() as u64).as_bytes(),
            )
            .header(AUTHORIZATION, format!("key={}", message.api_key).as_bytes())
            .uri("https://fcm.googleapis.com/fcm/send");

        let request = builder.body(Body::from(payload)).unwrap();
        let requesting = self.http_client.request(request);

        let response = requesting.await?;
        let response_status = response.status();

        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|ra| ra.to_str().ok())
            .and_then(|ra| RetryAfter::from_str(ra));

        let content_length: usize = response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|s| s.to_str().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let mut body: Vec<u8> = Vec::with_capacity(content_length);
        let mut chunks = response.into_body();

        while let Some(chunk) = chunks.next().await {
            body.extend_from_slice(&chunk?);
        }

        match response_status {
            StatusCode::OK => {
                let fcm_response: FcmResponse = serde_json::from_slice(&body).unwrap();

                match fcm_response.error {
                    Some(ErrorReason::Unavailable) => {
                        Err(response::FcmError::ServerError(retry_after))
                    }
                    Some(ErrorReason::InternalServerError) => {
                        Err(response::FcmError::ServerError(retry_after))
                    }
                    _ => Ok(fcm_response),
                }
            }
            StatusCode::UNAUTHORIZED => Err(response::FcmError::Unauthorized),
            StatusCode::BAD_REQUEST => Err(response::FcmError::InvalidMessage(
                "Bad Request".to_string(),
            )),
            status if status.is_server_error() => {
                Err(response::FcmError::ServerError(retry_after))
            }
            _ => Err(response::FcmError::InvalidMessage(
                "Unknown Error".to_string(),
            )),
        }
    }
}
