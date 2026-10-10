//! A Turnstile-like admission policy for the sign-in suites: it admits [`GOOD`] for the action
//! it was asked for, refuses anything else, and records every call.

use crate::common::pq::{pq_settings, PASSWORD};
use citadel_io::ErrorCode;
use citadel_sdk::async_trait;
use citadel_sdk::prelude::*;
use citadel_user::auth::pq::admission::{
    AdmissionContext, AdmissionPolicy, AdmissionRefusal, AdmissionToken,
};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const GOOD: &str = "turnstile-ok";

pub struct Turnstile {
    asked: Mutex<Vec<&'static str>>,
    grace: Duration,
}

impl Turnstile {
    /// A policy whose ended sessions' resume tokens count for `grace`.
    pub fn with_grace(grace: Duration) -> Self {
        Self {
            asked: Mutex::new(Vec::new()),
            grace,
        }
    }

    pub fn asked(&self) -> Vec<&'static str> {
        self.asked.lock().unwrap().clone()
    }
}

#[async_trait]
impl AdmissionPolicy for Turnstile {
    async fn admit(&self, ctx: AdmissionContext) -> Result<(), AdmissionRefusal> {
        self.asked.lock().unwrap().push(ctx.kind.action());
        assert!(
            ctx.remote_addr.is_some(),
            "the hook was not given the address"
        );
        match ctx.token.as_ref().map(AdmissionToken::as_str) {
            None => Err(AdmissionRefusal::Required),
            Some(GOOD) => Ok(()),
            Some(_) => Err(AdmissionRefusal::Failed("invalid-input-response".into())),
        }
    }

    fn resume_grace(&self) -> Duration {
        self.grace
    }
}

pub fn guarded(policy: Arc<Turnstile>) -> ServerMiscSettings {
    ServerMiscSettings {
        admission: Some(policy),
        ..pq_settings()
    }
}

pub fn code<T>(result: &Result<T, NetworkError>) -> Option<ErrorCode> {
    result.as_ref().err().map(|err| err.code)
}

pub async fn register(
    remote: &NodeRemote<StackedRatchet>,
    addr: std::net::SocketAddr,
    user: &str,
    token: Option<&str>,
) -> Result<RegisterSuccess, NetworkError> {
    let admission = token.map(str::to_string);
    remote
        .register_admitted(
            addr,
            user,
            user,
            PASSWORD,
            Default::default(),
            None,
            admission,
        )
        .await
}

pub async fn sign_in(
    remote: &NodeRemote<StackedRatchet>,
    user: &str,
    factors: SignInFactors,
) -> Result<CitadelClientServerConnection<StackedRatchet>, NetworkError> {
    remote
        .connect_with_defaults(AuthenticationRequest::sign_in(user.to_string(), factors))
        .await
}
