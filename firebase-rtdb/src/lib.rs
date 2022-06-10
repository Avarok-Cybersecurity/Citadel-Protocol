#![allow(non_snake_case)]

use reqwest::{Client, Response};
use std::time::{Duration, Instant};
use std::error::Error;
use reqwest::header::CONTENT_TYPE;
use serde::{Serialize, Deserialize};
use std::str::FromStr;

#[derive(Clone, Debug)]
pub struct FirebaseRTDB {
    pub base_url: String,
    client: Client,
    pub auth: AuthResponsePayload,
    pub expire_time: Instant,
    pub api_key: String,
    pub jwt: String
}

pub const DEFAULT_EXPIRE_BUFFER_SECS: Duration = Duration::from_secs(5);

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct AuthResponsePayload {
    pub idToken: String,
    pub refreshToken: String,
    pub expiresIn: String
}

pub struct Node<'a> {
    string_builder: String,
    client: &'a Client,
    token: &'a String
}

#[derive(Debug)]
pub struct RtdbError {
    pub inner: String
}

impl<E: Error> From<E> for RtdbError {
    fn from(err: E) -> Self {
        Self { inner: err.to_string() }
    }
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

impl FirebaseRTDB {
    /// `project_url`: e.g., https://PROJECT_ID.firebaseio.com/
    ///
    /// This will contact the authorization server in order to get the proper values
    pub async fn new_from_jwt<T: Into<String>, R: Into<String>, V: AsRef<str>>(project_url: T, jwt: R, api_key: V) -> Result<Self, RtdbError> {
        let jwt = jwt.into();

        //let token = resp.get("token").ok_or_else(|| RtdbError { inner: "Payload did not contain token".to_string() })?;
        let base_url = project_url.into();
        let api_key = api_key.as_ref();
        let client = Self::build_client()?;

        #[derive(Serialize)]
        struct AuthPayload {
            token: String,
            returnSecureToken: bool
        }

        let payload = AuthPayload { token: jwt.clone(), returnSecureToken: true };
        // auth first
        let resp: AuthResponsePayload = client.post(format!("https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key={}", api_key)).header(CONTENT_TYPE, "application/json").json(&payload).send().await?.json().await?;
        log::trace!(target: "lusna", "RESP AUTH: {:?}", resp);

        let expire_time = Instant::now() + Duration::from_secs(u64::from_str(resp.expiresIn.as_str())?);

        Ok(Self { base_url, client, auth: resp, expire_time, api_key: api_key.to_string(), jwt })
    }

    /// Use this if authentication already occurred, and the token is still valid
    pub fn new_from_token<T: Into<String>, R: Into<String>, V: Into<String>>(project_url: T, api_key: R, jwt: V, auth: AuthResponsePayload, expire_time: Instant) -> Result<Self, RtdbError> {
        let client = Self::build_client()?;

        Ok(Self { client, base_url: project_url.into(), auth, expire_time, api_key: api_key.into(), jwt: jwt.into() })
    }

    /// Unconditionally renews the token. Make sure to update internal client config afterwards as data could have changed
    pub async fn renew_token(&mut self) -> Result<(), RtdbError> {
        #[derive(Serialize)]
        struct RenewPayload {
            grant_type: String,
            refresh_token: String
        }

        #[derive(Deserialize, Debug)]
        struct RenewResponse {
            expires_in: String,
            #[allow(dead_code)]
            token_type: String,
            refresh_token: String,
            id_token: String,
            #[allow(dead_code)]
            user_id: String,
            #[allow(dead_code)]
            project_id: String
        }

        log::trace!(target: "lusna", "[RTDB] About to renew token");
        let payload = RenewPayload { grant_type: "refresh_token".to_string(), refresh_token: self.auth.refreshToken.clone() };

        let resp: RenewResponse = self.client.post(format!("https://securetoken.googleapis.com/v1/token?key={}", self.api_key.as_str())).header(CONTENT_TYPE, "application/x-www-form-urlencoded").json(&payload).send().await?.json().await?;

        log::trace!(target: "lusna", "RESP RENEW: {:?}", &resp);
        // update internal value using the new response
        let expire_time = Instant::now() + Duration::from_secs(u64::from_str(resp.expires_in.as_str())?);
        self.expire_time = expire_time;

        let auth = AuthResponsePayload {
            idToken: resp.id_token,
            refreshToken: resp.refresh_token,
            expiresIn: resp.expires_in
        };

        self.auth = auth;

        Ok(())
    }

    /// Returns true if the token expired. will need to be refreshed before use again
    pub fn token_expired(&self) -> bool {
        Instant::now() + DEFAULT_EXPIRE_BUFFER_SECS > self.expire_time
    }

    fn build_client() -> Result<Client, RtdbError> {
        Ok(Client::builder().use_native_tls().connect_timeout(CONNECT_TIMEOUT).tcp_nodelay(true).build()?)
    }

    /// Updates the token if required
    pub async fn root(&mut self) -> Result<Node<'_>, RtdbError> {
        if self.token_expired() {
            self.renew_token().await?
        }

        Ok(Node { string_builder: self.base_url.clone(), client: &self.client, token: &self.auth.idToken })
    }
}

impl Node<'_> {
    pub fn child<T: AsRef<str>>(&mut self, child: T) -> &mut Self {
        self.string_builder += child.as_ref();
        self.string_builder += "/";
        log::trace!(target: "lusna", "Builder: {:?}", &self.string_builder);
        self
    }

    pub fn final_node<T: AsRef<str>>(&mut self, node: T) -> &Self {
        self.string_builder += node.as_ref();
        self.string_builder += ".json";
        log::trace!(target: "lusna", "Builder: {:?}", &self.string_builder);
        self
    }

    pub async fn get(&self) -> Result<String, RtdbError> {
        let resp = self.client.get(format!("{}?auth={}", self.string_builder, self.token)).send().await?;
        Self::handle_response(resp).await
    }

    pub async fn put<T: Serialize>(&self, ref input: T) -> Result<String, RtdbError> {
        let resp = self.client.put(format!("{}?auth={}", self.string_builder, self.token)).json(input).send().await?;
        Self::handle_response(resp).await
    }

    pub async fn post<T: Serialize>(&self, ref input: T) -> Result<String, RtdbError> {
        let resp = self.client.post(format!("{}?auth={}", self.string_builder, self.token)).json(input).send().await?;
        Self::handle_response(resp).await
    }

    pub async fn patch<T: Serialize>(&self, ref input: T) -> Result<String, RtdbError> {
        let resp = self.client.patch(format!("{}?auth={}", self.string_builder, self.token)).json(input).send().await?;
        Self::handle_response(resp).await
    }

    pub async fn delete(&self) -> Result<String, RtdbError> {
        let resp = self.client.delete(format!("{}?auth={}", self.string_builder, self.token)).send().await?;
        Self::handle_response(resp).await
    }

    async fn handle_response(resp: Response) -> Result<String, RtdbError> {
        if resp.status().as_u16() == 200 {
            Ok(resp.text().await?)
        } else {
            Err(RtdbError { inner: resp.text().await? })
        }
    }
}