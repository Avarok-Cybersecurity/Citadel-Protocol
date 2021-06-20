#![allow(non_snake_case)]

use reqwest::{Client, Response};
use std::time::Duration;
use std::error::Error;
use reqwest::header::CONTENT_TYPE;
use serde::{Serialize, Deserialize};

#[derive(Clone, Debug)]
pub struct FirebaseRTDB {
    pub base_url: String,
    client: Client,
    pub token: String
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
        let token = jwt.into();

        //let token = resp.get("token").ok_or_else(|| RtdbError { inner: "Payload did not contain token".to_string() })?;
        let base_url = project_url.into();

        let client = Self::build_client()?;

        #[derive(Serialize)]
        struct AuthPayload {
            token: String,
            returnSecureToken: bool
        }

        #[derive(Deserialize, Debug)]
        struct AuthResponsePayload {
            idToken: String,
            refreshToken: String,
            expiresIn: String
        }

        let payload = AuthPayload { token, returnSecureToken: true };
        // auth first
        let resp: AuthResponsePayload = client.post(format!("https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key={}", api_key.as_ref())).header(CONTENT_TYPE, "application/json").json(&payload).send().await?.json().await?;
        log::info!("RESP AUTH: {:?}", resp);

        Ok(Self { base_url, client, token: resp.idToken })
    }

    /// Use this if authentication already occurred, and the token is still valid
    pub fn new_from_token<T: Into<String>, R: Into<String>>(project_url: T, token: R) -> Result<Self, RtdbError> {
        let client = Self::build_client()?;

        Ok(Self { client, base_url: project_url.into(), token: token.into() })
    }

    fn build_client() -> Result<Client, RtdbError> {
        Ok(Client::builder().use_native_tls().connect_timeout(CONNECT_TIMEOUT).tcp_nodelay(true).build()?)
    }

    pub fn root(&self) -> Node<'_> {
        Node { string_builder: self.base_url.clone(), client: &self.client, token: &self.token }
    }
}

impl Node<'_> {
    pub fn child<T: AsRef<str>>(&mut self, child: T) -> &mut Self {
        self.string_builder += child.as_ref();
        self.string_builder += "/";
        log::info!("Builder: {:?}", &self.string_builder);
        self
    }

    pub fn final_node<T: AsRef<str>>(&mut self, node: T) -> &Self {
        self.string_builder += node.as_ref();
        self.string_builder += ".json";
        log::info!("Builder: {:?}", &self.string_builder);
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