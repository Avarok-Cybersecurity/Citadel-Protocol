//! # Firebase Realtime Database Client
//!
//! A lightweight, async Rust client for interacting with Firebase Realtime Database.
//! This crate provides a safe and ergonomic interface for performing CRUD operations
//! on Firebase RTDB with JWT authentication support.
//!
//! ## Features
//!
//! - JWT-based authentication with automatic token renewal
//! - Support for all CRUD operations (GET, PUT, POST, PATCH, DELETE)
//! - Hierarchical node-based access to database paths
//! - Connection timeout handling and error management
//! - Serialization/deserialization support via serde
//! - TLS encryption for all requests
//! - Automatic token refresh before expiration
//!
//! ## Example
//!
//! ```rust
//! use firebase_rtdb::{FirebaseRTDB, Node, RtdbError};
//! use serde_json::json;
//!
//! async fn example() -> Result<(), RtdbError> {
//!     // Initialize with JWT
//!     let mut db = FirebaseRTDB::new_from_jwt(
//!         "https://your-project.firebaseio.com",
//!         "your-jwt-token",
//!         "your-api-key"
//!     ).await?;
//!
//!     // Access and modify data
//!     let mut root = db.root().await?;
//!     let mut users = root.child("users");
//!     
//!     // Read data
//!     let user_data = users.child("user1").get().await?;
//!     
//!     // Write data
//!     users.child("user2")
//!         .put(json!({
//!             "name": "John Doe",
//!             "age": 30,
//!             "email": "john@example.com"
//!         })).await?;
//!     
//!     // Update specific fields
//!     users.child("user2")
//!         .patch(json!({
//!             "age": 31,
//!             "last_login": "2023-01-01"
//!         })).await?;
//!     
//!     // Create new entry with generated key
//!     let new_user = users
//!         .post(json!({
//!             "name": "Jane Doe",
//!             "age": 25
//!         })).await?;
//!     
//!     // Delete data
//!     users.child("old_user").delete().await?;
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Security Considerations
//!
//! - JWT tokens are automatically renewed before expiration
//! - All HTTP requests use TLS encryption
//! - Connection timeouts are enforced to prevent hanging
//! - API keys and tokens should be kept secure and not hardcoded
//! - Supports Firebase Security Rules for access control
//!
//! ## Error Handling
//!
//! The crate uses a custom `RtdbError` type that wraps various error conditions:
//! - Network errors (connection timeouts, DNS failures)
//! - Authentication errors (invalid tokens, expired credentials)
//! - Database errors (permission denied, invalid paths)
//! - Serialization/deserialization errors
//!
//! ## Performance
//!
//! - Uses connection pooling via reqwest
//! - TCP nodelay enabled for reduced latency
//! - Efficient token renewal with expiration buffering
//! - Reuses HTTP clients for better performance

#![allow(non_snake_case)]

use reqwest::header::CONTENT_TYPE;
use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::str::FromStr;
use std::time::{Duration, Instant};

/// Firebase Realtime Database client with JWT authentication support.
///
/// This struct maintains the authentication state and provides access to database operations.
/// It automatically handles token renewal and maintains connection settings.
///
/// # Fields
///
/// * `base_url` - The base URL of your Firebase project
/// * `client` - HTTP client with connection pooling and TLS support
/// * `auth` - Current authentication state including tokens
/// * `expire_time` - Token expiration timestamp
/// * `api_key` - Firebase project API key
/// * `jwt` - Original JWT token for renewals
#[derive(Clone, Debug)]
pub struct FirebaseRTDB {
    pub base_url: String,
    client: Client,
    pub auth: AuthResponsePayload,
    pub expire_time: Instant,
    pub api_key: String,
    pub jwt: String,
}

/// Default buffer time before token expiration to trigger renewal
pub const DEFAULT_EXPIRE_BUFFER_SECS: Duration = Duration::from_secs(5);

/// Authentication response from Firebase containing tokens and expiration.
///
/// This struct represents the response from Firebase authentication endpoints
/// and contains the necessary tokens for database access.
///
/// # Fields
///
/// * `idToken` - The token used for database operations
/// * `refreshToken` - Token used to obtain new credentials
/// * `expiresIn` - Token lifetime in seconds
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct AuthResponsePayload {
    pub idToken: String,
    pub refreshToken: String,
    pub expiresIn: String,
}

/// Represents a node in the Firebase Realtime Database.
///
/// Nodes are used to traverse the database hierarchy and perform operations at specific paths.
/// Each node maintains its full path and can create child nodes or perform CRUD operations.
///
/// The path is built incrementally using the builder pattern, allowing for fluent API usage.
///
/// # Example
///
/// ```rust
/// use firebase_rtdb::{FirebaseRTDB, RtdbError};
///
///  async fn example() -> Result<(), RtdbError> {
///     let mut db = FirebaseRTDB::new_from_jwt("https://your-project.firebaseio.com", "your-jwt-token", "your-api-key").await?;
///     let mut root = db.root().await?;
///     let users = root
///         .child("users")
///         .child("user123")
///         .child("profile");
///     Ok(())
/// }
/// ```
pub struct Node<'a> {
    string_builder: String,
    client: &'a Client,
    token: &'a String,
}

/// Custom error type for Firebase RTDB operations.
///
/// Encapsulates various error conditions that can occur during database operations,
/// including network errors, authentication failures, and invalid data.
///
/// All errors are converted to a string representation for simplified error handling
/// while maintaining the original error context.
#[derive(Debug)]
pub struct RtdbError {
    pub inner: String,
}

impl<E: Error> From<E> for RtdbError {
    fn from(err: E) -> Self {
        Self {
            inner: err.to_string(),
        }
    }
}

/// Default connection timeout for HTTP requests
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

impl FirebaseRTDB {
    /// Creates a new Firebase RTDB client using a JWT token.
    ///
    /// This method will contact the authorization server to obtain necessary credentials.
    /// The JWT token is used for initial authentication and subsequent token renewals.
    ///
    /// # Arguments
    ///
    /// * `project_url` - The base URL of your Firebase project (e.g., "https://project-id.firebaseio.com")
    /// * `jwt` - A valid JWT token for authentication
    /// * `api_key` - Your Firebase project's API key
    ///
    /// # Returns
    ///
    /// Returns a Result containing the initialized FirebaseRTDB client or an error
    pub async fn new_from_jwt<T: Into<String>, R: Into<String>, V: AsRef<str>>(
        project_url: T,
        jwt: R,
        api_key: V,
    ) -> Result<Self, RtdbError> {
        let jwt = jwt.into();

        //let token = resp.get("token").ok_or_else(|| RtdbError { inner: "Payload did not contain token".to_string() })?;
        let base_url = project_url.into();
        let api_key = api_key.as_ref();
        let client = Self::build_client()?;

        #[derive(Serialize)]
        struct AuthPayload {
            token: String,
            returnSecureToken: bool,
        }

        let payload = AuthPayload {
            token: jwt.clone(),
            returnSecureToken: true,
        };
        // auth first
        let resp: AuthResponsePayload = client
            .post(format!(
                "https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key={api_key}",
            ))
            .header(CONTENT_TYPE, "application/json")
            .json(&payload)
            .send()
            .await?
            .json()
            .await?;
        log::trace!(target: "citadel", "RESP AUTH: {:?}", resp);

        let expire_time =
            Instant::now() + Duration::from_secs(u64::from_str(resp.expiresIn.as_str())?);

        Ok(Self {
            base_url,
            client,
            auth: resp,
            expire_time,
            api_key: api_key.to_string(),
            jwt,
        })
    }

    /// Creates a new Firebase RTDB client using an existing valid token.
    ///
    /// Use this method when you already have valid authentication credentials and want to
    /// avoid an initial token refresh.
    ///
    /// # Arguments
    ///
    /// * `project_url` - The base URL of your Firebase project
    /// * `api_key` - Your Firebase project's API key
    /// * `jwt` - A valid JWT token
    /// * `auth` - Existing authentication payload
    /// * `expire_time` - Token expiration time
    pub fn new_from_token<T: Into<String>, R: Into<String>, V: Into<String>>(
        project_url: T,
        api_key: R,
        jwt: V,
        auth: AuthResponsePayload,
        expire_time: Instant,
    ) -> Result<Self, RtdbError> {
        let client = Self::build_client()?;

        Ok(Self {
            client,
            base_url: project_url.into(),
            auth,
            expire_time,
            api_key: api_key.into(),
            jwt: jwt.into(),
        })
    }

    /// Renews the authentication token.
    ///
    /// This method should be called when the current token is about to expire or has expired.
    /// It will update the internal authentication state with new credentials.
    pub async fn renew_token(&mut self) -> Result<(), RtdbError> {
        #[derive(Serialize)]
        struct RenewPayload {
            grant_type: String,
            refresh_token: String,
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
            project_id: String,
        }

        log::trace!(target: "citadel", "[RTDB] About to renew token");
        let payload = RenewPayload {
            grant_type: "refresh_token".to_string(),
            refresh_token: self.auth.refreshToken.clone(),
        };

        let resp: RenewResponse = self
            .client
            .post(format!(
                "https://securetoken.googleapis.com/v1/token?key={}",
                self.api_key.as_str()
            ))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .json(&payload)
            .send()
            .await?
            .json()
            .await?;

        log::trace!(target: "citadel", "RESP RENEW: {:?}", &resp);
        // update internal value using the new response
        let expire_time =
            Instant::now() + Duration::from_secs(u64::from_str(resp.expires_in.as_str())?);
        self.expire_time = expire_time;

        let auth = AuthResponsePayload {
            idToken: resp.id_token,
            refreshToken: resp.refresh_token,
            expiresIn: resp.expires_in,
        };

        self.auth = auth;

        Ok(())
    }

    /// Checks if the current authentication token has expired.
    ///
    /// Returns true if the token has expired and needs to be renewed before making
    /// further database requests.
    pub fn token_expired(&self) -> bool {
        Instant::now() + DEFAULT_EXPIRE_BUFFER_SECS > self.expire_time
    }

    /// Creates a new reqwest Client with appropriate timeout settings.
    fn build_client() -> Result<Client, RtdbError> {
        Ok(Client::builder()
            .use_rustls_tls()
            .connect_timeout(CONNECT_TIMEOUT)
            .tcp_nodelay(true)
            .build()?)
    }

    /// Returns a Node representing the root of the database.
    ///
    /// This method will automatically renew the token if it has expired.
    /// Use this as the starting point for accessing database paths.
    pub async fn root(&mut self) -> Result<Node<'_>, RtdbError> {
        if self.token_expired() {
            self.renew_token().await?
        }

        Ok(Node {
            string_builder: self.base_url.clone(),
            client: &self.client,
            token: &self.auth.idToken,
        })
    }
}

impl Node<'_> {
    /// Creates a new child node at the specified path.
    ///
    /// # Arguments
    ///
    /// * `child` - The name of the child node to create
    ///
    /// # Returns
    ///
    /// Returns a mutable reference to the new child node
    pub fn child<T: AsRef<str>>(&mut self, child: T) -> &mut Self {
        self.string_builder += child.as_ref();
        self.string_builder += "/";
        log::trace!(target: "citadel", "Builder: {:?}", &self.string_builder);
        self
    }

    /// Finalizes the node path with a last segment.
    ///
    /// Similar to child() but returns an immutable reference, useful for
    /// immediately performing an operation.
    pub fn final_node<T: AsRef<str>>(&mut self, node: T) -> &Self {
        self.string_builder += node.as_ref();
        self.string_builder += ".json";
        log::trace!(target: "citadel", "Builder: {:?}", &self.string_builder);
        self
    }

    /// Retrieves data at the current node path.
    ///
    /// Performs a GET request to fetch the current value at this database location.
    pub async fn get(&self) -> Result<String, RtdbError> {
        let resp = self
            .client
            .get(format!("{}?auth={}", self.string_builder, self.token))
            .send()
            .await?;
        Self::handle_response(resp).await
    }

    /// Writes data to the current node path.
    ///
    /// Performs a PUT request to set the value at this database location.
    /// The input must be serializable to JSON.
    pub async fn put<T: Serialize>(&self, input: T) -> Result<String, RtdbError> {
        let resp = self
            .client
            .put(format!("{}?auth={}", self.string_builder, self.token))
            .json(&input)
            .send()
            .await?;
        Self::handle_response(resp).await
    }

    /// Creates a new child with a unique key.
    ///
    /// Performs a POST request to create a new child with a Firebase-generated key
    /// and the provided data.
    pub async fn post<T: Serialize>(&self, input: T) -> Result<String, RtdbError> {
        let resp = self
            .client
            .post(format!("{}?auth={}", self.string_builder, self.token))
            .json(&input)
            .send()
            .await?;
        Self::handle_response(resp).await
    }

    /// Updates specific fields at the current path.
    ///
    /// Performs a PATCH request to update only the specified fields while leaving
    /// others unchanged.
    pub async fn patch<T: Serialize>(&self, input: T) -> Result<String, RtdbError> {
        let resp = self
            .client
            .patch(format!("{}?auth={}", self.string_builder, self.token))
            .json(&input)
            .send()
            .await?;
        Self::handle_response(resp).await
    }

    /// Removes data at the current path.
    ///
    /// Performs a DELETE request to remove all data at this location.
    pub async fn delete(&self) -> Result<String, RtdbError> {
        let resp = self
            .client
            .delete(format!("{}?auth={}", self.string_builder, self.token))
            .send()
            .await?;
        Self::handle_response(resp).await
    }

    /// Processes the HTTP response and extracts the result or error.
    async fn handle_response(resp: Response) -> Result<String, RtdbError> {
        if resp.status().as_u16() == 200 {
            Ok(resp.text().await?)
        } else {
            Err(RtdbError {
                inner: resp.text().await?,
            })
        }
    }
}
