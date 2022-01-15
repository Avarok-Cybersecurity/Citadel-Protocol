use tokio::time::Duration;
///
pub const VERSION: &str = "0.5 alpha";

pub const DISCONNECT_TIMEOUT: Duration = Duration::from_millis(4000);

pub const DEREGISTER_TIMEOUT: Duration = Duration::from_millis(8000);

pub const GET_REGISTERED_USERS_TIMEOUT: Duration = Duration::from_millis(4000);

pub const FCM_FETCH_TIMEOUT: Duration = Duration::from_millis(3000);

pub const POST_REGISTER_TIMEOUT: Duration = Duration::from_secs(60*10);
/// Using the default FCM TTL: 4 weeks
pub const FCM_POST_REGISTER_TIMEOUT: Duration = Duration::from_secs(60*60*24*7*4);
// After 30 minutes of inactivity, the stream between two endpoints ends
pub const PEER_STREAM_TIMEOUT: Duration = Duration::from_secs(60*30);

pub const CREATE_GROUP_TIMEOUT: Duration = Duration::from_millis(5000);

pub const INVALID_UTF8: &str = "Invalid UTF-8 Message";