use super::SqlConnectionOptions;
use sqlx::any::AnyPoolOptions;

/// A release build's pool is what its options say, whatever the environment holds. It read a
/// `LOCALHOST_TESTING` variable and shrank to one connection, so a production node could run
/// with test pooling.
#[test]
fn the_environment_does_not_change_a_release_pool() {
    std::env::set_var("LOCALHOST_TESTING", "1");
    let opts = SqlConnectionOptions {
        max_connections: Some(7),
        ..Default::default()
    };
    let pool = AnyPoolOptions::from(&opts);
    assert_eq!(pool.get_max_connections(), 7);
}
