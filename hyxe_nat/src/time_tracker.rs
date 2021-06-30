use std::fmt::Formatter;

/*
use rsntp::{AsyncSntpClient, SynchronizationResult, SynchroniztationError};
use tokio::time::Duration;
use std::sync::Arc;
use arc_swap::ArcSwap;

/// An NTP-based module for tracking time with an NTP server
#[derive(Clone)]
pub struct TimeTracker {
    sync_result: ArcSwap<SynchronizationResult>
}


pub const NTP_SERVERS: &[&str] = &["time.cloudflare.com", "time.google.com", "0.us.pool.ntp.org", "1.us.pool.ntp.org", "2.us.pool.ntp.org", "3.us.pool.ntp.org"];
const TIMEOUT: Duration = Duration::from_millis(1500);
static LOCAL: parking_lot::Mutex<Option<TimeTracker>> = parking_lot::const_mutex(None);

impl TimeTracker {
    /// Creates a new [TimeTracker]
    pub async fn new() -> io::Result<Self> {
        let mut lock = LOCAL.lock();

        if let Some(val) = lock.as_ref() {
            return Ok(val.clone());
        }

        const RETRY_COUNT: usize = NTP_SERVERS.len();

        let mut client = AsyncSntpClient::new();
        client.set_timeout(TIMEOUT);

        for attempt in 0..RETRY_COUNT {
            log::info!("Fetching Global NTP time from {}...", NTP_SERVERS[attempt]);
            if let Ok(sync_result) = client.synchronize(NTP_SERVERS[attempt]).await {
                log::info!("Global NTP Time: {}", sync_result.datetime().timestamp_nanos());
                let this = Self::from(sync_result);
                *lock = Some(this.clone());

                return Ok(this);
            }
        }

        Err(std::io::Error::new(std::io::ErrorKind::NotConnected, "Unable to obtain NTP Time"))
    }

    pub async fn new_from(server: &str) -> io::Result<Self> {
        let mut client = AsyncSntpClient::new();
        client.set_timeout(TIMEOUT);
        client.synchronize(server).await
            .and_then(|res| Ok(Self::from(res)))
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::NotConnected, err))
    }

    #[inline]
    pub fn get_global_time_ns(&self) -> i64 {
        self.sync_result.load().datetime().timestamp_nanos()
    }

    #[inline]
    /// Returns the number of microseconds
    pub fn get_global_time_us(&self) -> i64 {
        self.get_global_time_ns() / 1000
    }

    #[inline]
    /// Returns the number of milliseconds
    pub fn get_global_time_ms(&self) -> i64 {
        self.get_global_time_us() / 1000
    }

    /// This should be periodically ran per session in the background every 20 minutes
    pub async fn resync(&self) -> bool {
        for server in NTP_SERVERS {
            if let Ok(_) = self.resync_inner(*server).await {
                return true;
            }
        }

        false
    }

    /// Resync the clock
    async fn resync_inner(&self, addr: &str) -> Result<(), SynchroniztationError> {
        let mut client = AsyncSntpClient::new();
        client.set_timeout(TIMEOUT);

        let sync_result = client.synchronize(addr).await?;
        self.sync_result.swap(Arc::new(sync_result));
        Ok(())
    }
}

impl From<SynchronizationResult> for TimeTracker {
    fn from(t: SynchronizationResult) -> Self {
        Self { sync_result: ArcSwap::new(Arc::new(t)) }
    }
}
*/

#[derive(Copy, Clone)]
pub struct TimeTracker;

impl TimeTracker {
    pub fn new() -> Self { Self }

    // This should work for about a hundred years before modulo'ing around back to zero
    pub fn get_global_time_ns(&self) -> i64 {
        (std::time::UNIX_EPOCH.elapsed().unwrap().as_nanos() % i64::MAX as u128) as i64
    }
}

impl std::fmt::Debug for TimeTracker {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Time tracker current global time: {}ns", self.get_global_time_ns())
    }
}
