use hyxe_nat::time_tracker::{TimeTracker, NTP_SERVERS};
use std::time::Instant;
use igd::PortMappingProtocol;

#[tokio::main]
async fn main() {
    let handler = hyxe_nat::upnp_handler::UPnPHandler::new(None).await.unwrap();
    handler.close_firewall_port(PortMappingProtocol::UDP, None, 25000).await.unwrap();
}

/*
#[tokio::main]
async fn main2() {
    let mut cache = Cache::new();
    let mut cache2 = cache.clone();
    cache.insert(100, String::from("Hello, from 3 seconds ago!"));
    tokio::task::spawn(run_cache(cache));
    tokio::task::spawn(run_listener(cache2)).await;
}

async fn run_cache(mut cache: Cache) {
    while let Some(expired) = cache.next().await {
        println!("Expired item recv: {:?}", expired);
    }
}

async fn run_listener(mut cache2: Cache) {
    println!("Started listener");
    let mut i = 11;
    let mut read = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    while let Some(Ok(line)) = read.next().await {
        if line.contains("rem") {
            let vals = line.split(" ").collect::<Vec<&str>>();
            let number = u64::from_str(vals[1]).unwrap();
            println!("Removing number: {}", number);
            cache2.remove(&number);
        } else {
            println!("input: {} (key={})", &line, i);
            cache2.insert(i, line);
            i+=1;
        }
    }
}

use tokio::time::{delay_queue, DelayQueue, Error};

use futures::{ready, Future, Stream, StreamExt};
use std::collections::HashMap;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::macros::support::Pin;
use std::io::BufRead;
use std::sync::{Arc, RwLock};
use std::str::FromStr;
use tokio::time::delay_queue::Expired;
use tokio::io::AsyncBufReadExt;
use futures::task::Waker;
use hyxe_nat::time_tracker::TimeTrackerRT;

struct CacheInner {
    entries: HashMap<u64, (String, delay_queue::Key)>,
    expirations: DelayQueue<u64>,
    waker: Option<Waker>
}

#[derive(Clone)]
struct Cache {
    inner: Arc<RwLock<CacheInner>>
}

impl Cache {
    pub fn new() -> Self {
        let inner = CacheInner { entries: HashMap::new(), expirations: DelayQueue::new(), waker: None };
        Self { inner: Arc::new(RwLock::new(inner)) }
    }
}

const TTL_SECS: u64 = 8;

impl Cache {
    fn insert(&mut self, key: u64, value: String) {
        let mut this = self.inner.write().unwrap();
        let delay = this.expirations
            .insert(key.clone(), Duration::from_secs(TTL_SECS));

        this.entries.insert(key, (value, delay));
        println!("[Cache] added {}", key);

        if let Some(waker) = this.waker.as_ref() {
            waker.wake_by_ref();
            println!("Waker alerted");
        } else {
            println!("Waker not yet loaded");
        }
    }

    fn remove(&mut self, key: &u64) {
        let mut this = self.inner.write().unwrap();
        if let Some((_, cache_key)) = this.entries.remove(key) {
            this.expirations.remove(&cache_key);
            println!("Removed {}", key);
        }
    }

    fn poll_purge(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let mut this = self.inner.write().unwrap();

        if this.waker.is_none() {
            this.waker = Some(cx.waker().clone());
        }

        while let Some(res) = ready!(this.expirations.poll_expired(cx)) {
            let entry = res?.into_inner();
            let (line, key) = this.entries.remove(&entry).unwrap();

            println!("Item '{}' expired", line);
        }

        Poll::Pending
    }
}

impl Stream for Cache {
    // DelayQueue seems much more specific, where a user may care that it
    // has reached capacity, so return those errors instead of panicking.
    type Item = Result<Expired<u64>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Option<Self::Item>> {
        match ready!(self.poll_purge(cx)) {
            Ok(_) => {
                Poll::Pending
            }

            Err(_) => {
                Poll::Ready(None)
            }
        }
    }
}*/