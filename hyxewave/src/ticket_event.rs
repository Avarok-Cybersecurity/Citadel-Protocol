use hyxe_net::hdp::hdp_server::Ticket;
use tokio_util::time::{DelayQueue, delay_queue};
use tokio::time::error::Error;
use std::pin::Pin;
use crate::console::console_context::ConsoleContext;
use hyxe_net::hdp::peer::peer_layer::PeerResponse;
use futures_util::task::{Poll, Context, Waker};
use tokio_stream::Stream;
use std::sync::Arc;
use parking_lot::Mutex;
use std::collections::HashMap;
use hyxe_net::hdp::hdp_packet_processor::includes::Duration;
use crate::command_handlers::connect::ConnectResponseReceived;

pub struct TrackedTicket {
    pub ticket: Ticket,
    pub key: delay_queue::Key,
    pub lifetime: Duration,
    pub implicated_cid: u64,
    pub fx: CallbackType
}

impl TrackedTicket {

    /// This should be called from the [TimedQueueHandler]
    pub fn new(key: delay_queue::Key, ticket: Ticket, lifetime: Duration, implicated_cid: u64, fx: CallbackType) -> Self {
        Self { ticket, key, lifetime, fx, implicated_cid}
    }

    pub fn run_fx(&self, ctx: &ConsoleContext, response: ResponseType) -> CallbackStatus {
        match (response, &self.fx) {
            (ResponseType::PeerResponse(response), CallbackType::Standard(fx)) => {
                (fx)(ctx, self.ticket, response)
            }

            (ResponseType::Custom(response), CallbackType::Custom(fx)) => {
                (fx)(ctx, self.ticket, response)
            }

            (ResponseType::Error(err), CallbackType::Custom(fx)) => {
                (fx)(ctx, self.ticket, CustomPayload::Error(err))
            }

            (ResponseType::Error(err), CallbackType::Standard(fx)) => {
                (fx)(ctx, self.ticket, PeerResponse::Err(Some(err)))
            }

            _ => {
                log::error!("Incompatible function type/response paired");
                CallbackStatus::TaskComplete
            }
        }
    }

    #[allow(unused_results)]
    pub fn on_timeout(&self, ctx: &ConsoleContext) {
        match &self.fx {
            CallbackType::Custom(fx) => {
                (fx)(ctx, self.ticket, CustomPayload::Timeout);
            }

            CallbackType::Standard(fx) => {
                (fx)(ctx, self.ticket, PeerResponse::Timeout);
            }
        }
    }

}

pub enum ResponseType {
    PeerResponse(PeerResponse),
    Custom(CustomPayload),
    Error(String)
}

impl From<PeerResponse> for ResponseType {
    fn from(this: PeerResponse) -> Self {
        Self::PeerResponse(this)
    }
}

impl From<CustomPayload> for ResponseType {
    fn from(this: CustomPayload) -> Self {
        Self::Custom(this)
    }
}

pub enum CallbackType {
    Standard(Pin<Box<dyn Fn(&ConsoleContext, Ticket, PeerResponse) -> CallbackStatus + Send + 'static>>),
    Custom(Pin<Box<dyn Fn(&ConsoleContext, Ticket, CustomPayload) -> CallbackStatus + Send + 'static>>)
}

pub enum CustomPayload {
    Timeout,
    Connect(ConnectResponseReceived),
    Error(String)
}

struct TicketQueueHandlerInner {
    tracked_tickets: HashMap<Ticket, TrackedTicket>,
    queue: DelayQueue<Ticket>,
    console_ctx: ConsoleContext,
    waker: Option<Waker>,
}

#[derive(Clone)]
pub struct TicketQueueHandler {
    inner: Arc<Mutex<TicketQueueHandlerInner>>
}

impl TicketQueueHandler {
    pub fn new(console_ctx: ConsoleContext) -> Self {
        let inner = TicketQueueHandlerInner { console_ctx, tracked_tickets: HashMap::new(), queue: DelayQueue::new(), waker: None };
        Self { inner: Arc::new(Mutex::new(inner)) }
    }

    pub fn register_ticket(&self, ticket: Ticket, lifetime: Duration, implicated_cid: u64, fx: CallbackType) {
        let mut this = self.inner.lock();
        let key = this.queue.insert(ticket, lifetime);
        let tracked_ticket = TrackedTicket::new(key, ticket, lifetime, implicated_cid, fx);
        this.tracked_tickets.insert(ticket, tracked_ticket);
        if let Some(waker) = this.waker.as_ref() {
            waker.wake_by_ref()
        }
    }

    #[allow(unused_results)]
    pub fn remove_ticket(&self, ticket: Ticket) -> bool {
        let mut this = self.inner.lock();
        if let Some(tt) = this.tracked_tickets.remove(&ticket) {
            this.queue.remove(&tt.key);

            if let Some(waker) = this.waker.as_ref() {
                waker.wake_by_ref()
            }

            true
        } else {
            false
        }
    }

    #[allow(unused_results)]
    /// This is the only closure where the callback gets measured. If the callback returns
    /// as TaskComplete, the entry is removed. Otherwise, the task will remain
    pub fn on_ticket_received(&self, ticket: Ticket, response: ResponseType) {
        let mut this = self.inner.lock();
        if let Some(waker) = this.waker.as_ref() {
            waker.wake_by_ref();
        }
        if let Some(tracker) = this.tracked_tickets.get(&ticket) {
            let ref ctx = this.console_ctx;
            // now, call the closure (success)
            match tracker.run_fx(ctx, response) {
                CallbackStatus::TaskComplete => {
                    if let Some(tracker) = this.tracked_tickets.remove(&ticket) {
                        this.queue.remove(&tracker.key);
                    }
                }

                _ => {
                    // Else, renew the lifetime
                    let lifetime = tracker.lifetime;
                    let key = tracker.key.clone();
                    // prolong the time
                    this.queue.reset(&key, lifetime);
                }
            }
        }
    }

    fn poll_purge(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let mut this = self.inner.lock();
        this.waker = Some(cx.waker().clone());

        while let Some(res) = futures_util::ready!(this.queue.poll_expired(cx)) {
            //log::info!("Poll: Expired ticket");
            let entry = res?.into_inner();
            // remove from hashmap; already removed from queue
            let tracker_opt = this.tracked_tickets.remove(&entry);
            if let Some(tracker) = tracker_opt {
                // run on_timeout
                let ref console_ctx = this.console_ctx;
                //(tracker.fx)(console_ctx, tracker.ticket, PeerResponse::Timeout);
                tracker.on_timeout(console_ctx)
            }
        }

        Poll::Ready(Ok(()))
    }
}

impl Stream for TicketQueueHandler {
    type Item = ();

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match futures_util::ready!(self.poll_purge(cx)) {
            Ok(_) => {
                Poll::Pending
            }

            Err(_) => {
                Poll::Ready(None)
            }
        }
    }
}

#[derive(Copy, Clone, PartialEq)]
pub enum CallbackStatus {
    // No more processing
    TaskComplete,
    // NotReady (will accept more calls)
    TaskPending,
}