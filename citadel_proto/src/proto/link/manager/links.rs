//! The link values the shell holds between the core's commands, one map per typestate. The
//! core names attempts and incarnations; these maps hand each command the value it consumes.

use std::collections::HashMap;

use citadel_link::outbox::Undelivered;
use citadel_link::{
    ConnectionId, Delivered, Incarnation, Link, LinkEstablisher, PathFailure, Pathed, SealFailure,
    Sealed,
};

/// What a port future returns, for the shell to store and turn into the core's input.
pub(crate) enum PortDone<E: LinkEstablisher> {
    Opened {
        attempt: u32,
        result: Result<Link<E, Pathed>, PathFailure>,
    },
    Sealed {
        incarnation: Incarnation,
        result: Result<Link<E, Sealed>, SealFailure>,
    },
    /// A side attempt's route, sealed under the live seal and ready to attach.
    SideSealed {
        result: Result<Link<E, Sealed>, SealFailure>,
    },
    Retired {
        incarnation: Incarnation,
        undelivered: Vec<Undelivered<E::Payload>>,
    },
    Met {
        attempt: u32,
        result: Result<citadel_link::PathPlan, citadel_link::StageFailure>,
    },
    Rebound {
        route: citadel_link::RouteId,
        ok: bool,
    },
    Probed {
        ok: bool,
    },
}

/// The key an offered path is kept under: no attempt of this side has that number.
const OFFERED: u32 = u32::MAX;

/// The values between commands.
pub(crate) struct Links<E: LinkEstablisher> {
    connection: ConnectionId,
    /// The highest incarnation the core has sealed (or is sealing).
    issued: Option<Incarnation>,
    pub(crate) pathed: HashMap<u32, Link<E, Pathed>>,
    pub(crate) sealed: HashMap<Incarnation, Link<E, Sealed>>,
    pub(crate) delivered: HashMap<Incarnation, Link<E, Delivered>>,
    /// The attempt whose path the next `Seal` (or `AttachRoute`) consumes.
    pub(crate) last_opened: Option<u32>,
    /// What the retired incarnations still held, returned on close (lane L4 turns this into
    /// the `Disconnect` event's `undelivered`).
    pub(crate) undelivered: Vec<Undelivered<E::Payload>>,
}

impl<E: LinkEstablisher> Links<E> {
    pub(crate) fn new(connection: ConnectionId) -> Self {
        Links {
            connection,
            issued: None,
            pathed: HashMap::new(),
            sealed: HashMap::new(),
            delivered: HashMap::new(),
            last_opened: None,
            undelivered: Vec::new(),
        }
    }

    /// The incarnation a path opened now will seal as: the one after the last the core issued,
    /// which is how the core numbers its next seal (`OpenPath` does not name it).
    pub(crate) fn next_incarnation(&self) -> Incarnation {
        match self.issued {
            None => Incarnation::first(self.connection),
            Some(last) => last.next().unwrap_or(last),
        }
    }

    pub(crate) fn issue(&mut self, incarnation: Incarnation) {
        if self.issued.is_none_or(|last| incarnation > last) {
            self.issued = Some(incarnation);
        }
    }

    /// The path the current attempt opened, for its seal.
    pub(crate) fn take_opened(&mut self) -> Option<Link<E, Pathed>> {
        let attempt = self.last_opened.take()?;
        self.pathed.remove(&attempt)
    }

    /// The path a peer opened when it healed first, for the responder's seal.
    pub(crate) fn offer(&mut self, link: Link<E, Pathed>) {
        self.pathed.insert(OFFERED, link);
        self.last_opened = Some(OFFERED);
    }

    /// Drops every path and seal not yet delivered (`ClosePath`).
    pub(crate) fn close_undelivered(&mut self) {
        self.pathed.clear();
        self.sealed.clear();
        self.last_opened = None;
    }
}
