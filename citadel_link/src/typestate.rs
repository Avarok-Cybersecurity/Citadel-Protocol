//! The ordered sequence path → seal → deliver, enforced by types (§2.2). A `Link<E, S>` exists
//! only in the states below, and each state's value is built only from the state before it:
//! [`Link::opened`] is the one entry, a `Sealed` link is made only by consuming a `Pathed` one,
//! and a `Delivered` one only by consuming a `Sealed` one. The fields are private, so no other
//! module can fabricate a later state.

use std::marker::PhantomData;

use crate::establisher::LinkEstablisher;
use crate::event::{LossCause, SealRefusal};
use crate::kind::{Incarnation, Millis};
use crate::path::{PathStage, StageFailure};

/// No link value exists before its path opened; this state is a seal kept after its path was
/// lost, waiting to be reattached (§5.2).
pub struct Unpathed;
/// A raw path with no session on it.
pub struct Pathed;
/// A path carrying a sealed session, not yet handed to the kernel.
pub struct Sealed;
/// A sealed incarnation attached to the kernel's stable handle.
pub struct Delivered;

mod private {
    pub trait Sealed {}
    impl Sealed for super::Unpathed {}
    impl Sealed for super::Pathed {}
    impl Sealed for super::Sealed {}
    impl Sealed for super::Delivered {}
}

/// What a link holds in each state: a state without a path stores `()` for it, a state without a
/// seal stores `()` for that, so no accessor can find one missing.
pub trait Stage<E: LinkEstablisher>: private::Sealed {
    type Path;
    type Seal;
}
impl<E: LinkEstablisher> Stage<E> for Unpathed {
    type Path = ();
    type Seal = E::Seal;
}
impl<E: LinkEstablisher> Stage<E> for Pathed {
    type Path = E::Path;
    type Seal = ();
}
impl<E: LinkEstablisher> Stage<E> for Sealed {
    type Path = E::Path;
    type Seal = E::Seal;
}
impl<E: LinkEstablisher> Stage<E> for Delivered {
    type Path = E::Path;
    type Seal = E::Seal;
}

/// Ties a link to its establisher and state without owning either (and without making it
/// `!Send`).
type Marker<E, S> = (fn(&E), S);

/// A link at one point of the ordered sequence.
pub struct Link<E: LinkEstablisher, S: Stage<E>> {
    path: S::Path,
    seal: S::Seal,
    incarnation: Incarnation,
    opened_at: Millis,
    _s: PhantomData<Marker<E, S>>,
}

/// A path that could not be opened.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PathFailure {
    pub stage: PathStage,
    pub failure: StageFailure,
}

/// A seal that could not be made.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SealFailure {
    /// Refused for good; the link closes.
    Refused(SealRefusal),
    /// A reattach named a seal the far end no longer holds: a fresh seal on the same path.
    UnknownSeal,
    Timeout,
    /// The handshake failed on the wire.
    Handshake,
    /// The path died under the handshake.
    PathLost,
}

/// Why an incarnation is retired.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum RetireReason {
    /// A newer incarnation replaced it (a fresh-seal heal or a reseal's cutover).
    Superseded,
    /// A reseal was abandoned because the link dropped under it.
    Abandoned,
    /// Its path died and its seal can no longer be reattached.
    Lost(LossCause),
    /// The link is closing.
    Closing,
}

impl<E: LinkEstablisher> Link<E, Pathed> {
    /// The one entry into the sequence: a path that just opened, for the incarnation the core
    /// named in its `Seal` (a fresh seal) or `Reattach` (the held seal's) command.
    pub fn opened(path: E::Path, incarnation: Incarnation, opened_at: Millis) -> Self {
        Link {
            path,
            seal: (),
            incarnation,
            opened_at,
            _s: PhantomData,
        }
    }

    /// The handshake on this path produced `seal`.
    pub fn seal_with(self, seal: E::Seal) -> Link<E, Sealed> {
        Link {
            path: self.path,
            seal,
            incarnation: self.incarnation,
            opened_at: self.opened_at,
            _s: PhantomData,
        }
    }

    /// A reattach succeeded: the held seal now rides this path, as the incarnation it was.
    pub fn reattach_seal(self, held: Link<E, Unpathed>) -> Link<E, Sealed> {
        Link {
            path: self.path,
            seal: held.seal,
            incarnation: held.incarnation,
            opened_at: self.opened_at,
            _s: PhantomData,
        }
    }
}

impl<E: LinkEstablisher> Link<E, Sealed> {
    /// Attached to the kernel's stable handle (only `LinkEstablisher::deliver` calls this).
    pub fn delivered(self) -> Link<E, Delivered> {
        Link {
            path: self.path,
            seal: self.seal,
            incarnation: self.incarnation,
            opened_at: self.opened_at,
            _s: PhantomData,
        }
    }
}

impl<E: LinkEstablisher> Link<E, Delivered> {
    /// The path died; the seal is kept for a reattach within the grace.
    pub fn lose_path(self) -> (Link<E, Unpathed>, E::Path) {
        let held = Link {
            path: (),
            seal: self.seal,
            incarnation: self.incarnation,
            opened_at: self.opened_at,
            _s: PhantomData,
        };
        (held, self.path)
    }

    /// Takes the incarnation apart for retirement.
    pub fn into_parts(self) -> (E::Path, E::Seal) {
        (self.path, self.seal)
    }
}

impl<E: LinkEstablisher> Link<E, Unpathed> {
    /// Gives up on reattaching: the seal is all that is left.
    pub fn into_seal(self) -> E::Seal {
        self.seal
    }
}

impl<E: LinkEstablisher, S: Stage<E, Path = <E as LinkEstablisher>::Path>> Link<E, S> {
    pub fn path(&self) -> &E::Path {
        &self.path
    }
}

impl<E: LinkEstablisher, S: Stage<E, Seal = <E as LinkEstablisher>::Seal>> Link<E, S> {
    pub fn seal(&self) -> &E::Seal {
        &self.seal
    }
}

impl<E: LinkEstablisher, S: Stage<E>> Link<E, S> {
    pub fn incarnation(&self) -> Incarnation {
        self.incarnation
    }

    pub fn opened_at(&self) -> Millis {
        self.opened_at
    }
}
