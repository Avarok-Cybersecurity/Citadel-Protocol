//! `P2pEstablisher`: the `citadel_link::LinkEstablisher` of one peer pair over today's code.
//! `open_path` runs one stage (the direct punch, TURN, or the server relay), `seal` wraps the
//! route under the pair's keys, `deliver` attaches it and, the first time, hands the kernel its
//! one `PeerChannel` (the stable handle, §3.4).

use std::sync::Arc;

use citadel_crypt::ratchets::Ratchet;
use citadel_link::outbox::Undelivered;
use citadel_link::{
    Clock, Delivered, Fut, Incarnation, Link, LinkEstablisher, PathFailure, PathStage, PathTrigger,
    Pathed, PunchReuse, RetireReason, SealFailure, SealParams, Sealed, StableHandle, StageFailure,
    TimedStage, Unpathed,
};
use citadel_types::crypto::{SecBuffer, SecurityLevel};
use citadel_wire::exports::tokio_rustls::rustls;
use citadel_wire::udp_traversal::udp_hole_puncher::PunchBudget;

use super::context::{P2pLinkContext, WeakSession};
use super::direct::{open_direct_path, DirectStage};
use super::failure::link_failure;
use super::handles::{OpenedRoute, P2pChannel, P2pPath, P2pSeal, P2pTarget};
use super::wrap::wrap_p2p_stream;
use crate::proto::misc::native_io_platform::generate_hole_punch_crypt_container;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::peer::coordination::RETRY_RENDEZVOUS;
use crate::proto::peer::turn_p2p::open_relayed_path;
use crate::proto::session::CitadelSession;
use citadel_io::time::Instant;

/// One pair's establisher. Cheap to clone: everything it holds is shared.
pub(crate) struct P2pEstablisher<R: Ratchet, T: PlatformOps> {
    pub(crate) ctx: Arc<P2pLinkContext<R, T>>,
    pub(crate) clock: Arc<dyn Clock>,
}

fn failed(stage: PathStage, failure: StageFailure) -> PathFailure {
    PathFailure { stage, failure }
}

impl<R: Ratchet, T: PlatformOps> P2pEstablisher<R, T> {
    fn session(&self, stage: PathStage) -> Result<CitadelSession<R, T>, PathFailure> {
        upgrade(&self.ctx.session).ok_or(failed(stage, StageFailure::SessionGone))
    }

    fn tls(&self, session: &CitadelSession<R, T>) -> Option<Arc<rustls::ClientConfig>> {
        T::client_config_to_any(&session.client_config)
            .and_then(|c| c.downcast::<Arc<rustls::ClientConfig>>().ok())
            .map(|c| *c)
    }

    /// Every attempt but the first meets the peer on the coordination endpoint before its stage,
    /// as the campaign's retries do (the first one's meeting was the key exchange): both ends
    /// run the same rule, so they start each stage together.
    async fn meet(&self, trigger: PathTrigger, at: PathStage) -> Result<Instant, PathFailure> {
        if trigger == PathTrigger::Initial {
            return Ok(self.ctx.sync_time);
        }
        self.ctx
            .app
            .on(RETRY_RENDEZVOUS)
            .sync()
            .await
            .map_err(|_| failed(at, StageFailure::Signalling))?;
        Ok(Instant::now())
    }

    async fn open(
        &self,
        stage: TimedStage,
        trigger: PathTrigger,
    ) -> Result<OpenedRoute, PathFailure> {
        let ctx = &self.ctx;
        let at = stage.stage;
        if at == PathStage::Relay {
            return Ok(OpenedRoute::Relay);
        }
        let sync_time = self.meet(trigger, at).await?;
        match at {
            PathStage::Direct => {
                let session = self.session(at)?;
                let tls = self
                    .tls(&session)
                    .ok_or(failed(at, StageFailure::Unsupported))?;
                let direct = DirectStage {
                    app: ctx.app.clone(),
                    sync_time,
                    cipher: generate_hole_punch_crypt_container(
                        ctx.endpoint_ratchet.clone(),
                        SecurityLevel::Standard,
                        ctx.peer_cid,
                    ),
                    stun_servers: session.stun_servers.clone(),
                    tls,
                    peer_nat_info: ctx.peer_nat_info.clone(),
                    budget: PunchBudget::within_stage(stage.timeout),
                };
                drop(session);
                let direct = open_direct_path(direct)
                    .await
                    .map_err(|e| failed(at, link_failure(e)))?;
                Ok(OpenedRoute::Direct(direct))
            }
            PathStage::Turn => {
                let config = ctx
                    .turn
                    .clone()
                    .ok_or(failed(at, StageFailure::NotConfigured))?;
                let session = self.session(at)?;
                let tls = self
                    .tls(&session)
                    .ok_or(failed(at, StageFailure::Unsupported))?;
                drop(session);
                open_relayed_path(
                    &ctx.app,
                    &config,
                    ctx.local_cid,
                    ctx.peer_cid,
                    &ctx.peer_nat_info,
                    tls,
                )
                .await
                .map(OpenedRoute::Turn)
                .map_err(|e| failed(at, link_failure(e)))
            }
            _ => Err(failed(at, StageFailure::Unsupported)),
        }
    }
}

fn upgrade<R: Ratchet, T: PlatformOps>(weak: &WeakSession<R, T>) -> Option<CitadelSession<R, T>> {
    CitadelSession::upgrade_weak(weak)
}

impl<R: Ratchet, T: PlatformOps> LinkEstablisher for P2pEstablisher<R, T> {
    type Target = P2pTarget;
    type Path = P2pPath;
    type Seal = P2pSeal<R, T>;
    type Channel = P2pChannel<R>;
    type Payload = SecBuffer;

    fn open_path<'a>(
        &'a self,
        _target: &'a P2pTarget,
        stage: TimedStage,
        trigger: PathTrigger,
        _reuse: PunchReuse,
        incarnation: Incarnation,
        deadline: citadel_link::Millis,
    ) -> Fut<'a, Result<Link<Self, Pathed>, PathFailure>> {
        Box::pin(async move {
            // The core's deadline bounds the whole stage, its meeting included: a peer that
            // never meets this attempt ends it as a timeout, not a hang.
            let expired = self.clock.sleep_until(deadline);
            let opened = citadel_io::tokio::select! {
                opened = self.open(stage, trigger) => opened?,
                _ = expired => return Err(failed(stage.stage, StageFailure::Timeout)),
            };
            let path = P2pPath::new(opened, self.ctx.local_nat, self.ctx.peer_nat);
            Ok(Link::opened(path, incarnation, self.clock.now()))
        })
    }

    fn seal<'a>(
        &'a self,
        link: Link<Self, Pathed>,
        params: &'a SealParams,
        _deadline: citadel_link::Millis,
    ) -> Fut<'a, Result<Link<Self, Sealed>, SealFailure>> {
        Box::pin(async move {
            let ctx = &self.ctx;
            let session = upgrade(&ctx.session).ok_or(SealFailure::PathLost)?;
            let route_id = citadel_link::PathHandle::route_id(link.path());
            let opened = link.path().take_route();
            let facts = opened.and_then(|o| o.into_facts(route_id, ctx, params.settings.udp_mode));
            let wrapped = match facts {
                None => None,
                Some((stream, facts)) => {
                    let kernel_tx = session.kernel_tx.clone();
                    let session_cid = ctx.session_cid.clone();
                    let wrapped = wrap_p2p_stream(stream, session_cid, session, kernel_tx, facts)
                        .map_err(|_| SealFailure::Handshake)?;
                    Some(wrapped)
                }
            };
            let seal = P2pSeal::new(
                params.settings,
                ctx.connection,
                ctx.endpoint_ratchet.version(),
                wrapped,
            );
            Ok(link.seal_with(seal))
        })
    }

    fn deliver(
        &self,
        link: Link<Self, Sealed>,
        handle: &StableHandle<P2pChannel<R>>,
    ) -> Link<Self, Delivered> {
        link.seal().attach(self.ctx.peer_cid);
        citadel_link::KernelChannel::attach(handle.channel(), link.incarnation());
        link.delivered()
    }

    fn fork_path(&self, _live: &Link<Self, Delivered>) -> Result<Link<Self, Pathed>, PathFailure> {
        // A second session on the live path is lane L5's reseal (`LINK_RESEAL_SINCE`).
        Err(failed(PathStage::Direct, StageFailure::Unsupported))
    }

    fn reattach<'a>(
        &'a self,
        _held: Link<Self, Unpathed>,
        _path: Link<Self, Pathed>,
        _deadline: citadel_link::Millis,
    ) -> Fut<'a, Result<Link<Self, Sealed>, SealFailure>> {
        // The P2P reattach frame is lane L1's `REATTACH` (`LINK_REATTACH_SINCE`); without it the
        // core seals afresh on the path already open (§3.2).
        Box::pin(async { Err(SealFailure::UnknownSeal) })
    }

    fn retire(
        &self,
        old: Link<Self, Delivered>,
        _reason: RetireReason,
    ) -> Fut<'_, Vec<Undelivered<SecBuffer>>> {
        // The route's queues are not yet the outbox (lane L4): nothing is returned from them.
        drop(old.into_parts());
        Box::pin(async { Vec::new() })
    }
}
