use tokio::sync::mpsc::{Receiver, Sender};
use tokio::stream::Stream;
use futures::task::Context;
use tokio::macros::support::{Pin, Poll};
use crate::primitives::variable::NetworkVariableInner;
use crate::application::NetworkUpdateState;
use std::future::Future;
use crate::primitives::accessor::NetworkTransferable;
use serde::export::PhantomData;
use pin_project::*;

#[pin_project]
pub struct VariableUpdater<T: NetworkTransferable> {
    #[pin]
    receiver: Receiver<NetworkUpdateState>,
    notifier_tx: Sender<()>,
    ptr: NetworkVariableInner,
    _pd: PhantomData<T>
}

impl<T: NetworkTransferable> VariableUpdater<T> {
    pub fn new(state_update_receiver: Receiver<NetworkUpdateState>, notifier_tx: Sender<()>, ptr: NetworkVariableInner) -> Self {
        Self { receiver: state_update_receiver, notifier_tx, ptr, _pd: Default::default() }
    }
}

impl<T: NetworkTransferable> Stream for VariableUpdater<T> {
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match futures::ready!(self.receiver.poll_recv(cx)) {
            Some(item) => {
                match item {
                    NetworkUpdateState::ValueModified { value, .. } => {
                        let ptr = self.as_ref().ptr.clone();
                        let _ = tokio::task::spawn(async move { ptr.update_value::<T>(value).await });
                        return Poll::Pending
                    }

                    _ => {
                        if let Err(err) = self.as_mut().notifier_tx.try_send(()) {
                            log::error!("Unable to send notification ({:?})", err);
                        } else {
                            return Poll::Pending
                        }
                    }
                }
            }

            _ => {
                log::error!("Receiver died [x01]");
            }
        }

        Poll::Ready(None)
    }
}

impl<T: NetworkTransferable> Future for VariableUpdater<T> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match futures::ready!(self.poll_next(cx)) {
            Some(_) => Poll::Pending,
            _ => Poll::Ready(())
        }
    }
}