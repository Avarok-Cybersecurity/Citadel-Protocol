use futures::stream::{SplitSink, SplitStream};
use tokio_util::codec::{Framed, Encoder, Decoder};
use std::ops::{Deref, DerefMut};
use futures::{StreamExt, SinkExt, Sink};
use std::marker::PhantomData;
use crate::macros::ContextRequirements;
use tokio::io::{AsyncWrite, AsyncRead};
use std::task::{Context, Poll};
use std::pin::Pin;

pub fn clean_framed_shutdown<S: AsyncWrite + AsyncRead + Unpin + ContextRequirements, U: Encoder<I> + Decoder + ContextRequirements, I: ContextRequirements>(framed: Framed<S, U>)
 -> (CleanShutdownSink<S, U, I>, CleanShutdownStream<S, U, I>) {
    let (sink, stream) = framed.split();
    let sink = CleanShutdownSink::new(sink);
    let stream = CleanShutdownStream::new(stream);
    (sink, stream)
}

pub struct CleanShutdownSink<S: AsyncWrite + AsyncRead + Unpin + ContextRequirements, U: Encoder<I> + Decoder + ContextRequirements, I: ContextRequirements> {
    inner: Option<SplitSink<Framed<S, U>, I>>
}

pub struct CleanShutdownStream<S: AsyncWrite + AsyncRead + Unpin + ContextRequirements, U: Encoder<I> + Decoder + ContextRequirements, I: ContextRequirements> {
    inner: SplitStream<Framed<S, U>>,
    _pd: PhantomData<I>
}

impl<S: AsyncWrite + AsyncRead + Unpin + ContextRequirements, U: Encoder<I> + Decoder + ContextRequirements, I: ContextRequirements> CleanShutdownSink<S, U, I> {
    pub fn new(inner: SplitSink<Framed<S, U>, I>) -> Self {
        Self { inner: Some(inner) }
    }
}

impl<S: AsyncWrite + AsyncRead + Unpin + ContextRequirements, U: Encoder<I> + Decoder + ContextRequirements, I: ContextRequirements> Sink<I> for CleanShutdownSink<S, U ,I> {
    type Error = <U as Encoder<I>>::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.as_mut().map(Pin::new).unwrap().poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: I) -> Result<(), Self::Error> {
        self.inner.as_mut().map(Pin::new).unwrap().start_send(item)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.as_mut().map(Pin::new).unwrap().poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.as_mut().map(Pin::new).unwrap().poll_close(cx)
    }
}

impl<S: AsyncWrite + AsyncRead + Unpin + ContextRequirements, U: Encoder<I> + Decoder + ContextRequirements, I: ContextRequirements> Drop for CleanShutdownSink<S, U, I> {
    #[allow(unused_results, unused_must_use)]
    fn drop(&mut self) {
        let mut inner = self.inner.take().unwrap();

        let drop_future = async move {
            inner.close().await;
        };

        spawn!(drop_future);
    }
}

impl<S: AsyncWrite + AsyncRead + Unpin + ContextRequirements, U: Encoder<I> + Decoder + ContextRequirements, I: ContextRequirements> CleanShutdownStream<S, U, I> {
    pub fn new(inner: SplitStream<Framed<S, U>>) -> Self {
        Self { inner, _pd: Default::default() }
    }
}

impl<S: AsyncWrite + AsyncRead + Unpin + ContextRequirements, U: Encoder<I> + Decoder + ContextRequirements, I: ContextRequirements> Deref for CleanShutdownSink<S, U, I> {
    type Target = SplitSink<Framed<S, U>, I>;

    fn deref(&self) -> &Self::Target {
        self.inner.as_ref().unwrap()
    }
}

impl<S: AsyncWrite + AsyncRead + Unpin + ContextRequirements, U: Encoder<I> + Decoder + ContextRequirements, I: ContextRequirements> DerefMut for CleanShutdownSink<S, U, I> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner.as_mut().unwrap()
    }
}

impl<S: AsyncWrite + AsyncRead + Unpin + ContextRequirements, U: Encoder<I> + Decoder + ContextRequirements, I: ContextRequirements> Deref for CleanShutdownStream<S, U, I> {
    type Target = SplitStream<Framed<S, U>>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<S: AsyncWrite + AsyncRead + Unpin + ContextRequirements, U: Encoder<I> + Decoder + ContextRequirements, I: ContextRequirements> DerefMut for CleanShutdownStream<S, U, I> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}