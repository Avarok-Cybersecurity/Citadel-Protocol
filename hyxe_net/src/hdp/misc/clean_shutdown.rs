use parking_lot::Mutex;
use futures::stream::{SplitSink, SplitStream};
use std::sync::Arc;
use std::pin::Pin;
use tokio::prelude::{AsyncWrite, AsyncRead};
use tokio_util::codec::{Framed, Encoder, Decoder};
use std::ops::{Deref, DerefMut};
use futures::{StreamExt, SinkExt};

struct CleanFramedShutdownInner<S, U, I> {
    sink: Option<SplitSink<Framed<S, U>, I>>,
    stream: Option<SplitStream<Framed<S, U>>>
}

pub struct CleanFramedShutdown<S, U, I> {
    inner: Arc<Mutex<CleanFramedShutdownInner<S, U, I>>>
}

pub struct CleanTcpShutdownSink<S: AsyncWrite + AsyncRead + Unpin + 'static, U: Encoder<I, Error: From<std::io::Error>> + Decoder + 'static, I: 'static> {
    ptr: CleanFramedShutdown<S, U, I>,
    inner: Option<SplitSink<Framed<S, U>, I>>
}

pub struct CleanTcpShutdownStream<S: AsyncWrite + AsyncRead + Unpin + 'static, U: Encoder<I, Error: From<std::io::Error>> + Decoder + 'static, I: 'static> {
    ptr: CleanFramedShutdown<S, U, I>,
    inner: Option<SplitStream<Framed<S, U>>>
}

impl<S: AsyncWrite + AsyncRead + Unpin + 'static, U: Encoder<I, Error: From<std::io::Error>> + Decoder + 'static, I: 'static> CleanTcpShutdownSink<S, U, I> {
    pub fn new(inner: SplitSink<Framed<S, U>, I>, ptr: CleanFramedShutdown<S, U, I>) -> Self {
        Self { inner: Some(inner), ptr }
    }
}

impl<S: AsyncWrite + AsyncRead + Unpin + 'static, U: Encoder<I, Error: From<std::io::Error>> + Decoder + 'static, I: 'static> Drop for CleanTcpShutdownSink<S, U, I> {
    #[allow(unused_results)]
    fn drop(&mut self) {
        let inner = self.inner.take().unwrap();
        let ptr = self.ptr.clone();
        spawn!(ptr.push_sink(inner));
    }
}

impl<S: AsyncWrite + AsyncRead + Unpin + 'static, U: Encoder<I, Error: From<std::io::Error>> + Decoder + 'static, I: 'static> CleanTcpShutdownStream<S, U, I> {
    pub fn new(inner: SplitStream<Framed<S, U>>, ptr: CleanFramedShutdown<S, U, I>) -> Self {
        Self { inner: Some(inner), ptr }
    }
}

impl<S: AsyncWrite + AsyncRead + Unpin + 'static, U: Encoder<I, Error: From<std::io::Error>> + Decoder + 'static, I: 'static> Drop for CleanTcpShutdownStream<S, U, I> {
    #[allow(unused_results)]
    fn drop(&mut self) {
        let inner = self.inner.take().unwrap();
        let ptr = self.ptr.clone();
        spawn!(ptr.push_stream(inner));
    }
}

impl<S: AsyncWrite + AsyncRead + Unpin + 'static, U: Encoder<I, Error: From<std::io::Error>> + Decoder + 'static, I: 'static> Deref for CleanTcpShutdownSink<S, U, I> {
    type Target = SplitSink<Framed<S, U>, I>;

    fn deref(&self) -> &Self::Target {
        self.inner.as_ref().unwrap()
    }
}

impl<S: AsyncWrite + AsyncRead + Unpin + 'static, U: Encoder<I, Error: From<std::io::Error>> + Decoder + 'static, I: 'static> DerefMut for CleanTcpShutdownSink<S, U, I> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner.as_mut().unwrap()
    }
}

impl<S: AsyncWrite + AsyncRead + Unpin + 'static, U: Encoder<I, Error: From<std::io::Error>> + Decoder + 'static, I: 'static> Deref for CleanTcpShutdownStream<S, U, I> {
    type Target = SplitStream<Framed<S, U>>;

    fn deref(&self) -> &Self::Target {
        self.inner.as_ref().unwrap()
    }
}

impl<S: AsyncWrite + AsyncRead + Unpin + 'static, U: Encoder<I, Error: From<std::io::Error>> + Decoder + 'static, I: 'static> DerefMut for CleanTcpShutdownStream<S, U, I> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner.as_mut().unwrap()
    }
}

impl<S: AsyncWrite + AsyncRead + Unpin + 'static, U: Encoder<I, Error: From<std::io::Error>> + Decoder + 'static, I: 'static> CleanFramedShutdown<S, U, I> {
    pub fn new() -> Self {
        let inner = CleanFramedShutdownInner { sink: None, stream: None };
        CleanFramedShutdown { inner: Arc::new(Mutex::new(inner)) }
    }

    pub fn wrap(framed: Framed<S, U>) -> (CleanTcpShutdownSink<S, U, I>, CleanTcpShutdownStream<S, U, I>) {
        let ptr = Self::new();
        let (sink, stream) = framed.split();
        let sink = CleanTcpShutdownSink::new(sink, ptr.clone());
        let stream = CleanTcpShutdownStream::new(stream, ptr);
        (sink, stream)
    }

    pub async fn push_sink(self, sink: SplitSink<Framed<S, U>, I>) {
        let mut this = self.inner.lock();
        if let Some(stream) = this.stream.take() {
            let reunited = stream.reunite(sink);
            if let Ok(reunited) = reunited {
                Self::reunite_fn(reunited).await
            }
        } else {
            this.sink = Some(sink);
        }
    }

    pub async fn push_stream(self, stream: SplitStream<Framed<S, U>>) {
        let mut this = self.inner.lock();
        if let Some(sink) = this.sink.take() {
            let reunited = sink.reunite(stream);
            if let Ok(reunited) = reunited {
                Self::reunite_fn(reunited).await
            }
        } else {
            this.stream = Some(stream);
        }
    }

    #[allow(unused_must_use)]
    async fn reunite_fn(reunited: Framed<S, U>) {
        let mut reunited = reunited.into_inner();
        futures::future::poll_fn(move |cx| {
            Pin::new(&mut reunited).poll_shutdown(cx)
        }).await;
    }
}

impl<S, U, I> Clone for CleanFramedShutdown<S, U, I> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}