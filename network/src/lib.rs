pub use async_tools::{AsyncToStream, StreamToAsync};
use chacha20::XChaCha20;
use std::{pin::Pin, task::Poll};
mod async_tools;
pub mod error;
pub mod event;
pub mod transport;
pub mod ws;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use error::NetworkError;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};

pub trait AsyncSocket: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T> AsyncSocket for T where T: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

pub trait UniversalStream<S, E>:
    Stream<Item = Result<S, E>> + Sink<S, Error = E> + Unpin + Send + 'static
{
}
impl<S, E, T> UniversalStream<S, E> for T where
    T: Stream<Item = Result<S, E>> + Sink<S, Error = E> + Unpin + Send + 'static
{
}

pub async fn stream_forward(
    left: impl UniversalStream<Vec<u8>, NetworkError>,
    right: impl UniversalStream<Vec<u8>, NetworkError>,
) -> Result<(), NetworkError> {
    let (mut left_tx, mut left_rx) = left.split();
    let (mut right_tx, mut right_rx) = right.split();

    loop {
        tokio::select! {
            res = left_rx.next() => {
                match res{
                    Some(v)=>right_tx.send(v?).await?,
                    None=>return Ok(())
                };
            },
            res = right_rx.next() => {
                match res{
                    Some(v)=>left_tx.send(v?).await?,
                    None=>return Ok(())
                };
            },
        }
    }
}

pub struct StreamCrypt {
    inner: Box<dyn UniversalStream<Vec<u8>, NetworkError>>,
    cipher: XChaCha20,
}

impl StreamCrypt {
    pub fn new(
        key: [u8; 32],
        nonce: [u8; 24],
        inner: impl UniversalStream<Vec<u8>, NetworkError>,
    ) -> Self {
        let cipher = XChaCha20::new(&key.into(), &nonce.into());
        Self {
            inner: Box::new(inner),
            cipher,
        }
    }
}

impl Stream for StreamCrypt {
    type Item = Result<Vec<u8>, NetworkError>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match self.inner.poll_next_unpin(cx)? {
            Poll::Ready(Some(mut buf)) => {
                self.cipher.apply_keystream(&mut buf);
                Poll::Ready(Some(Ok(buf)))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
impl Sink<Vec<u8>> for StreamCrypt {
    type Error = NetworkError;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready_unpin(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        let mut buf = item.to_vec();
        self.cipher.apply_keystream(&mut buf);
        self.inner.start_send_unpin(buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_flush_unpin(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_close_unpin(cx)
    }
}
