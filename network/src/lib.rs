pub use async_tools::{AsyncToStream, StreamToAsync};
use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305};
use chunkio::ChunkIO;
use std::{io, pin::Pin, task::Poll};
mod async_tools;
pub mod error;
pub mod event;
pub mod p2p;
pub mod transport;
pub mod ws;
use error::NetworkError;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

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
                    None=>{
                        let _ = left_tx.close().await;
                        let _ = right_tx.close().await;
                        return Ok(())
                    }
                };
            },
            res = right_rx.next() => {
                match res{
                    Some(v)=>left_tx.send(v?).await?,
                    None=>{
                        let _ = left_tx.close().await;
                        let _ = right_tx.close().await;
                        return Ok(())
                    }
                };
            },
        }
    }
}

pub async fn async_forward(
    left: impl AsyncSocket,
    right: impl AsyncSocket,
) -> Result<(), NetworkError> {
    let (mut left_rx, mut left_tx) = tokio::io::split(left);
    let (mut right_rx, mut right_tx) = tokio::io::split(right);
    loop {
        tokio::select! {
            res = tokio::io::copy(&mut left_rx, &mut right_tx) => {
                if res? == 0 {
                    let _ = left_tx.shutdown().await;
                    let _ = right_tx.shutdown().await;
                    return Ok(())
                }
            },
            res = tokio::io::copy(&mut right_rx, &mut left_tx) => {
                if res? == 0 {
                    let _ = left_tx.shutdown().await;
                    let _ = right_tx.shutdown().await;
                    return Ok(())
                }
            },
        }
    }
}

pub struct AsyncSocketCrypt {
    inner: ChunkIO<Box<dyn AsyncSocket>>,
    cipher: XChaCha20Poly1305,
    nonce: [u8; 24],
}

impl AsyncSocketCrypt {
    pub async fn new(key: [u8; 32], nonce: [u8; 24], inner: Box<dyn AsyncSocket>) -> Self {
        let cipher = XChaCha20Poly1305::new(&key.into());
        Self {
            inner: ChunkIO::new(inner),
            cipher,
            nonce,
        }
    }
}

impl Stream for AsyncSocketCrypt {
    type Item = Result<Vec<u8>, std::io::Error>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match self
            .inner
            .poll_next_unpin(cx)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?
        {
            Poll::Ready(Some(chunk)) => Poll::Ready(Some(
                self.cipher
                    .decrypt(&self.nonce.into(), chunk.as_ref())
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string())),
            )),
            Poll::Pending => Poll::Pending,
            _ => Poll::Ready(None),
        }
    }
}
impl Sink<Vec<u8>> for AsyncSocketCrypt {
    type Error = std::io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready_unpin(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        let buf = self
            .cipher
            .encrypt(&self.nonce.into(), item.as_ref())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        self.inner
            .start_send_unpin(buf)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_flush_unpin(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_close_unpin(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }
}

impl AsyncRead for AsyncSocketCrypt {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match Pin::new(&mut self).poll_next(cx)? {
            Poll::Ready(Some(item)) => {
                let b = self
                    .cipher
                    .decrypt(&self.nonce.into(), item.as_slice())
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                buf.put_slice(&b); // todo: fix
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for AsyncSocketCrypt {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.as_mut().poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                let cipher_text = self
                    .cipher
                    .encrypt(&self.nonce.into(), buf)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                match self.start_send_unpin(cipher_text) {
                    Ok(()) => Poll::Ready(Ok(buf.len())),
                    Err(e) => Poll::Ready(Err(e)),
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        <dyn Sink<Vec<u8>, Error = std::io::Error>>::poll_flush(self, cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.poll_close(cx)
    }
}
