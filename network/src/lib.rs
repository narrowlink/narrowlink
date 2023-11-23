pub use async_tools::{AsyncToStream, StreamToAsync};
use bytes::Buf;
use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305};
use std::{io, ops::Deref, pin::Pin, task::Poll};
use thiserror::Error;
mod async_tools;
pub mod error;
pub mod event;
pub mod p2p;
pub mod transport;
pub mod ws;
use error::NetworkError;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio_util::codec::{Decoder, Encoder, Framed};

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
    inner: Framed<Box<dyn AsyncSocket>, ChunkStream>,
    cipher: XChaCha20Poly1305,
    nonce: [u8; 24],
}

impl AsyncSocketCrypt {
    pub async fn new(key: [u8; 32], nonce: [u8; 24], inner: Box<dyn AsyncSocket>) -> Self {
        let cipher = XChaCha20Poly1305::new(&key.into());
        let chunk_stream = ChunkStream::new(None);
        Self {
            inner: tokio_util::codec::Framed::new(inner, chunk_stream),
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

#[derive(Error, Debug)]
enum ChunkError {
    #[error("Chunk is empty")]
    InvalidChunk,
    #[error("Chunk is out of order")]
    OutOfOrder,
    #[error("IO error {0}")]
    Future(#[from] std::io::Error),
}

struct ChunkStream {
    current_index: Option<(u64, u64)>, // send index, receive index
}

impl ChunkStream {
    fn new(current_index: Option<(u64, u64)>) -> ChunkStream {
        ChunkStream { current_index }
    }
}

struct Chunk {
    #[allow(dead_code)]
    index: u64,
    #[allow(dead_code)]
    length: u64,
    data: Vec<u8>,
}

impl Deref for Chunk {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl Decoder for ChunkStream {
    type Item = Chunk;

    type Error = ChunkError;

    fn decode(
        &mut self,
        src: &mut tokio_util::bytes::BytesMut,
    ) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 2 {
            return Ok(None);
        }
        let index_pointer = (src[0] & 0xf0) as u64;
        let len_pointer = (src[0] & 0x7f) as u64;
        if index_pointer > 8 || len_pointer > 8 || len_pointer == 0 {
            return Err(ChunkError::InvalidChunk);
        }
        if (src.len() as u64) < (len_pointer + index_pointer + 1) {
            return Ok(None);
        }
        let index = match index_pointer {
            0 => 0_u64,
            1 => u8::from_be_bytes([src[1]]) as u64,
            2 => u16::from_be_bytes([src[1], src[2]]) as u64,
            3..=4 => u32::from_be_bytes(
                src[1..index_pointer as usize]
                    .try_into()
                    .map_err(|_| ChunkError::InvalidChunk)?,
            ) as u64,
            5..=8 => u64::from_be_bytes(
                src[1..index_pointer as usize]
                    .try_into()
                    .map_err(|_| ChunkError::InvalidChunk)?,
            ),
            _ => return Err(ChunkError::InvalidChunk),
        };

        if self.current_index.filter(|(_, i)| i != &index).is_some() {
            return Err(ChunkError::OutOfOrder);
        }

        let length = match len_pointer {
            1 => u8::from_be_bytes([src[1 + index_pointer as usize]]) as u64,
            2 => u16::from_be_bytes([
                src[1 + index_pointer as usize],
                src[2 + index_pointer as usize],
            ]) as u64,
            3..=4 => u32::from_be_bytes(
                src[1 + (index_pointer as usize)..((index_pointer + len_pointer) as usize)]
                    .try_into()
                    .map_err(|_| ChunkError::InvalidChunk)?,
            ) as u64,
            5..=8 => u64::from_be_bytes(
                src[1 + index_pointer as usize..(index_pointer + len_pointer) as usize]
                    .try_into()
                    .map_err(|_| ChunkError::InvalidChunk)?,
            ),
            _ => return Err(ChunkError::InvalidChunk),
        };
        if src.len() < (index_pointer + len_pointer + length + 1) as usize {
            Ok(None)
        } else {
            src.advance((index_pointer + len_pointer + 1) as usize);
            Ok(Some(Chunk {
                index,
                length,
                data: src.split_to(length as usize).to_vec(),
            }))
        }
    }
}

impl Encoder<Vec<u8>> for ChunkStream {
    type Error = ChunkError;

    fn encode(
        &mut self,
        item: Vec<u8>,
        dst: &mut tokio_util::bytes::BytesMut,
    ) -> Result<(), Self::Error> {
        let index = self
            .current_index
            .map(|(i, _)| i)
            .unwrap_or(0)
            .to_be_bytes()
            .into_iter()
            .skip_while(|x| x == &0)
            .collect::<Vec<u8>>();

        let length = item
            .len()
            .to_be_bytes()
            .into_iter()
            .skip_while(|x| x == &0)
            .collect::<Vec<u8>>();
        dst.extend_from_slice(&[((index.len() as u8) << 4) | (length.len() as u8)]);
        dst.extend_from_slice(&index);
        dst.extend_from_slice(&length);
        dst.extend_from_slice(&item);
        self.current_index = self.current_index.map(|(i, y)| (i + item.len() as u64, y));

        Ok(())
    }
}
