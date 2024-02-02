
use std::{pin::Pin, task::{Context, Poll}};

use futures::Stream;
use crate::AsyncSocket;
mod h1;
mod h2;
use super::TransportStream;

pub(crate) struct HTTP<S> {
    receiver: tokio::sync::mpsc::UnboundedReceiver<TransportStream<S>>,
    task: tokio::task::JoinHandle<()>,
}

impl<S> HTTP<S>
where
    S: AsyncSocket,
{
    pub fn new(socket: S) -> HTTP<S> {
        if socket.info().unwrap().tls_info.unwrap().alpn == [104,50]{
            h2::H2::new(socket)
        }else{
            h1::H1::new(socket)
        }
    }
}

impl<S: AsyncSocket> Stream for HTTP<S> {
    type Item = TransportStream<S>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match self.receiver.poll_recv(cx) {
            Poll::Ready(Some(x)) => Poll::Ready(Some(x)),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
