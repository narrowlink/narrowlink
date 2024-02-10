use std::{
    pin::Pin,
    task::{Context, Poll},
};

use crate::AsyncSocket;
use futures::Stream;
mod h1;
mod h2;
use super::TransportStream;

pub(crate) struct Http {
    receiver: tokio::sync::mpsc::UnboundedReceiver<TransportStream>,
    task: tokio::task::JoinHandle<()>,
}

impl Http {
    pub fn new(socket: impl AsyncSocket) -> Http {
        if socket
            .info()
            .unwrap()
            .tls_info
            .filter(|v| v.alpn == [104, 50])
            .is_some()
        {
            h2::H2::new(socket)
        } else {
            h1::H1::new(socket)
        }
    }
}

impl Stream for Http {
    type Item = TransportStream;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.receiver.poll_recv(cx) {
            Poll::Ready(Some(x)) => Poll::Ready(Some(x)),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
