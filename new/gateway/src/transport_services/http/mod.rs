use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use crate::error::GatewayError;
use futures::Stream;
mod error;
mod h1;
mod h2;
use super::{AsyncSocket, CertificateIssue, TransportStream};

pub(crate) struct Http {
    receiver: tokio::sync::mpsc::UnboundedReceiver<TransportStream>,
    task: tokio::task::JoinHandle<()>,
}

impl Http {
    pub fn new(
        socket: impl AsyncSocket,
        issue: Option<Arc<impl CertificateIssue + Send + Sync + 'static>>,
    ) -> Result<Http, GatewayError> {
        if socket
            .info()
            .unwrap()
            .tls_info
            .filter(|v| v.alpn() == [104, 50])
            .is_some()
        {
            Self::h2(socket)
        } else {
            Self::h1(socket, issue)
        }
    }
}

impl Stream for Http {
    type Item = TransportStream;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.receiver.poll_recv(cx)
    }
}
