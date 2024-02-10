use std::{io::Error, net::SocketAddr, pin::Pin};

use futures::{FutureExt, Stream};
use tokio::net::{TcpListener, TcpStream};

pub struct Tcp {
    listener: Pin<Box<TcpListener>>,
}

impl Tcp {
    pub async fn new(listen_addr: SocketAddr) -> Tcp {
        let listener = TcpListener::bind(listen_addr).await.unwrap();

        Tcp {
            listener: Box::pin(listener),
        }
    }
}

impl Stream for Tcp {
    type Item = Result<TcpStream, Error>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.listener.poll_accept(cx).map(|result| {
            Some(result.map(|(stream, _peer_addr)| stream))
        })
    }
}
