use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
};

use futures::{
    stream::{select_all, FuturesUnordered},
    Stream, StreamExt, TryFutureExt, TryStreamExt,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::server::TlsStream;

use crate::transport_services::{CertificateFileStorage, TransportStream};

mod error;
mod negotiatation;
mod state;
mod transport_services;

#[tokio::main]
async fn main() {
    let mut streams = Vec::new();
    let https: Pin<Box<dyn Stream<Item = TransportStream>>> = Box::pin(
        transport_services::Tcp::new(SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            8080,
        ))
        .await
        .map_err(|_| ())
        .and_then(|s| transport_services::Tls::new(s).map_err(|_| ()))
        .flat_map_unordered(None, |s| {
            let x: Pin<Box<dyn Stream<Item = TransportStream>>> =
                Box::pin(transport_services::Http::new(s.unwrap().inner()));

            x
        }),
    );

    let http: Pin<Box<dyn Stream<Item = TransportStream>>> = Box::pin(
        transport_services::Tcp::new(SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            8081,
        ))
        .await
        .map_err(|_| ())
        .flat_map_unordered(None, |s| {
            let x: Pin<Box<dyn Stream<Item = TransportStream>>> =
                Box::pin(transport_services::Http::new(s.unwrap()));

            x
        }),
    );

    streams.push(https);
    streams.push(http);

    select_all(streams)
        .for_each(|x| async move {
            match x {
                TransportStream::Command(_, _, _) => {}
                TransportStream::Data(_, _, _) => {}
                TransportStream::HttpProxy(req, si, res) => {
                    res.send(hyper::Response::new(http_body_util::Full::new(
                        hyper::body::Bytes::from("Hello World!"),
                    )))
                    .unwrap();
                }
                TransportStream::SniProxy(_) => {}
            }
        })
        .await;
}

pub enum ServiceType<T> {
    Sni(T),
    Regular(T),
}

pub(crate) trait AsyncSocket:
    AsyncRead + AsyncWrite + Unpin + Send + SocketInfoImpl + 'static
{
}
impl<T> AsyncSocket for T where T: AsyncRead + AsyncWrite + Unpin + Send + SocketInfoImpl + 'static {}

#[derive(Clone)]
struct SocketInfo {
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    tls_info: Option<TlsInfo>,
}

impl SocketInfoImpl for TcpStream {
    fn info(&self) -> io::Result<SocketInfo> {
        Ok(SocketInfo {
            peer_addr: self.peer_addr().unwrap(),
            local_addr: self.local_addr().unwrap(),
            tls_info: None,
        })
    }
}

impl SocketInfoImpl for TlsStream<TcpStream> {
    fn info(&self) -> io::Result<SocketInfo> {
        dbg!(self.get_ref().1.alpn_protocol());
        Ok(SocketInfo {
            peer_addr: self.get_ref().0.peer_addr()?,
            local_addr: self.get_ref().0.local_addr()?,
            tls_info: self.get_ref().1.server_name().and_then(|sni| {
                self.get_ref().1.alpn_protocol().map(|alpn| TlsInfo {
                    server_name: sni.to_owned(),
                    alpn: alpn.to_owned(),
                })
            }),
        })
    }
}

impl SocketInfoImpl for Box<dyn AsyncSocket> {
    fn info(&self) -> io::Result<SocketInfo> {
        (**self).info()
    }
}

pub(crate) trait SocketInfoImpl {
    fn info(&self) -> io::Result<SocketInfo>;
}

#[derive(Clone)]
struct TlsInfo {
    server_name: String,
    alpn: Vec<u8>,
}
