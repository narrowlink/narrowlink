use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
};

use error::CertificateError;
use futures::{
    stream::{select_all, FuturesUnordered},
    Stream, StreamExt, TryFutureExt, TryStreamExt,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::server::TlsStream;
use transport_services::{AcmeService, CertificateResolver, DashMapCache};

use crate::transport_services::{CertificateFileStorage, TransportStream};
mod config;
mod error;
mod negotiatation;
mod state;
mod transport_services;

#[tokio::main]
async fn main() {
    
    let storage = Arc::new(CertificateFileStorage::default());
    let mut resolver = CertificateResolver::new(storage.clone(), DashMapCache::default());
    let acme = AcmeService::new(storage, "dev@narrowlink.com", None)
        .await
        .unwrap()
        .into();
    dbg!("s2");
    resolver.set_certificate_issuer(acme);
    dbg!("s");
    resolver
        .load_and_cache("main", "home.gateway.computer")
        .await
        .unwrap();

    let resolver = Arc::new(resolver);

    let mut streams = Vec::<Pin<Box<dyn Stream<Item = TransportStream>>>>::new();
    streams.push(Box::pin(
        transport_services::Tcp::new(SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            443,
        ))
        .await
        .map_err(|x| ())
        .and_then(|s| transport_services::Tls::new(s, resolver.clone()).map_err(|_| ()))
        .flat_map_unordered(None, |s| {
            Box::pin(transport_services::Http::new(s.unwrap().inner()))
        }),
    ));
    dbg!("s");
    streams.push(Box::pin(
        transport_services::Tcp::new(SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            80,
        ))
        .await
        .map_err(|_| ())
        .flat_map_unordered(None, |s| {
            Box::pin(transport_services::Http::new(s.unwrap()))
        }),
    ));

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
