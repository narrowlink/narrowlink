use std::{
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
};

use futures::{stream::select_all, Stream, StreamExt, TryStreamExt};

use transport_services::{AcmeService, CertificateResolver};

use crate::transport_services::{CertificateFileStorage, DashMapCache, TransportStream};
mod config;
mod error;
mod messages;
mod state;
mod transport_services;

#[tokio::main]
async fn main() {
    env_logger::init();
    let storage = Arc::new(CertificateFileStorage::default());
    let mut resolver = CertificateResolver::new(storage.clone(), DashMapCache::default());
    let acme = AcmeService::new(storage, "dev@narrowlink.com", None)
        .await
        .map(Arc::new)
        .ok();
    dbg!("s2");

    resolver.set_certificate_issuer(acme.clone());

    dbg!("s");
    resolver
        .load_and_cache("main", "home.gateway.computer")
        .await
        .unwrap();

    let resolver = Arc::new(resolver);
    let tls = transport_services::Tls::new(resolver.clone());
    let mut streams = Vec::<Pin<Box<dyn Stream<Item = TransportStream>>>>::new();

    streams.push(Box::pin(
        transport_services::Tcp::new(SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            80,
        ))
        .await
        .map_err(error::GatewayError::IOError)
        .flat_map_unordered(None, |s| {
            match s.and_then(|s| transport_services::Http::new(s, acme.clone())) {
                Ok(s) => Box::pin(s) as Pin<Box<dyn Stream<Item = TransportStream>>>,
                Err(e) => Box::pin(futures::stream::once(futures::future::ready(
                    TransportStream::Error(e),
                ))),
            }
        }),
    ));
    dbg!("sss");

    streams.push(Box::pin(
        transport_services::Tcp::new(SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            443,
        ))
        .await
        .map_err(error::GatewayError::IOError)
        .and_then(|s| tls.accept(s))
        .flat_map_unordered(None, |s| {
            match s.and_then(|s| transport_services::Http::new(s.inner(), None::<Arc<AcmeService>>))
            {
                Ok(s) => Box::pin(s) as Pin<Box<dyn Stream<Item = TransportStream>>>,
                Err(e) => Box::pin(futures::stream::once(futures::future::ready(
                    TransportStream::Error(e),
                ))),
            }
        }),
    ));
    dbg!("s");

    select_all(streams)
        .for_each_concurrent(None, |x| async move {
            match x {
                TransportStream::Command(_, _, _) => {}
                TransportStream::Data(_, _, _) => {}
                TransportStream::HttpProxy(_req, _si, res) => {
                    res.send(hyper::Response::new(http_body_util::Full::new(
                        hyper::body::Bytes::from("Hello World!"),
                    )))
                    .unwrap();
                }
                TransportStream::SniProxy(_) => {}
                TransportStream::Error(e) => {
                    dbg!(e);
                }
            }
        })
        .await;
}

pub enum ServiceType<T> {
    Sni(T),
    Regular(T),
}
