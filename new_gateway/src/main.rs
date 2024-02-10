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
// pub struct UpgradeAsync(Upgraded);

// impl AsyncRead for UpgradeAsync {
//     fn poll_read(
//         mut self: std::pin::Pin<&mut Self>,
//         cx: &mut std::task::Context<'_>,
//         buf: &mut ReadBuf,
//     ) -> std::task::Poll<std::io::Result<()>> {
//         let mut pinned = std::pin::pin!(self.0);
//         pinned.as_mut().poll_read(cx, buf)
//     }
// }

#[tokio::main]
async fn main() {
    // negotiatation::Publish::new(Uuid::new_v4(), "127.0.0.1:1080".parse().unwrap());
    // let mut x = negotiatation::Request::default();
    // let mut a = negotiatation::Agent::default();
    // a.publish.push(negotiatation::Publish::new(
    //     Uuid::new_v4(),
    //     "127.0.0.1:1080".parse().unwrap(),
    // ));
    // a.name = "hello".to_string();
    // a.uid = Uuid::new_v4().as_bytes().to_vec();
    // x.sign = vec![
    //     1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3,
    // ];
    // x.msg = Some(negotiatation::request::Msg::Agent(a));
    // let o = negotiatation::Request::decode(x.encode_to_vec().as_slice()).unwrap();
    // dbg!(o);
    // negotiatation::Request::try_from(&x.encode_to_vec());)
    // prost::Message::decode(x.encode_to_vec().as_slice()).unwrap();

    // let xx = base64::engine::GeneralPurposeConfig::new().with_decode_padding_mode(base64::engine::DecodePaddingMode::RequireNone).with_encode_padding(false);
    // dbg!(xx.encode_padding());
    // let gp = base64::engine::GeneralPurpose::new(&base64::alphabet::STANDARD, xx);
    // dbg!(gp.encode(x.encode_to_vec()));
    // dbg!(x.encode_to_vec());
    // dbg!(x.encode_to_vec().len());
    // 16+16+14+5

    // Client::Publish(negotiatation::Publish::new(
    //     Uuid::new_v4(),
    //     "127.0.0.1:1080".parse().unwrap(),
    // ));
    // x.msg = Some(negotiatation::request::Msg::Client(negotiatation::Client::Publish(
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

// struct TcpService;

// impl Service<ServiceType<>> for TcpService {
//     type Response;

//     type Error;

//     type Future;

//     fn poll_ready(
//         &mut self,
//         cx: &mut std::task::Context<'_>,
//     ) -> std::task::Poll<Result<(), Self::Error>> {
//         todo!()
//     }

//     fn call(&mut self, req: Request) -> Self::Future {
//         todo!()
//     }
// }

pub(crate) trait AsyncSocket:
    AsyncRead + AsyncWrite + Unpin + Send + SocketInfoImpl + 'static
{
}
impl<T> AsyncSocket for T where T: AsyncRead + AsyncWrite + Unpin + Send + SocketInfoImpl + 'static {}

// pub struct TlsListener<S> {
//     listener: S,
// }

// impl TlsListener<TcpListener> {
//     async fn accept(&mut self) -> (impl AsyncSocket, SocketInfo) {
//         let (socket, peer_addr) = self.listener.accept().await.unwrap();
//         let local_addr = socket.local_addr().unwrap();
//         let tls_info = None;
//         let socket_info = SocketInfo {
//             peer_addr,
//             local_addr,
//             tls_info,
//         };
//         (socket, socket_info)
//     }
// }

// pub struct HttpService<S> {
//     socket_info: SocketInfo,
//     socket: S,
// }

// impl<S> HttpService<S>
// where
//     S: AsyncSocket,
// {
//     pub fn new(socket_info: SocketInfo, socket: S) -> HttpService<S> {
//         HttpService {
//             socket_info,
//             socket,
//         }
//     }
// }

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
// pub(crate) trait SocketPeekImpl {
//     async fn peek(&self) -> io::Result<SocketInfo>;
// }

#[derive(Clone)]
struct TlsInfo {
    server_name: String,
    alpn: Vec<u8>,
}
