use std::{
    net::{SocketAddr, UdpSocket},
    ops::DerefMut,
    sync::Arc,
};

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use futures_util::Future;
use h3::{
    quic::{BidiStream, SendStream},
    server::RequestStream,
};
use quinn::{EndpointConfig, ServerConfig};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::mpsc::UnboundedSender,
};
use tracing::{span, trace};

use crate::{error::GatewayError, state::InBound};

use super::{wss::TlsEngine, Service};

#[derive(Clone)]
pub struct QUIC {
    listen_addr: SocketAddr,
    domains: Vec<String>,
    status_sender: UnboundedSender<InBound>,
    cm: TlsEngine,
}

impl QUIC {
    pub fn from(
        quic: &crate::config::QUICService,
        status_sender: UnboundedSender<InBound>,
        cm: TlsEngine,
    ) -> Self {
        Self {
            listen_addr: quic.listen_addr,
            domains: quic.domains.to_owned(),
            status_sender,
            cm,
        }
    }
}
#[async_trait]
impl Service for QUIC {
    async fn run(self) -> Result<(), GatewayError> {
        let span = span!(tracing::Level::TRACE, "quic", listen_addr = %self.listen_addr, domains = ?self.domains);
        let tls_engine = self.cm.clone();
        if let TlsEngine::Acme(acme, _) = &tls_engine {
            let _ = acme.clone().get_service_sender().send(
                crate::service::certificate::manager::CertificateServiceMessage::Load(
                    "main".to_owned(),
                    "self".to_owned(),
                    self.domains,
                ),
            );
        }
        span.in_scope(|| trace!("binding listener"));
        // span_connection.in_scope(|| trace!("setting up tls acceptor"));
        // let secure_stream =
        //     TlsAcceptor::from(tls_engine.get_server_config().await)
        //         .accept(tcp_stream)
        //         .instrument(span_connection.clone())
        //         .await
        //         .map_err(|_| ())?;
        let server_config = ServerConfig::with_crypto(tls_engine.get_server_config());

        let endpoint = quinn::Endpoint::new(
            EndpointConfig::default(),
            Some(server_config),
            UdpSocket::bind(self.listen_addr)?,
            quinn::default_runtime().unwrap(),
        )
        .unwrap();
        dbg!(2);
        while let Some(mut new_conn) = endpoint.accept().await {
            let x:Box<quinn::crypto::rustls::HandshakeData> = new_conn.handshake_data().await.unwrap().downcast().unwrap();
            dbg!(x.server_name);
            trace!("New connection being attempted");
            tokio::spawn(async move {
                match new_conn.await {
                    Ok(conn) => {
                        trace!("Connection established");
                        let mut h3_conn =
                            h3::server::Connection::new(h3_quinn::Connection::new(conn))
                                .await
                                .unwrap();
                        loop {
                            match h3_conn.accept().await {
                                Ok(Some((req, mut stream))) => {
                                    dbg!(req.body());
                                    // spawn a new task to handle the request
                                    tokio::spawn(async move {
                                        // build a http response
                                        let response = hyper::Response::builder()
                                            .status(hyper::StatusCode::OK)
                                            .body(())
                                            .unwrap();
                                        // let x = stream.as_mut();
                                        // send the response to the wire
                                        if stream.send_response(response).await.is_err(){
                                            dbg!(22);
                                            return ;
                                        }
                                        // // send some date
                                        // stream.send_data(bytes::Bytes::from("test")).await.unwrap();
                                        // // let x = stream.recv_data().await.unwrap().unwrap();
                                        // // dbg!(x.chunk());
                                        // stream.send_data(bytes::Bytes::from("test")).await.unwrap();
                                        // stream.finish().await.unwrap();
                                        let mut s = RequestStreamWrapper::new(stream);
                                        s.write("src".as_bytes()).await.unwrap();
                                        s.shutdown().await.unwrap();
                                    });
                                }
                                Ok(None) => {
                                    // break if no Request is accepted
                                    break;
                                }
                                Err(err) => {
                                    match err.get_error_level() {
                                        // break on connection errors
                                        h3::error::ErrorLevel::ConnectionError => break,
                                        // continue on stream errors
                                        h3::error::ErrorLevel::StreamError => continue,
                                    }
                                }
                            }
                        }
                        // let _ = wss.status_sender.send(InBound::QUIC(conn));
                    }
                    Err(e) => {
                        trace!("Connection failed: {:?}", e);
                    }
                }
            });
        }
        Ok(())
    }
}

// h.insert("Alt-Svc", hyper::header::HeaderValue::from_static("h3=\":443\"; ma=2592000"));

// pub struct RequestStreamWrapper<S,B> //where S: h3::quic::RecvStream
// {rs: pub RequestStream<S,B>}

pub struct RequestStreamWrapper<S: BidiStream<B>, B: bytes::Buf>(RequestStream<S, B>);

impl<S: BidiStream<B>, B: bytes::Buf> RequestStreamWrapper<S, B> {
    pub fn new(rs: RequestStream<S, B>) -> Self {
        Self(rs)
    }
}

impl<S: BidiStream<B>, B: bytes::Buf> AsyncRead for RequestStreamWrapper<S, B> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match std::pin::Pin::new(&mut Box::pin(self.0.recv_data())).poll(cx) {
            std::task::Poll::Ready(Ok(Some(data))) => {
                buf.put_slice(data.chunk());
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(Ok(None)) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Ready(Err(e)) => {
                std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl<S: h3::quic::BidiStream<bytes::Bytes>> AsyncWrite for RequestStreamWrapper<S, bytes::Bytes> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let buf = bytes::Bytes::from(buf.to_owned());
        let buf_len = buf.len();
        match std::pin::Pin::new(&mut Box::pin(self.0.send_data(buf))).poll(cx) {
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(buf_len)),
            std::task::Poll::Ready(Err(e)) => {
                std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match std::pin::Pin::new(&mut Box::pin(self.0.finish())).poll(cx) {
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Ready(Err(e)) => {
                std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl<S: BidiStream<B>, B: bytes::Buf> std::marker::Unpin for RequestStreamWrapper<S, B> {}
