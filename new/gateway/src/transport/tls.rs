use std::{collections::VecDeque, io, sync::Arc};

use rustls::internal::msgs::{
    codec::{self, Codec},
    handshake, message,
};
use tokio::net::TcpStream;
use tokio_rustls::{server::TlsStream, TlsAcceptor};

use crate::{
    error::{GatewayError, GatewayNetworkError},
    transport::certificate::CertificateResolver,
};

use super::{AsyncSocket, SocketInfo, SocketInfoImpl};

pub mod alpn {
    pub const H2: &[u8] = b"h2";
    pub const HTTP1_1: &[u8] = b"http/1.1";
    pub const ACME_TLS_ALPN_NAME: &[u8] = b"acme-tls/1";
}

pub struct Tls {
    acceptor: Arc<TlsAcceptor>,
}

pub(crate) enum TlsConnection {
    Unpacked(Box<dyn AsyncSocket>),
    Original(Box<dyn AsyncSocket>),
}

impl Tls {
    pub fn new(certificate_resolver: Arc<CertificateResolver>) -> Self {
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(certificate_resolver);
        config.alpn_protocols = vec![
            alpn::H2.to_owned(),
            alpn::HTTP1_1.to_owned(),
            alpn::ACME_TLS_ALPN_NAME.to_owned(),
        ];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        Self {
            acceptor: Arc::new(acceptor),
        }
    }
    pub async fn accept(&self, socket: TcpStream) -> Result<TlsConnection, GatewayError> {
        let stream = self
            .acceptor
            .accept(socket)
            .await
            .map_err(GatewayNetworkError::TlsError)?;
        Ok(TlsConnection::Unpacked(Box::new(stream)))
    }
    pub fn peek_sni_and_alpns(buf: &[u8]) -> Option<(String, Vec<Vec<u8>>)> {
        let message = message::OutboundOpaqueMessage::read(&mut codec::Reader::init(buf)).ok()?;

        let mut r = codec::Reader::init(message.payload.as_ref());
        let _typ = rustls::HandshakeType::read(&mut r).ok()?;

        let len = r.take(3).and_then(|v| {
            if let [a, b, c] = v {
                Some(u32::from_be_bytes([0, *a, *b, *c]) as usize)
            } else {
                None
            }
        })?;
        let mut sub = r.sub(len).ok()?;
        let ch = handshake::ClientHelloPayload::read(&mut sub).ok()?;

        let sni = ch.extensions.iter().find_map(|e| {
            if let handshake::ClientExtension::ServerName(ref ch) = e {
                let mut raw_sni = VecDeque::from(ch.first()?.get_encoding());
                let _typ = raw_sni.pop_front()?;
                let sni_len =
                    u16::from_be_bytes([raw_sni.pop_front()?, raw_sni.pop_front()?]) as usize;
                let sni = raw_sni.into_iter().map(|b| b as char).collect::<String>();
                if sni_len == sni.len() {
                    Some(sni)
                } else {
                    None
                }
            } else {
                None
            }
        })?;

        let available_alpns = ch.extensions.iter().find_map(|e| {
            if let handshake::ClientExtension::Protocols(ref ch) = e {
                Some(
                    ch.iter()
                        .filter_map(|p| {
                            let mut raw_protocol = VecDeque::from(p.get_encoding());
                            raw_protocol.pop_front().and_then(|protocol_len| {
                                if protocol_len as usize == raw_protocol.len() {
                                    Some(Vec::from(raw_protocol))
                                } else {
                                    None
                                }
                            })
                        })
                        .collect::<Vec<Vec<u8>>>(),
                )
            } else {
                None
            }
        });
        Some((sni, available_alpns.unwrap_or_default()))
    }
}

impl TlsConnection {
    pub fn inner(self) -> Box<dyn AsyncSocket> {
        match self {
            TlsConnection::Unpacked(s) => s,
            TlsConnection::Original(s) => s,
        }
    }
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
#[derive(Clone)]
pub struct TlsInfo {
    server_name: String,
    alpn: Vec<u8>,
}
impl TlsInfo {
    pub fn server_name(&self) -> &str {
        &self.server_name
    }
    pub fn alpn(&self) -> &[u8] {
        &self.alpn
    }
}
