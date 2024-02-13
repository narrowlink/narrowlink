use std::{collections::VecDeque, io, sync::Arc};

use rustls::internal::msgs::{
    codec::{self, Codec},
    handshake, message,
};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use crate::{
    error::GatewayError, transport_services::certificate::CertificateResolver, AsyncSocket,
};

// use super::certificate::CertificateStorage;

pub(crate) enum Tls {
    Unpacked(Box<dyn AsyncSocket>),
    Original(Box<dyn AsyncSocket>),
}

impl Tls {
    pub async fn new(
        socket: TcpStream,
        // certificate_storage: impl CertificateStorage,
    ) -> Result<Self, GatewayError> {
        // let mut buf = vec![0; 1024];
        // let len = socket.peek(&mut buf).await.unwrap();
        // let (sni, alpns) = Self::peek_sni_and_alpns(&buf[..len]).unwrap();
        // dbg!(&sni, alpns);
        let resolver = CertificateResolver::default();
        resolver.load_and_cache("main", "home.gateway.computer").await.unwrap();

        let resolver = Arc::new(resolver);
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        // let config = certificate_storage.get_config("main", &sni).await.unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        // dbg!("accepting");
        let mut stream = acceptor.accept(socket).await.unwrap();
        // dbg!("accepted");
        Ok(Tls::Unpacked(Box::new(stream)))
        // Ok(TLS::Unpacked(Box::new(socket)))
    }
    pub fn peek_sni_and_alpns(buf: &[u8]) -> Option<(String, Vec<Vec<u8>>)> {
        let message = message::OpaqueMessage::read(&mut codec::Reader::init(buf)).ok()?;

        let mut r = codec::Reader::init(message.payload());
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
    pub fn inner(self) -> Box<dyn AsyncSocket> {
        match self {
            Tls::Unpacked(s) => s,
            Tls::Original(s) => s,
        }
    }
}
