use std::{net::SocketAddr, sync::Arc};

use crate::{config::TlsConfig, error::GatewayError, state::InBound};

use async_trait::async_trait;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use rustls::ServerConfig;
use tokio::{net::TcpListener, sync::mpsc::UnboundedSender};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, instrument, span, trace, warn, Instrument};

use super::{certificate::manager::CertificateManager, ws::WsService, RequestProtocol, Service};

#[derive(Clone)]
pub struct Wss {
    listen_addr: SocketAddr,
    domains: Vec<String>,
    status_sender: UnboundedSender<InBound>,
    cm: TlsEngine,
}
#[derive(Clone)]
pub enum TlsEngine {
    Acme(Arc<CertificateManager>),
    File((Vec<String>, Arc<ServerConfig>)),
}

impl TlsEngine {
    #[instrument(name = "tls_engine::new", skip(conf))]
    pub async fn new(conf: TlsConfig) -> Result<Self, GatewayError> {
        debug!("tls config: {:?}", conf);
        match conf {
            TlsConfig::Acme(acme) => {
                trace!("setting up acme tls engine");
                let certificate_file_storage = Arc::new(
                    crate::service::certificate::file_storage::CertificateFileStorage::new(
                        "./certificates",
                    ),
                );
                let certificate_manager = CertificateManager::new(
                    certificate_file_storage,
                    Some((acme.email, acme.challenge_type, acme.directory_url)),
                )
                .in_current_span()
                .await?;
                trace!("acme tls engine successfully created");
                Ok(Self::Acme(Arc::new(certificate_manager)))
            }
            TlsConfig::File(file) => {
                trace!("setting up file tls engine");
                let cert = super::certificate::Certificate::from_pem_vec(pem::parse_many(
                    tokio::fs::read_to_string(file.cert_path).await?,
                )?)?
                .get_config();
                trace!("file tls engine successfully created");
                Ok(Self::File((file.domains, cert)))
            }
        }
    }
}

impl Wss {
    pub fn from(
        ws: &crate::config::WsSecureService,
        status_sender: UnboundedSender<InBound>,
        cm: TlsEngine,
    ) -> Self {
        Self {
            listen_addr: ws.listen_addr,
            domains: ws.domains.to_owned(),
            status_sender,
            cm,
        }
    }
    // buf is the first 1024 bytes of the tcp stream, which is the client hello
    #[instrument(name = "peek_sni_and_alpns", skip(buf))]
    pub fn peek_sni_and_alpns(buf: &[u8]) -> Option<(String, Vec<Vec<u8>>)> {
        trace!("peeking sni and alpns from client hello");
        use tls_parser::{
            parse_tls_extensions, parse_tls_plaintext, SNIType, TlsExtension, TlsMessage,
            TlsMessageHandshake,
        };
        let (_, record) = parse_tls_plaintext(buf).ok()?;
        let hello = record.msg.iter().find_map(|message| match message {
            TlsMessage::Handshake(TlsMessageHandshake::ClientHello(hello)) => Some(hello),
            _ => None,
        })?;
        let (_, extensions) = parse_tls_extensions(hello.ext?).ok()?;
        let names = extensions.iter().find_map(|extension| match extension {
            TlsExtension::SNI(names) => Some(names),
            _ => None,
        })?;
        // Match rustls 0.21: reject IP addresses and malformed hostnames in SNI,
        // and use only the first entry in the first server-name extension.
        for (kind, name) in names {
            if *kind == SNIType::HostName {
                let name = std::str::from_utf8(name).ok()?;
                if !matches!(
                    rustls::pki_types::ServerName::try_from(name),
                    Ok(rustls::pki_types::ServerName::DnsName(_))
                ) {
                    return None;
                }
            }
        }
        let (kind, name) = names.first()?;
        if *kind != SNIType::HostName {
            return None;
        }
        let sni = std::str::from_utf8(name).ok()?.to_owned();
        let available_alpns = extensions
            .iter()
            .find_map(|extension| match extension {
                TlsExtension::ALPN(protocols) => {
                    Some(protocols.iter().map(|protocol| protocol.to_vec()).collect())
                }
                _ => None,
            })
            .unwrap_or_default();
        Some((sni, available_alpns))
    }
}

#[async_trait]
impl Service for Wss {
    async fn run(self) -> Result<(), GatewayError> {
        let span = span!(tracing::Level::TRACE, "wss", listen_addr = %self.listen_addr, domains = ?self.domains);

        let wss = self.clone();
        let tls_engine = self.cm.clone();
        if let TlsEngine::Acme(acme) = &tls_engine {
            let _ = acme.clone().get_service_sender().send(
                crate::service::certificate::manager::CertificateServiceMessage::Load(
                    "main".to_owned(),
                    "self".to_owned(),
                    self.domains,
                ),
            );
        }
        span.in_scope(|| trace!("binding tcp listener"));

        let tcp_listener = TcpListener::bind(&self.listen_addr).await?;
        loop {
            let Ok((tcp_stream, peer_addr)) = tcp_listener.accept().await else {
                span.in_scope(|| warn!("failed to accept tcp connection"));
                continue;
            };
            let span_connection = span
                .in_scope(|| span!(tracing::Level::TRACE, "connection", peer_addr = %peer_addr));

            let wss = wss.clone();
            let tls_engine = tls_engine.clone();
            tokio::spawn(async move {
                let mut buf = vec![0; 2048];
                tcp_stream
                    .peek(&mut buf)
                    .instrument(span_connection.clone())
                    .await
                    .map_err(|_| {
                        span_connection.in_scope(|| trace!("failed to peek client hello"));
                    })?;

                let Some((sni, alpns)) =
                    span_connection.in_scope(|| Self::peek_sni_and_alpns(&buf))
                else {
                    span_connection.in_scope(|| warn!("failed to peek sni and alpns"));
                    return Err::<(), ()>(());
                };
                span_connection.record("sni", &sni);
                let Some(server_config) = (match tls_engine {
                    TlsEngine::Acme(acme) => {
                        if acme.acme_type().is_some()
                            && alpns.contains(&super::certificate::ACME_TLS_ALPN_NAME.to_vec())
                        {
                            span_connection.in_scope(|| trace!("tls alpn 01 challenge detected"));
                            acme.get_acme_tls_challenge(&sni)
                                .instrument(span_connection.clone())
                                .await
                                .ok()
                        } else {
                            span_connection.in_scope(|| trace!("get certificate from acme"));
                            acme.get(&sni)
                                .instrument(span_connection.clone())
                                .await
                                .ok()
                        }
                    }
                    TlsEngine::File((domains, acceptor)) => {
                        if domains.contains(&sni) {
                            span_connection.in_scope(|| trace!("get certificate from file"));
                            Some(acceptor)
                        } else {
                            span_connection.in_scope(|| {
                                trace!("no certificate found for this domain in file")
                            });
                            None
                        }
                    }
                }) else {
                    span_connection.in_scope(|| trace!("certificate not found, act as SNI proxy"));
                    let _ = wss.status_sender.send(InBound::TlsTransparent(
                        sni,
                        tcp_stream,
                        self.listen_addr.port(),
                    ));
                    return Ok::<(), ()>(());
                };
                span_connection.in_scope(|| trace!("setting up tls acceptor"));
                let secure_stream = TlsAcceptor::from(server_config)
                    .accept(tcp_stream)
                    .instrument(span_connection.clone())
                    .await
                    .map_err(|_| ())?;
                span_connection.in_scope(|| trace!("tls acceptor successfully created"));
                if let Err(http_err) = Builder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(
                        TokioIo::new(secure_stream),
                        WsService {
                            listen_addr: RequestProtocol::Https(self.listen_addr),
                            domains: wss.domains,
                            sni: Some(sni),
                            status_sender: wss.status_sender,
                            peer_addr,
                            cm: None,
                        },
                    )
                    .instrument(span_connection.clone())
                    .await
                {
                    span_connection.in_scope(|| warn!("{}", http_err));
                };
                Ok::<(), ()>(())
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Wss;
    use std::sync::Arc;

    #[test]
    fn extracts_server_name_and_alpn_from_client_hello() {
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let name = rustls::pki_types::ServerName::try_from("example.com").unwrap();
        let mut client = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        assert_eq!(
            Wss::peek_sni_and_alpns(&hello),
            Some((
                "example.com".to_owned(),
                vec![b"h2".to_vec(), b"http/1.1".to_vec()]
            ))
        );
        assert!(Wss::peek_sni_and_alpns(&hello[..10]).is_none());
        let hostname = hello
            .windows(b"example.com".len())
            .position(|window| window == b"example.com")
            .unwrap();
        let mut invalid = hello.clone();
        invalid[hostname..hostname + 11].copy_from_slice(b"bad host!xx");
        assert!(Wss::peek_sni_and_alpns(&invalid).is_none());
        let mut ip_address = hello;
        ip_address[hostname..hostname + 11].copy_from_slice(b"192.168.1.1");
        assert!(Wss::peek_sni_and_alpns(&ip_address).is_none());
    }
    #[tokio::test]
    async fn file_certificate_supports_tls_handshake() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};
        use tokio::time::{timeout, Duration};
        timeout(Duration::from_secs(5), async {
            let generated =
                rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
            let pem = format!(
                "{}{}",
                generated.serialize_pem().unwrap(),
                generated.serialize_private_key_pem()
            );
            let certificate =
                super::super::certificate::Certificate::from_pem_vec(pem::parse_many(pem).unwrap())
                    .unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(certificate.get_config());
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = acceptor.accept(stream).await.unwrap();
                stream.write_all(b"ok").await.unwrap();
            });
            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(rustls::pki_types::CertificateDer::from(
                    generated.serialize_der().unwrap(),
                ))
                .unwrap();
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
            let stream = TcpStream::connect(address).await.unwrap();
            let mut stream = connector
                .connect(
                    rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                    stream,
                )
                .await
                .unwrap();
            let mut message = [0; 2];
            stream.read_exact(&mut message).await.unwrap();
            assert_eq!(&message, b"ok");
            server.await.unwrap();
        })
        .await
        .expect("TLS handshake timed out");
    }
}
