use std::{net::SocketAddr, sync::Arc};

use crate::{config::TlsConfig, error::GatewayError, state::InBound};

use async_trait::async_trait;
use hyper::server::conn::Http;
use rustls::{internal::msgs::codec::Codec, ServerConfig};
use tokio::{net::TcpListener, sync::mpsc::UnboundedSender};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, instrument, span, trace, warn, Instrument};

use super::{certificate::manager::CertificateManager, http::HttpService, RequestProtocol, Service};

#[derive(Clone)]
pub struct Tls {
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

impl Tls {
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
        let message = rustls::internal::msgs::message::OpaqueMessage::read(
            &mut rustls::internal::msgs::codec::Reader::init(buf),
        )
        .ok()?;
        trace!("buffer successfully parsed into a TLS opaque message");
        let mut r = rustls::internal::msgs::codec::Reader::init(&message.payload.0);
        let _typ = rustls::HandshakeType::read(&mut r).ok()?;
        let len = rustls::internal::msgs::codec::u24::read(&mut r).ok()?.0 as usize;
        let mut sub = r.sub(len).ok()?;
        trace!("reading client hello payload");
        let ch = rustls::internal::msgs::handshake::ClientHelloPayload::read(&mut sub).ok()?;
        trace!("extracting sni from client hello");
        let rustls::internal::msgs::handshake::ServerNamePayload::HostName(ref sni) =
            ch.get_sni_extension()?.first()?.payload
        else {
            return None;
        };
        debug!("sni: {:?}", sni);
        let mut available_alpns = Vec::new();
        trace!("extracting alpns from client hello");
        if let Some(alpns) = ch.get_alpn_extension() {
            for alpn in alpns {
                available_alpns.push(alpn.as_ref().to_vec())
            }
        }
        debug!("alpns: {:?}", available_alpns);
        Some((sni.as_ref().to_string(), available_alpns))
    }
}

#[async_trait]
impl Service for Tls {
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
                let mut buf = vec![0; 1024];
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
                if let Err(http_err) = Http::new()
                    .serve_connection(
                        secure_stream,
                        HttpService {
                            listen_addr: RequestProtocol::Https(self.listen_addr),
                            domains: wss.domains,
                            sni: Some(sni),
                            status_sender: wss.status_sender,
                            peer_addr,
                            cm: None,
                        },
                    )
                    .with_upgrades()
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
