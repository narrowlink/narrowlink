use std::{net::SocketAddr, sync::Arc};

use crate::{config::TlsConfig, error::GatewayError, state::InBound};

use async_trait::async_trait;
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
    pub fn peek_sni_and_alpns(buf: &[u8]) -> Option<(String, Vec<Vec<u8>>)> {
        trace!("peeking sni and alpns from client hello");
        if buf.len() < 5 {
            return None;
        }
        // Record header
        if buf[0] != 0x16 {
            return None;
        } // Handshake
        let record_len = ((buf[3] as usize) << 8) | (buf[4] as usize);
        if buf.len() < 5 + record_len {
            return None;
        }

        let mut pos = 5;
        // Handshake header
        if buf[pos] != 0x01 {
            return None;
        } // ClientHello
        let hs_len = ((buf[pos + 1] as usize) << 16)
            | ((buf[pos + 2] as usize) << 8)
            | (buf[pos + 3] as usize);
        if record_len < 4 + hs_len {
            return None;
        }
        pos += 4;

        if pos + 35 > buf.len() {
            return None;
        }
        pos += 2; // Version
        pos += 32; // Random

        // Session ID
        let sid_len = buf[pos] as usize;
        pos += 1 + sid_len;
        if pos + 2 > buf.len() {
            return None;
        }

        // Cipher Suites
        let cs_len = ((buf[pos] as usize) << 8) | (buf[pos + 1] as usize);
        pos += 2 + cs_len;
        if pos + 1 > buf.len() {
            return None;
        }

        // Compression Methods
        let cm_len = buf[pos] as usize;
        pos += 1 + cm_len;
        if pos + 2 > buf.len() {
            return None;
        } // no extensions

        // Extensions
        let ext_len = ((buf[pos] as usize) << 8) | (buf[pos + 1] as usize);
        pos += 2;
        let ext_end = pos + ext_len;
        if ext_end > buf.len() {
            return None;
        }

        let mut sni = None;
        let mut alpns = Vec::new();

        while pos + 4 <= ext_end {
            let e_type = ((buf[pos] as usize) << 8) | (buf[pos + 1] as usize);
            let e_len = ((buf[pos + 2] as usize) << 8) | (buf[pos + 3] as usize);
            pos += 4;
            if pos + e_len > ext_end {
                break;
            }

            if e_type == 0x0000 {
                // SNI
                let mut p = pos;
                if p + 2 <= pos + e_len {
                    let _sni_list_len = ((buf[p] as usize) << 8) | (buf[p + 1] as usize);
                    p += 2;
                    while p + 3 <= pos + e_len {
                        let name_type = buf[p];
                        let name_len = ((buf[p + 1] as usize) << 8) | (buf[p + 2] as usize);
                        p += 3;
                        if p + name_len <= pos + e_len && name_type == 0 {
                            // host_name
                            if let Ok(s) = std::str::from_utf8(&buf[p..p + name_len]) {
                                sni = Some(s.to_string());
                            }
                        }
                        p += name_len;
                    }
                }
            } else if e_type == 0x0010 {
                // ALPN
                let mut p = pos;
                if p + 2 <= pos + e_len {
                    let _alpn_list_len = ((buf[p] as usize) << 8) | (buf[p + 1] as usize);
                    p += 2;
                    while p < pos + e_len {
                        let name_len = buf[p] as usize;
                        p += 1;
                        if p + name_len <= pos + e_len {
                            alpns.push(buf[p..p + name_len].to_vec());
                        }
                        p += name_len;
                    }
                }
            }

            pos += e_len;
        }

        sni.map(|s| (s, alpns))
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
                let n = tcp_stream
                    .peek(&mut buf)
                    .instrument(span_connection.clone())
                    .await
                    .map_err(|_| {
                        span_connection.in_scope(|| trace!("failed to peek client hello"));
                    })?;

                let Some((sni, alpns)) =
                    span_connection.in_scope(|| Self::peek_sni_and_alpns(&buf[..n]))
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
                let ws_service = WsService {
                    listen_addr: RequestProtocol::Https(self.listen_addr),
                    domains: wss.domains.clone(),
                    sni: Some(sni),
                    status_sender: wss.status_sender.clone(),
                    peer_addr,
                    cm: None,
                };
                if let Err(http_err) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        hyper_util::rt::TokioIo::new(secure_stream),
                        hyper::service::service_fn(move |req| {
                            let mut ws_service = ws_service.clone();
                            async move {
                                Ok::<_, std::convert::Infallible>(ws_service.handle(req).await)
                            }
                        }),
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
