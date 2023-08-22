use std::{net::SocketAddr, sync::Arc};

use crate::{config::TlsConfig, error::GatewayError, state::InBound};

use async_trait::async_trait;
use hyper::server::conn::Http;
use rustls::{internal::msgs::codec::Codec, ServerConfig};
use tokio::{net::TcpListener, sync::mpsc::UnboundedSender};
use tokio_rustls::TlsAcceptor;
use tracing::debug;

use super::{certificate::manager::CertificateManager, ws::WsService, Service};

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
    pub async fn new(conf: TlsConfig) -> Result<Self, GatewayError> {
        match conf {
            TlsConfig::Acme(acme) => {
                debug!("setting up certificate manager");
                let certificate_file_storage = Arc::new(
                    crate::service::certificate::file_storage::CertificateFileStorage::new(
                        "./certificates",
                    ),
                );
                let certificate_manager = CertificateManager::new(
                    certificate_file_storage,
                    Some((acme.email, acme.challenge_type, acme.directory_url)),
                )
                .await?;
                debug!("certificate manager successfully created");
                Ok(Self::Acme(Arc::new(certificate_manager)))
            }
            TlsConfig::File(file) => {
                let cert = super::certificate::Certificate::from_pem_vec(pem::parse_many(
                    tokio::fs::read_to_string(file.cert_path).await?,
                )?)?
                .get_config();
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
    pub fn peek_sni_and_alpns(buf: &[u8]) -> Option<(String, Vec<Vec<u8>>)> {
        let message = rustls::internal::msgs::message::OpaqueMessage::read(
            &mut rustls::internal::msgs::codec::Reader::init(buf),
        )
        .ok()?;
        let mut r = rustls::internal::msgs::codec::Reader::init(&message.payload.0);
        let _typ = rustls::HandshakeType::read(&mut r).ok()?;
        let len = rustls::internal::msgs::codec::u24::read(&mut r).ok()?.0 as usize;
        let mut sub = r.sub(len).ok()?;
        let ch = rustls::internal::msgs::handshake::ClientHelloPayload::read(&mut sub).ok()?;
        let rustls::internal::msgs::handshake::ServerNamePayload::HostName(ref sni) = ch.get_sni_extension()?.first()?.payload else{
            return None;
        };
        let mut available_alpns = Vec::new();
        if let Some(alpns) = ch.get_alpn_extension() {
            for alpn in alpns {
                available_alpns.push(alpn.as_ref().to_vec())
            }
        }
        Some((sni.as_ref().to_string(), available_alpns))
    }
}

#[async_trait]
impl Service for Wss {
    async fn run(self) -> Result<(), GatewayError> {
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

        let tcp_listener = TcpListener::bind(&self.listen_addr).await?;
        loop {
            let Ok((tcp_stream, _addr)) = tcp_listener.accept().await else{
                continue;
            };
            let Ok(peer_addr) = tcp_stream.peer_addr() else {
                continue
            };
            let wss = wss.clone();
            let tls_engine = tls_engine.clone();
            tokio::spawn(async move {
                let mut buf = vec![0; 1024];
                tcp_stream.peek(&mut buf).await.map_err(|_| ())?;
                let Some((sni,alpns)) = Self::peek_sni_and_alpns(&buf) else {
                    return Err::<(), ()>(());
                };

                let Some(server_config) = (match tls_engine {
                    TlsEngine::Acme(acme) => {
                        if acme.acme_type().is_some()
                            && alpns.contains(&super::certificate::ACME_TLS_ALPN_NAME.to_vec())
                        {
                            acme.get_acme_tls_challenge(&sni).await.ok()
                        } else {
                            acme.get(&sni).await.ok()
                        }
                    }
                    TlsEngine::File((domains, acceptor)) => {
                        if domains.contains(&sni) {
                            Some(acceptor)
                        } else {
                            None
                        }
                    }
                }) else {
                    let _ = wss.status_sender.send(InBound::TlsTransparent(sni,tcp_stream,self.listen_addr.port()));
                    return Ok::<(), ()>(());
                };
                let secure_stream = TlsAcceptor::from(server_config)
                    .accept(tcp_stream)
                    .await
                    .map_err(|_| ())?;
                if let Err(_http_err) = Http::new()
                    .serve_connection(
                        secure_stream,
                        WsService {
                            listen_addr: self.listen_addr,
                            domains: wss.domains,
                            sni: Some(sni),
                            status_sender: wss.status_sender,
                            peer_addr,
                            cm: None,
                        },
                    )
                    .with_upgrades()
                    .await
                {
                    debug!("{}", _http_err);
                };
                Ok::<(), ()>(())
            });
        }
    }
}

// pub struct TLSService {
//     pub cm: Arc<CertificateManager>,
// }

// impl TLSService {
//     pub async fn into_stream<IO>(self, io: IO) -> Result<(TlsStream<IO>, String), GatewayError>
//     where
//         IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
//     {
//         let mut alpns = Vec::new(); // todo
//         let ch =
//             tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), io).await?;

//         let Some(sni) = ch
//             .client_hello()
//             .server_name()
//             .map(|d|d.to_owned()) else{
//                 return Err(GatewayError::CertificateNotFound);
//             };

//         if let Some(ch_alpns) = ch.client_hello().alpn() {
//             alpns.append(&mut ch_alpns.collect::<Vec<&[u8]>>());
//         }

//         if self.cm.acme_type().is_some() && alpns.contains(&super::certificate::ACME_TLS_ALPN_NAME)
//         {
//             return Ok((
//                 ch.into_stream(self.cm.get_acme_tls_challenge(&sni).await?)
//                     .await?,
//                 sni,
//             ));
//         }
//         Ok((ch.into_stream(self.cm.get(&sni).await?).await?, sni))
//     }
// }
