use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tracing::debug;

use crate::{error::NetworkError, AsyncSocket};

pub struct TlsConfiguration {
    pub sni: String,
}
pub enum StreamType {
    Tcp,
    Tls(TlsConfiguration),
}

pub struct UnifiedSocket {
    io: Box<dyn AsyncSocket>,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
}

impl UnifiedSocket {
    pub async fn new(addr: &str, transport_type: StreamType) -> Result<Self, NetworkError> {
        match transport_type {
            StreamType::Tcp | StreamType::Tls(_) => {
                let tcp_stream = TcpStream::connect(addr).await?;
                let local_addr = tcp_stream.local_addr()?;
                let peer_addr = tcp_stream.peer_addr()?;
                let mut stream: Box<dyn AsyncSocket> = Box::new(tcp_stream);
                if let StreamType::Tls(conf) = transport_type {
                    debug!("using rustls to connect to {}", peer_addr.to_string());
                    use std::sync::Arc;
                    use tokio_rustls::{
                        rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore, ServerName},
                        TlsConnector,
                    };

                    let mut root_store = RootCertStore::empty();
                    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
                        OwnedTrustAnchor::from_subject_spki_name_constraints(
                            ta.subject,
                            ta.spki,
                            ta.name_constraints,
                        )
                    }));

                    let config = ClientConfig::builder()
                        .with_safe_default_cipher_suites()
                        .with_safe_default_kx_groups()
                        .with_safe_default_protocol_versions()
                        .or(Err(NetworkError::TlsError))?
                        .with_root_certificates(root_store)
                        .with_no_client_auth();

                    let config = TlsConnector::from(Arc::new(config));

                    let dnsname = ServerName::try_from(conf.sni.as_str()).or(Err(
                        io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"),
                    ))?;
                    stream = Box::new(config.connect(dnsname, stream).await?);
                }

                Ok(Self {
                    io: stream,
                    local_addr,
                    peer_addr,
                })
            }
        }
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}

impl AsyncRead for UnifiedSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl AsyncWrite for UnifiedSocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
