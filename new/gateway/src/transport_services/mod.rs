use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};

use tokio::sync::oneshot;

mod tcp;
use crate::error::GatewayError;
use crate::messages::command;
pub use tcp::Tcp;
mod tls;
pub(super) use tls::Tls;
mod http;
pub(super) use http::Http;
mod certificate;
pub use certificate::AcmeService;
pub use certificate::{CertificateFileStorage, CertificateResolver};

pub use self::certificate::{cache::DashMapCache, CertificateIssue};
use self::tls::TlsInfo;

pub(crate) enum TransportStream {
    Command(command::Request, Box<dyn AsyncSocket>, command::Response),
    Data(String, Box<dyn AsyncSocket>, String),
    HttpProxy(
        hyper::Request<hyper::body::Incoming>,
        Arc<SocketInfo>,
        oneshot::Sender<hyper::Response<Full<Bytes>>>,
    ),
    SniProxy(Box<dyn AsyncSocket>),
    Error(GatewayError),
}

pub(crate) trait AsyncSocket:
    AsyncRead + AsyncWrite + Unpin + Send + SocketInfoImpl + 'static
{
}
impl<T> AsyncSocket for T where T: AsyncRead + AsyncWrite + Unpin + Send + SocketInfoImpl + 'static {}

#[derive(Clone)]
pub struct SocketInfo {
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    tls_info: Option<TlsInfo>,
}

impl SocketInfoImpl for Box<dyn AsyncSocket> {
    fn info(&self) -> io::Result<SocketInfo> {
        (**self).info()
    }
}

pub(crate) trait SocketInfoImpl {
    fn info(&self) -> io::Result<SocketInfo>;
}
