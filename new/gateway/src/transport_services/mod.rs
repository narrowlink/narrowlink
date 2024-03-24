use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use tokio::sync::oneshot;
mod tcp;
use crate::error::GatewayError;
use crate::{negotiatation, AsyncSocket, SocketInfo};
pub use tcp::Tcp;
mod tls;
pub(super) use tls::Tls;
mod http;
pub(super) use http::Http;
mod certificate;
pub use certificate::{CertificateFileStorage,CertificateResolver,DashMapCache};
pub use certificate::AcmeService;

pub use self::certificate::CertificateIssue;

pub(crate) enum TransportStream {
    Command(
        negotiatation::Request,
        Box<dyn AsyncSocket>,
        negotiatation::Response,
    ),
    Data(String, Box<dyn AsyncSocket>, String),
    HttpProxy(
        hyper::Request<hyper::body::Incoming>,
        Arc<SocketInfo>,
        oneshot::Sender<hyper::Response<Full<Bytes>>>,
    ),
    SniProxy(Box<dyn AsyncSocket>),
    Error(GatewayError),
}
