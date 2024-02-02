use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use tokio::sync::oneshot;

use crate::{negotiatation, SocketInfo};
mod tls;
pub(super) use tls::TLS;

mod http;
pub(super) use http::HTTP;
mod certificate;
pub use certificate::CertificateFileStorage;
pub(crate) enum TransportStream<S> {
    Command(negotiatation::Request, S, negotiatation::Response),
    Data(String, S, String),
    HttpProxy(
        hyper::Request<hyper::body::Incoming>,
        Arc<SocketInfo>,
        oneshot::Sender<hyper::Response<Full<Bytes>>>,
    ),
    SniProxy(S),
}
