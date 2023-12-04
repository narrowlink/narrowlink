use std::net::SocketAddr;

use async_trait::async_trait;

use crate::error::GatewayError;

pub mod certificate;
pub mod http_templates;
pub mod http;
pub mod tls;
pub struct ServiceEventRequest {
    pub(crate) token: String,
    pub(crate) acl: Option<String>,
    pub(crate) publish: Option<String>,
}
pub struct ServiceDataRequest {
    pub(crate) token: String,
    pub(crate) command: Option<String>,
    pub(crate) session: Option<String>,
    pub(crate) connection: Option<String>,
    pub(crate) connecting_address: Option<String>,
}

#[derive(Debug, Clone)]
pub enum RequestProtocol {
    Http(SocketAddr),
    Https(SocketAddr),
}

impl RequestProtocol {
    pub fn get_address(&self) -> SocketAddr {
        match self {
            RequestProtocol::Http(address) => *address,
            RequestProtocol::Https(address) => *address,
        }
    }
}

// pub struct ServiceResponse {
//     session: String,
//     connection: Option<String>,
// }

#[async_trait]
pub trait Service: 'static {
    async fn run(self) -> Result<(), GatewayError>;
}
