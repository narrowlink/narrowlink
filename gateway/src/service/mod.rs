use async_trait::async_trait;

use crate::error::GatewayError;

pub mod certificate;
pub mod http_templates;
pub mod ws;
pub mod wss;
pub mod quic;
pub struct ServiceEventRequest {
    pub(crate) token: String,
    pub(crate) publish: Option<String>,
}
pub struct ServiceDataRequest {
    pub(crate) token: String,
    pub(crate) command: Option<String>,
    pub(crate) session: Option<String>,
    pub(crate) connection: Option<String>,
    pub(crate) connecting_address: Option<String>,
}

// pub struct ServiceResponse {
//     session: String,
//     connection: Option<String>,
// }

#[async_trait]
pub trait Service: 'static {
    async fn run(self) -> Result<(), GatewayError>;
}
