use std::{
    net::{SocketAddr, UdpSocket},
    sync::Arc,
};

use async_trait::async_trait;
use quinn::{EndpointConfig, ServerConfig};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{span, trace};

use crate::{error::GatewayError, state::InBound};

use super::{wss::TlsEngine, Service};

#[derive(Clone)]
pub struct QUIC {
    listen_addr: SocketAddr,
    domains: Vec<String>,
    status_sender: UnboundedSender<InBound>,
    cm: TlsEngine,
}

impl QUIC {
    pub fn from(
        ws: &crate::config::QUICService,
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
}
#[async_trait]
impl Service for QUIC {
    async fn run(self) -> Result<(), GatewayError> {
        let span = span!(tracing::Level::TRACE, "quic", listen_addr = %self.listen_addr, domains = ?self.domains);
        let wss = self.clone();
        let tls_engine = self.cm.clone();
        if let TlsEngine::Acme(acme, _) = &tls_engine {
            let _ = acme.clone().get_service_sender().send(
                crate::service::certificate::manager::CertificateServiceMessage::Load(
                    "main".to_owned(),
                    "self".to_owned(),
                    self.domains,
                ),
            );
        }
        span.in_scope(|| trace!("binding listener"));
        // span_connection.in_scope(|| trace!("setting up tls acceptor"));
        // let secure_stream =
        //     TlsAcceptor::from(tls_engine.get_server_config().await)
        //         .accept(tcp_stream)
        //         .instrument(span_connection.clone())
        //         .await
        //         .map_err(|_| ())?;
        let server_config = ServerConfig::with_crypto(tls_engine.get_server_config());

        let endpoint = quinn::Endpoint::new(
            EndpointConfig::default(),
            Some(server_config),
            UdpSocket::bind(self.listen_addr).unwrap(),
            quinn::default_runtime().unwrap(),
        )
        .unwrap();
        dbg!(2);
        while let Some(new_conn) = endpoint.accept().await {
            trace!("New connection being attempted");
            tokio::spawn(async move {
                match new_conn.await {
                    Ok(conn) => {
                        // trace!("Connection established");
                        // let mut h3_conn =
                        //     h3::server::Connection::new(h3_quinn::Connection::new(conn))
                        //         .await
                        //         .unwrap();
                        // loop {
                        //     match h3_conn.accept().await {
                        //         Ok(Some((req, stream))) => {
                        //             let mut body = String::from("Hello, world!");
                        //             let resp = hyper::Response::builder().status(hyper::StatusCode::OK).body(()).unwrap();
                        //             stream.send_response(resp).await.unwrap();
                        //             // response.send_response(&mut body, false).unwrap();
                        //         }
                        //         _ => {
                        //             println!("Error accepting request");
                        //             break;
                        //         }
                        //     }
                        // }
                        // let _ = wss.status_sender.send(InBound::QUIC(conn));
                    }
                    Err(e) => {
                        trace!("Connection failed: {:?}", e);
                    }
                }
            });
        }
        Ok(())
    }
}

// h.insert("Alt-Svc", hyper::header::HeaderValue::from_static("h3=\":443\"; ma=2592000"));
