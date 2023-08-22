use std::{collections::HashMap, net::SocketAddr, pin::Pin, sync::Arc, task::Poll};

use async_trait::async_trait;
use either::Either::{Left, Right};
use futures_util::Future;
use hyper::{
    header::{self, HOST},
    http::{self, HeaderValue},
    server::conn::Http,
    service::Service as HyperService,
    upgrade, Body, Request, Response, StatusCode,
};
use tracing::debug;
use tokio::{
    net::TcpListener,
    sync::{mpsc::UnboundedSender, oneshot},
};

use crate::{
    error::GatewayError,
    service::{ServiceDataRequest, ServiceEventRequest},
    state::{InBound, ResponseHeaders},
};

use super::{certificate::manager::CertificateManager, wss::TlsEngine, Service};

#[derive(Clone)]
pub struct Ws {
    listen_addr: SocketAddr,
    domains: Vec<String>,
    status_sender: UnboundedSender<InBound>,
    cm: Option<Arc<CertificateManager>>,
}

impl Ws {
    pub fn from(
        ws: &crate::config::WsService,
        status_sender: UnboundedSender<InBound>,
        tls_engine: Option<TlsEngine>,
    ) -> Self {
        let cm = tls_engine.and_then(|e| match e {
            TlsEngine::Acme(cm) => Some(cm),
            _ => None,
        });
        Self {
            listen_addr: ws.listen_addr,
            domains: ws.domains.to_owned(),
            status_sender,
            cm,
        }
    }
}

#[async_trait]
impl Service for Ws {
    async fn run(self) -> Result<(), GatewayError> {
        let tcp_listener: TcpListener = TcpListener::bind(&self.listen_addr).await?;
        loop {
            let listen_addr = self.listen_addr;
            let Ok((tcp_stream, _addr)) = tcp_listener.accept().await else{
                continue;
            };
            let Ok(peer_addr) = tcp_stream.peer_addr() else{
                continue;
            };
            let ws = self.clone();
            tokio::spawn(async move {
                if let Err(_http_err) = Http::new()
                    .serve_connection(
                        tcp_stream,
                        WsService {
                            listen_addr,
                            domains: ws.domains,
                            sni: None,
                            status_sender: ws.status_sender,
                            peer_addr,
                            cm: ws.cm,
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
//response header
pub struct WsService {
    pub listen_addr: SocketAddr,
    pub domains: Vec<String>,
    pub sni: Option<String>,
    pub status_sender: UnboundedSender<InBound>,
    pub peer_addr: SocketAddr,
    pub cm: Option<Arc<CertificateManager>>,
}

impl HyperService<Request<Body>> for WsService {
    type Response = Response<Body>;
    type Error = http::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let Some(host) = req.uri().host().or(req.headers().get(HOST).and_then(|h|h.to_str().ok())).map(|h|h.to_owned()) else{ //inconsistency:port number
            return Box::pin(async { Ok(crate::service::http_templates::response_error(crate::service::http_templates::ErrorFormat::Html,
                crate::service::http_templates::HttpErrors::BadRequest))
             });
        };
        let tunnel_permit =
            self.domains.iter().any(|domain| domain == &host) || self.domains.is_empty();
        let cm = self.cm.clone().filter(|_| self.sni.is_none());
        let status_sender = self.status_sender.clone();
        let peer_addr = self.peer_addr;
        let listen_addr = self.listen_addr;
        Box::pin(async move {
            let req_version = req.version();
            if let Some(acme) = cm.as_ref() {
                if req.uri().path().starts_with("/.well-known/acme-challenge/") {
                    if let Ok((token, key_authorization)) =
                        acme.get_acme_http_challenge(&host).await
                    {
                        if req.uri().path() == format!("/.well-known/acme-challenge/{}", token) {
                            return Response::builder()
                                .version(req_version)
                                .status(StatusCode::OK)
                                .body::<Body>(key_authorization.into());
                        }
                    }
                }
                // return Response::builder()
                //     .version(req_version)
                //     .status(StatusCode::TEMPORARY_REDIRECT)
                //     .header(
                //         header::LOCATION,
                //         format!("https://{}{}", host, req.uri().path()),
                //     )
                //     .body("".into());
            }

            if let Some(token) = req
                .headers()
                .get("NL-TOKEN")
                .filter(|_| {
                    tunnel_permit
                        && req
                            .headers()
                            .get(header::UPGRADE)
                            .eq(&Some(&header::HeaderValue::from_static("websocket")))
                })
                .and_then(|t| t.to_str().ok())
                .map(|t| t.to_owned())
            {
                let publish = req
                    .headers()
                    .get("NL-PUBLISH")
                    .and_then(|t| t.to_str().ok())
                    .map(|t| t.to_owned());

                let connection = req
                    .headers()
                    .get("NL-CONNECTION")
                    .and_then(|t| t.to_str().ok())
                    .map(|t| t.to_owned());

                let command = req
                    .headers()
                    .get("NL-COMMAND")
                    .and_then(|t| t.to_str().ok())
                    .map(|t| t.to_owned());

                let session = req
                    .headers()
                    .get("NL-SESSION")
                    .and_then(|t| t.to_str().ok())
                    .map(|t| t.to_owned());

                let connecting_address = req
                    .headers()
                    .get("NL-CONNECTING-ADDRESS")
                    .and_then(|t| t.to_str().ok())
                    .map(|t| t.to_owned());

                let forward_address = req
                    .headers()
                    .get("X-FORWARDED-FOR")
                    .and_then(|t| t.to_str().ok())
                    .map(|t| t.to_owned());

                let Some(derived_key) = req
                    .headers()
                    .get(header::SEC_WEBSOCKET_KEY)
                    .map(|t| {
                        narrowlink_network::ws::WsConnection::drive_key(
                            t.as_bytes(),
                        )
                    }) else {
                        return Ok(crate::service::http_templates::response_error(crate::service::http_templates::ErrorFormat::Html,crate::service::http_templates::HttpErrors::BadRequest));
                    };

                let (response_sender, response_receiver) = oneshot::channel();
                let (request, sender) = if command.is_some() ^ connection.is_some() {
                    let (socket_sender, socket_receiver) = oneshot::channel();
                    (
                        InBound::DataRequest(
                            ServiceDataRequest {
                                token,
                                command,
                                session,
                                connection,
                                connecting_address,
                            },
                            socket_receiver,
                            peer_addr,
                            response_sender,
                        ),
                        Left(socket_sender),
                    )
                } else {
                    let (stream_sender, stream_receiver) = oneshot::channel();
                    (
                        InBound::EventRequest(
                            ServiceEventRequest { token, publish },
                            stream_receiver,
                            peer_addr,
                            forward_address,
                            response_sender,
                        ),
                        Right(stream_sender),
                    )
                };

                let _ = status_sender.send(request);

                match response_receiver.await {
                    Ok(Ok(response_headers)) => {
                        tokio::spawn(async move {
                            //any change to control

                            match sender {
                                Left(s) => {
                                    if let Ok(upgraded) = upgrade::on(req).await {
                                        let ws_connection = Box::new(
                                            narrowlink_network::ws::WsConnectionBinary::from(
                                                upgraded,
                                            )
                                            .await
                                            .unwrap(),
                                        );
                                        let _ = s.send(ws_connection);
                                    }
                                }
                                Right(s) => {
                                    if let Ok(upgraded) = upgrade::on(req).await {
                                        let ws_connection = Box::new(
                                            narrowlink_network::ws::WsConnection::from(upgraded)
                                                .await
                                                .unwrap(),
                                        );
                                        let _ = s.send(ws_connection);
                                    }
                                }
                            };
                        });
                        Response::builder()
                            .version(req_version)
                            .status(StatusCode::SWITCHING_PROTOCOLS)
                            .header(header::CONNECTION, "Upgrade")
                            .header(header::UPGRADE, "websocket")
                            .header(header::SEC_WEBSOCKET_ACCEPT, derived_key)
                            .body::<Body>("".into())
                            .map(|mut r| {
                                let headers: HashMap<&str, HeaderValue> = response_headers.into();
                                for (k, v) in headers {
                                    r.headers_mut().append(k, v);
                                }
                                r
                            })
                    }
                    Ok(Err(error)) => Ok(crate::service::http_templates::response_error(
                        crate::service::http_templates::ErrorFormat::Json,
                        error.into(),
                    )),
                    Err(_) => Ok(crate::service::http_templates::response_error(
                        crate::service::http_templates::ErrorFormat::Html,
                        super::http_templates::HttpErrors::InternalServerError,
                    )),
                }
            } else {
                let (response_sender, response_receiver) = oneshot::channel();
                let _ = status_sender.send(InBound::HttpTransparent(
                    host,
                    req,
                    peer_addr,
                    response_sender,
                    listen_addr.port(),
                ));
                match response_receiver.await {
                    Ok(Ok(res)) => Ok(res),
                    Ok(Err(e)) => Ok(crate::service::http_templates::response_error(
                        crate::service::http_templates::ErrorFormat::Html,
                        e.into(),
                    )),
                    Err(_e) => Ok(crate::service::http_templates::response_error(
                        crate::service::http_templates::ErrorFormat::Html,
                        super::http_templates::HttpErrors::ServiceUnavailable,
                    )),
                }
            }
        })
    }
}

impl From<ResponseHeaders> for HashMap<&str, HeaderValue> {
    fn from(value: ResponseHeaders) -> Self {
        let ResponseHeaders {
            session,
            connection,
        } = value;
        let mut map = HashMap::new();
        if let Some(session) = session.and_then(|s| HeaderValue::from_str(&s.to_string()).ok()) {
            map.insert("NL-SESSION", session);
        }
        if let Some(connection) =
            connection.and_then(|c| HeaderValue::from_str(&c.to_string()).ok())
        {
            map.insert("NL-CONNECTION", connection);
        }
        map
    }
}

impl From<crate::state::ResponseErrors> for super::http_templates::HttpErrors {
    fn from(v: crate::state::ResponseErrors) -> Self {
        match v {
            crate::state::ResponseErrors::Unauthorized => {
                super::http_templates::HttpErrors::Unauthorized
            }
            crate::state::ResponseErrors::NotAcceptable(e) => {
                super::http_templates::HttpErrors::NotAcceptable(e)
            }
            crate::state::ResponseErrors::NotFound(e) => {
                super::http_templates::HttpErrors::NotFound(e)
            }
            crate::state::ResponseErrors::Forbidden => super::http_templates::HttpErrors::Forbidden,
        }
    }
}
