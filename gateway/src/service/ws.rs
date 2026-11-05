use std::{collections::HashMap, net::SocketAddr, pin::Pin, sync::Arc};

use crate::HttpBody;
use async_trait::async_trait;
use either::Either::{Left, Right};
use futures_util::Future;
use hyper::{
    Request, Response, StatusCode,
    header::{self, HOST},
    http::{self, HeaderValue},
    service::Service as HyperService,
    upgrade,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use tokio::{
    net::TcpListener,
    sync::{mpsc::UnboundedSender, oneshot},
};
use tracing::{Instrument, debug, span, trace, warn};

use crate::{
    error::GatewayError,
    service::{ServiceDataRequest, ServiceEventRequest},
    state::{InBound, ResponseHeaders},
};

use super::{RequestProtocol, Service, certificate::manager::CertificateManager, wss::TlsEngine};

const INDEX_HTML: &str = include_str!("../../templates/index.html");

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
        let span = span!(tracing::Level::TRACE, "ws", listen_addr = %self.listen_addr, domains = ?self.domains);
        let tcp_listener: TcpListener = TcpListener::bind(&self.listen_addr).await?;
        span.in_scope(|| trace!("tcp listener successfully bound"));
        loop {
            let listen_addr = self.listen_addr;
            let Ok((tcp_stream, peer_addr)) = tcp_listener.accept().await else {
                span.in_scope(|| warn!("failed to accept tcp connection"));
                continue;
            };
            let span_connection = span
                .in_scope(|| span!(tracing::Level::TRACE, "connection", peer_addr = %peer_addr));

            span_connection.in_scope(|| debug!("new connection from {}", peer_addr));
            let ws = self.clone();
            let span_connection = span_connection.clone();
            tokio::spawn(async move {
                if let Err(http_err) = Builder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(
                        TokioIo::new(tcp_stream),
                        WsService {
                            listen_addr: RequestProtocol::Http(listen_addr),
                            domains: ws.domains,
                            sni: None,
                            status_sender: ws.status_sender,
                            peer_addr,
                            cm: ws.cm,
                        },
                    )
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

//response header
pub struct WsService {
    pub listen_addr: RequestProtocol,
    pub domains: Vec<String>,
    pub sni: Option<String>,
    pub status_sender: UnboundedSender<InBound>,
    pub peer_addr: SocketAddr,
    pub cm: Option<Arc<CertificateManager>>,
}

impl HyperService<Request<hyper::body::Incoming>> for WsService {
    type Response = Response<HttpBody>;
    type Error = http::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<hyper::body::Incoming>) -> Self::Future {
        let span = span!(tracing::Level::INFO, "service", peer_addr = %self.peer_addr);
        span.in_scope(|| debug!("request: {:?}", req));
        let Some(host) = req
            .uri()
            .host()
            .or(req.headers().get(HOST).and_then(|h| h.to_str().ok()))
            .map(|h| h.to_owned())
        else {
            //inconsistency:port number
            return Box::pin(async {
                Ok(crate::service::http_templates::response_error(
                    crate::service::http_templates::ErrorFormat::Html,
                    crate::service::http_templates::HttpErrors::BadRequest,
                ))
            });
        };

        span.record("host", &host);
        span.in_scope(|| trace!("host: {}", host));
        let tunnel_permit =
            self.domains.iter().any(|domain| domain == &host) || self.domains.is_empty();
        span.in_scope(|| debug!("tunnel permission: {}", tunnel_permit));
        let cm = self.cm.clone().filter(|_| self.sni.is_none());
        let status_sender = self.status_sender.clone();
        let peer_addr = self.peer_addr;
        let listen_addr = self.listen_addr.clone();

        let handler = async move {
            let req_version = req.version();
            if let Some(acme) = cm.as_ref()
                && req.uri().path().starts_with("/.well-known/acme-challenge/")
            {
                trace!("acme challenge");
                if let Ok((token, key_authorization)) =
                    acme.get_acme_http_challenge(&host).in_current_span().await
                {
                    if req.uri().path() == format!("/.well-known/acme-challenge/{}", token) {
                        return Response::builder()
                            .version(req_version)
                            .status(StatusCode::OK)
                            .body(crate::full_body(key_authorization));
                    }
                } else {
                    trace!("acme challenge not found for {}", host);
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
                debug!("narrowlink token found: {}", token);
                let Some(derived_key) = req
                    .headers()
                    .get(header::SEC_WEBSOCKET_KEY)
                    .map(|t| narrowlink_network::ws::WsConnection::drive_key(t.as_bytes()))
                else {
                    trace!("invalid websocket key or key header not found");
                    use crate::service::http_templates::{ErrorFormat, HttpErrors, response_error};
                    return Ok(response_error(ErrorFormat::Html, HttpErrors::BadRequest));
                };
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
                let acl = req
                    .headers()
                    .get("NL-ACL")
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

                let (response_sender, response_receiver) = oneshot::channel();
                let (request, sender) = if command.is_some() ^ connection.is_some() {
                    trace!("data request found");
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
                            forward_address,
                            response_sender,
                        ),
                        Left(socket_sender),
                    )
                } else {
                    trace!("event request found");
                    let (stream_sender, stream_receiver) = oneshot::channel();
                    (
                        InBound::EventRequest(
                            ServiceEventRequest {
                                token,
                                acl,
                                publish,
                            },
                            stream_receiver,
                            peer_addr,
                            forward_address,
                            response_sender,
                        ),
                        Right(stream_sender),
                    )
                };

                let _ = status_sender.send(request);
                trace!("request sent and waiting for response");
                match response_receiver.await {
                    Ok(Ok(response_headers)) => {
                        trace!("response received");
                        tokio::spawn(
                            async move {
                                //any change to control
                                match sender {
                                    Left(s) => {
                                        trace!("upgrading to websocket data channel");
                                        if let Ok(upgraded) = upgrade::on(req).await {
                                            let ws_connection = Box::new(
                                                narrowlink_network::ws::WsConnectionBinary::from(
                                                    TokioIo::new(upgraded),
                                                )
                                                .await,
                                            );
                                            let _ = s.send(ws_connection);
                                        }
                                    }
                                    Right(s) => {
                                        trace!("upgrading to websocket event channel");
                                        if let Ok(upgraded) = upgrade::on(req).await {
                                            let ws_connection = Box::new(
                                                narrowlink_network::ws::WsConnection::from(
                                                    TokioIo::new(upgraded),
                                                )
                                                .await,
                                            );
                                            let _ = s.send(ws_connection);
                                        }
                                    }
                                };
                            }
                            .in_current_span(),
                        );
                        trace!("websocket connection established");
                        Response::builder()
                            .version(req_version)
                            .status(StatusCode::SWITCHING_PROTOCOLS)
                            .header(header::CONNECTION, "Upgrade")
                            .header(header::UPGRADE, "websocket")
                            .header(header::SEC_WEBSOCKET_ACCEPT, derived_key)
                            .body(crate::full_body(""))
                            .map(|mut r| {
                                let headers: HashMap<&str, HeaderValue> = response_headers.into();
                                for (k, v) in headers {
                                    r.headers_mut().append(k, v);
                                }
                                r
                            })
                    }
                    Ok(Err(error)) => {
                        debug!("an expected response error received: {:?}", error);
                        Ok(crate::service::http_templates::response_error(
                            crate::service::http_templates::ErrorFormat::Json,
                            error.into(),
                        ))
                    }
                    Err(e) => {
                        debug!("unexpected response error: {}", e);
                        Ok(crate::service::http_templates::response_error(
                            crate::service::http_templates::ErrorFormat::Html,
                            super::http_templates::HttpErrors::InternalServerError,
                        ))
                    }
                }
            } else {
                let is_homepage = req.uri().path().eq("/");
                let (response_sender, response_receiver) = oneshot::channel();
                let _ = status_sender.send(InBound::HttpTransparent(
                    host,
                    req,
                    peer_addr,
                    response_sender,
                    listen_addr,
                ));
                trace!("http transparent request found and sent and waiting for response");
                match response_receiver.await {
                    Ok(Ok(res)) => {
                        trace!("response received");
                        Ok(res)
                    }
                    Ok(Err(e)) => {
                        if matches!(e, crate::state::ResponseErrors::NotFound(_)) && is_homepage {
                            return Response::builder()
                                .version(req_version)
                                .status(StatusCode::OK)
                                .body(crate::full_body(INDEX_HTML));
                        }
                        debug!("an expected response error received: {:?}", e);
                        Ok(crate::service::http_templates::response_error(
                            crate::service::http_templates::ErrorFormat::Html,
                            e.into(),
                        ))
                    }
                    Err(e) => {
                        trace!("unexpected response error: {:?}", e);
                        Ok(crate::service::http_templates::response_error(
                            crate::service::http_templates::ErrorFormat::Html,
                            super::http_templates::HttpErrors::ServiceUnavailable,
                        ))
                    }
                }
            }
        }
        .instrument(span);
        Box::pin(handler)
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use narrowlink_types::ServiceType;
    use tokio::{
        net::TcpListener,
        sync::mpsc,
        time::{Duration, timeout},
    };

    #[tokio::test]
    async fn websocket_upgrade_exchanges_messages() {
        timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (sender, mut receiver) = mpsc::unbounded_channel();
            let server = tokio::spawn(async move {
                let (socket, peer_addr) = listener.accept().await.unwrap();
                let service = WsService {
                    listen_addr: RequestProtocol::Http(addr),
                    domains: Vec::new(),
                    sni: None,
                    status_sender: sender,
                    peer_addr,
                    cm: None,
                };
                Builder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(TokioIo::new(socket), service)
                    .await
                    .unwrap();
            });
            let handler = tokio::spawn(async move {
                if let Some(InBound::EventRequest(_, stream, _, _, response)) =
                    receiver.recv().await
                {
                    assert!(
                        response
                            .send(Ok(ResponseHeaders {
                                session: None,
                                connection: None
                            }))
                            .is_ok()
                    );
                    let mut stream = stream.await.unwrap();
                    assert_eq!(stream.next().await.unwrap().unwrap(), "ping");
                    stream.send("pong".to_owned()).await.unwrap();
                } else {
                    panic!("expected event request");
                }
            });
            let headers = HashMap::from([("NL-TOKEN", "test".to_owned())]);
            let mut client = narrowlink_network::ws::WsConnection::new(
                &addr.to_string(),
                &headers,
                &ServiceType::Ws,
            )
            .await
            .unwrap();
            client.send("ping".to_owned()).await.unwrap();
            assert_eq!(client.next().await.unwrap().unwrap(), "pong");
            handler.await.unwrap();
            server.await.unwrap();
        })
        .await
        .expect("websocket exchange timed out");
    }
    #[tokio::test]
    async fn forwards_http_request_and_response_body() {
        use http_body_util::BodyExt;
        timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (sender, mut receiver) = mpsc::unbounded_channel();
            tokio::spawn(async move {
                let (socket, peer_addr) = listener.accept().await.unwrap();
                let service = WsService {
                    listen_addr: RequestProtocol::Http(addr),
                    domains: Vec::new(),
                    sni: None,
                    status_sender: sender,
                    peer_addr,
                    cm: None,
                };
                Builder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(TokioIo::new(socket), service)
                    .await
                    .unwrap();
            });
            let handler = tokio::spawn(async move {
                if let Some(InBound::HttpTransparent(host, request, _, response, _)) =
                    receiver.recv().await
                {
                    assert_eq!(host, "example.com");
                    assert_eq!(request.uri().path(), "/resource");
                    assert_eq!(
                        request.into_body().collect().await.unwrap().to_bytes(),
                        "request body"
                    );
                    assert!(
                        response
                            .send(Ok(Response::new(crate::full_body("response body"))))
                            .is_ok()
                    );
                } else {
                    panic!("expected HTTP request");
                }
            });
            let socket = tokio::net::TcpStream::connect(addr).await.unwrap();
            let (mut client, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(socket))
                    .await
                    .unwrap();
            tokio::spawn(async move {
                connection.await.unwrap();
            });
            let request = Request::builder()
                .method("POST")
                .uri("/resource")
                .header("Host", "example.com")
                .body(http_body_util::Full::new(bytes::Bytes::from_static(
                    b"request body",
                )))
                .unwrap();
            let response = client.send_request(request).await.unwrap();
            assert_eq!(
                response.into_body().collect().await.unwrap().to_bytes(),
                "response body"
            );
            handler.await.unwrap();
        })
        .await
        .expect("HTTP exchange timed out");
    }
    #[tokio::test]
    async fn http2_forwards_request_and_response() {
        use http_body_util::BodyExt;
        timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (sender, mut receiver) = mpsc::unbounded_channel();
            let server = tokio::spawn(async move {
                let (socket, peer_addr) = listener.accept().await.unwrap();
                let service = WsService {
                    listen_addr: RequestProtocol::Http(addr),
                    domains: Vec::new(),
                    sni: None,
                    status_sender: sender,
                    peer_addr,
                    cm: None,
                };
                Builder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(TokioIo::new(socket), service)
                    .await
                    .unwrap();
            });
            let handler = tokio::spawn(async move {
                if let Some(InBound::HttpTransparent(host, request, _, response, _)) =
                    receiver.recv().await
                {
                    assert_eq!(host, "example.com");
                    assert_eq!(request.version(), hyper::Version::HTTP_2);
                    assert_eq!(request.uri().path(), "/resource");
                    assert_eq!(
                        request.into_body().collect().await.unwrap().to_bytes(),
                        "request body"
                    );
                    assert!(
                        response
                            .send(Ok(Response::new(crate::full_body("response body"))))
                            .is_ok()
                    );
                } else {
                    panic!("expected HTTP request");
                }
            });
            let socket = tokio::net::TcpStream::connect(addr).await.unwrap();
            let (mut client, connection) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(socket))
                    .await
                    .unwrap();
            let driver = tokio::spawn(connection);
            let request = Request::builder()
                .method("POST")
                .uri("http://example.com/resource")
                .body(http_body_util::Full::new(bytes::Bytes::from_static(
                    b"request body",
                )))
                .unwrap();
            let response = client.send_request(request).await.unwrap();
            assert_eq!(response.version(), hyper::Version::HTTP_2);
            assert_eq!(
                response.into_body().collect().await.unwrap().to_bytes(),
                "response body"
            );
            handler.await.unwrap();
            drop(client);
            driver.await.unwrap().unwrap();
            server.await.unwrap();
        })
        .await
        .expect("HTTP/2 exchange timed out");
    }
    #[tokio::test]
    async fn transparent_http_proxy_forwards_to_agent() {
        use crate::state::{
            ClientConnection, ConnectionData, TestAgentConnection as AgentConnection,
        };
        use http_body_util::BodyExt;
        timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (sender, mut receiver) = mpsc::unbounded_channel();
            tokio::spawn(async move {
                let (socket, peer_addr) = listener.accept().await.unwrap();
                let service = WsService {
                    listen_addr: RequestProtocol::Http(addr),
                    domains: Vec::new(),
                    sni: None,
                    status_sender: sender,
                    peer_addr,
                    cm: None,
                };
                Builder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(TokioIo::new(socket), service)
                    .await
                    .unwrap();
            });
            let router = tokio::spawn(async move {
                let Some(InBound::HttpTransparent(_, request, peer, response, protocol)) =
                    receiver.recv().await
                else {
                    panic!("expected HTTP request");
                };
                let (agent_side, origin_side) = tokio::io::duplex(65536);
                let origin = tokio::spawn(async move {
                    let service = hyper::service::service_fn(
                        |request: Request<hyper::body::Incoming>| async move {
                            assert_eq!(
                                request.uri().path_and_query().unwrap().as_str(),
                                "/resource?a=1"
                            );
                            assert_eq!(request.headers().get("host").unwrap(), "example.com");
                            assert_eq!(request.headers().get("x-forwarded-proto").unwrap(), "http");
                            assert_eq!(
                                request.into_body().collect().await.unwrap().to_bytes(),
                                "request body"
                            );
                            Ok::<_, std::convert::Infallible>(Response::new(crate::full_body(
                                "origin body",
                            )))
                        },
                    );
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(origin_side), service)
                        .await
                        .unwrap();
                });
                let (agent_tx, agent_rx) = oneshot::channel();
                assert!(
                    agent_tx
                        .send(Box::new(narrowlink_network::AsyncToStream::new(agent_side))
                            as Box<
                                dyn narrowlink_network::UniversalStream<
                                        Vec<u8>,
                                        narrowlink_network::error::NetworkError,
                                    >,
                            >)
                        .is_ok()
                );
                let mut connection = ConnectionData::new(
                    uuid::Uuid::new_v4(),
                    None,
                    Some(ClientConnection::HttpTransparent(
                        Box::new(request),
                        peer,
                        response,
                        protocol,
                    )),
                    Some(AgentConnection::Agent(None, agent_rx)),
                );
                connection.serve().await.unwrap();
                origin.await.unwrap();
            });
            let socket = tokio::net::TcpStream::connect(addr).await.unwrap();
            let (mut client, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(socket))
                    .await
                    .unwrap();
            tokio::spawn(async move {
                let _ = connection.await;
            });
            let request = Request::builder()
                .method("POST")
                .uri("/resource?a=1")
                .header("Host", "example.com")
                .body(http_body_util::Full::new(bytes::Bytes::from_static(
                    b"request body",
                )))
                .unwrap();
            let response = client.send_request(request).await.unwrap();
            assert_eq!(
                response.into_body().collect().await.unwrap().to_bytes(),
                "origin body"
            );
            router.await.unwrap();
        })
        .await
        .expect("proxy exchange timed out");
    }
}
