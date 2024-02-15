use std::net::SocketAddr;

use hyper::{client::conn, http::HeaderValue, Body, Request, Response};
use narrowlink_network::{error::NetworkError, UniversalStream};
// use narrowlink_types::policy::Policy;
use tokio::{net::TcpStream, sync::oneshot};
use tracing::{debug, Instrument};
use uuid::Uuid;

use crate::{error::GatewayError, service::RequestProtocol};

use super::{ResponseErrors, ResponseHeaders};

// #[derive(Debug)]
pub struct Connection {
    pub id: Uuid,
    pub session_id: Option<Uuid>,
    pub data: ConnectionData,
    // pub policies: Vec<Policy>,
}

// #[derive(Debug)]
pub enum ClientConnection {
    HttpTransparent(
        Request<Body>,
        SocketAddr,
        oneshot::Sender<Result<Response<Body>, ResponseErrors>>,
        RequestProtocol,
    ),
    TlsTransparent(TcpStream),
    Client(
        Option<oneshot::Sender<Result<ResponseHeaders, ResponseErrors>>>,
        oneshot::Receiver<Box<dyn UniversalStream<Vec<u8>, NetworkError>>>,
    ),
}

pub enum AgentConnection {
    Agent(
        Option<oneshot::Sender<Result<ResponseHeaders, ResponseErrors>>>,
        oneshot::Receiver<Box<dyn UniversalStream<Vec<u8>, NetworkError>>>,
    ),
}

impl Connection {
    pub fn new(
        id: Uuid,
        session_id: Option<Uuid>,
        client_socket: Option<ClientConnection>,
        agent_socket: Option<AgentConnection>,
        // policies: Vec<Policy>,
    ) -> Self {
        Self {
            id,
            session_id,
            data: ConnectionData::new(id, session_id, client_socket, agent_socket),
            // policies,
        }
    }

    pub fn set_agent_socket(&mut self, socket: AgentConnection) {
        self.data.agent_socket = Some(socket);
    }
    // pub fn take_client_socket(
    //     &mut self,
    // ) -> Option<oneshot::Sender<Result<ResponseHeaders, ResponseErrors>>> {
    //     if let Some(ClientConnection::Client(res, _stream)) = self.data.client_socket.take() {
    //         return res;
    //     }
    //     None
    // }
    pub fn get_id(&self) -> Uuid {
        self.id
    }
    // pub fn take_policy(&mut self) -> Vec<Policy> {
    //     self.policies.clone()
    // }
}

// #[derive(Debug)]
pub struct ConnectionData {
    pub id: Uuid,
    pub session_id: Option<Uuid>,
    pub client_socket: Option<ClientConnection>,
    pub agent_socket: Option<AgentConnection>,
}

impl ConnectionData {
    pub fn new(
        id: Uuid,
        session_id: Option<Uuid>,
        client_socket: Option<ClientConnection>,
        agent_socket: Option<AgentConnection>,
    ) -> Self {
        Self {
            id,
            session_id,
            client_socket,
            agent_socket,
        }
    }
    #[tracing::instrument(name = "connection_serve", skip(self))]
    pub async fn serve(&mut self) -> Result<(), GatewayError> {
        let (Some(client_connection), Some(agent_connection)) =
            (self.client_socket.take(), self.agent_socket.take())
        else {
            return Err(GatewayError::Other("No client or agent socket found"));
        };
        let AgentConnection::Agent(agent_response, agent_socket_receiver) = agent_connection;
        match client_connection {
            ClientConnection::Client(client_response, client_socket_receiver) => {
                if client_response
                    .and_then(|res| {
                        res.send(Ok(ResponseHeaders {
                            session: self.session_id,
                            connection: Some(self.id),
                        }))
                        .ok()
                    })
                    .is_none()
                {};
                if agent_response
                    .and_then(|res| {
                        res.send(Ok(ResponseHeaders {
                            session: self.session_id,
                            connection: Some(self.id),
                        }))
                        .ok()
                    })
                    .is_none()
                {};

                let client_socket = client_socket_receiver
                    .await
                    .map_err(|_| GatewayError::Other("Client Connection gone"))?;
                let agent_socket = agent_socket_receiver
                    .await
                    .map_err(|_| GatewayError::Other("Agent Connection gone"))?;
                narrowlink_network::stream_forward(client_socket, agent_socket)
                    .await
                    .map_err(|e| e.into())
            }
            ClientConnection::TlsTransparent(tcp_stream) => {
                if agent_response
                    .and_then(|res| {
                        res.send(Ok(ResponseHeaders {
                            session: self.session_id,
                            connection: Some(self.id),
                        }))
                        .ok()
                    })
                    .is_none()
                {};

                let agent_socket = agent_socket_receiver
                    .await
                    .map_err(|_| GatewayError::Other("Agent Connection gone"))?;
                narrowlink_network::stream_forward(
                    narrowlink_network::AsyncToStream::new(tcp_stream),
                    agent_socket,
                )
                .await
                .map_err(|e| e.into())
            }
            ClientConnection::HttpTransparent(mut request, peer_addr, replay, service_protocol) => {
                let agent_stream = agent_socket_receiver
                    .await
                    .map_err(|_| GatewayError::Other("Agent Connection gone"))?;
                let agent_socket = narrowlink_network::StreamToAsync::new(agent_stream);
                let (mut request_sender, connection) = conn::handshake(agent_socket).await?;
                tokio::spawn(
                    async move {
                        if let Err(e) = connection.await {
                            debug!("Error in connection: {}", e);
                        }
                    }
                    .in_current_span(),
                );
                let original_version = request.version();
                if let Some(host) = request
                    .uri()
                    .host()
                    .or(request.headers().get("Host").and_then(|h| h.to_str().ok()))
                    .and_then(|h| {
                        request
                            .uri()
                            .port()
                            .map(|p| [h, p.as_str()].join(":"))
                            .or(Some(h.to_owned()))
                    })
                    .and_then(|h| HeaderValue::from_str(&h).ok())
                {
                    let mut parts = request.uri().clone().into_parts();
                    parts.authority = None;
                    parts.scheme = None;
                    if let Ok(uri) = hyper::http::uri::Uri::from_parts(parts) {
                        *request.version_mut() = hyper::Version::HTTP_11;
                        if let Ok(peer_addr) = peer_addr.to_string().parse() {
                            request.headers_mut().insert("NL-Connecting-IP", peer_addr);
                        };
                        if request.headers().contains_key("Cookie")
                            && original_version == hyper::Version::HTTP_2
                        {
                            let cookies =
                                request.headers().iter().fold(String::new(), |acc, (k, v)| {
                                    if k == "Cookie" {
                                        if acc.is_empty() {
                                            v.to_str().unwrap_or("").to_owned()
                                        } else {
                                            format!("{}; {}", acc, v.to_str().unwrap_or(""))
                                        }
                                    } else {
                                        acc
                                    }
                                });
                            if let Ok(cookies) = HeaderValue::from_str(&cookies) {
                                request.headers_mut().insert("Cookie", cookies);
                            }
                        }
                        request.headers_mut().insert(
                            "X-Forwarded-Proto",
                            match service_protocol {
                                RequestProtocol::Http(_) => HeaderValue::from_static("http"),
                                RequestProtocol::Https(_) => HeaderValue::from_static("https"),
                            },
                        );

                        *request.uri_mut() = uri;
                        request
                            .headers_mut()
                            .insert(hyper::http::header::HOST, host);
                    }
                }
                request_sender
                    .send_request(request)
                    .await
                    .map_err(|_| ())
                    .and_then(|mut response| {
                        *response.version_mut() = original_version;
                        replay.send(Ok(response)).map_err(|_| ())
                    })
                    .map_err(|_| GatewayError::Other("Connection gone"))
            }
        }
    }
}
