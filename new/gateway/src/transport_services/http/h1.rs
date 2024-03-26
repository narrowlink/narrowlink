use std::{convert::Infallible, sync::Arc};

use futures::StreamExt;
use http_body_util::Full;
use hyper::{body::Bytes, header, service::service_fn, upgrade, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio_tungstenite::WebSocketStream;

use crate::{
    error::{GatewayError, GatewayNetworkError},
    transport_services::{AsyncSocket, CertificateIssue, TransportStream},
};

use super::{
    error::{response_error, ErrorFormat, HttpErrors},
    Http,
};

static ACME_CHALLENGE_PATH: &str = "/.well-known/acme-challenge/";

impl Http {
    pub fn h1(
        socket: impl AsyncSocket,
        issue: Option<Arc<impl CertificateIssue + Send + Sync + 'static>>,
    ) -> Result<Http, GatewayError> {
        let socket_info = socket
            .info()
            .map(Arc::new)
            .map_err(GatewayNetworkError::InvalidSocket)?;

        let (stream_sender, stream_receiver) =
            tokio::sync::mpsc::unbounded_channel::<TransportStream>();
        let task = tokio::spawn(async move {
            let http = hyper::server::conn::http1::Builder::new();
            http.serve_connection(
                hyper_util::rt::tokio::TokioIo::new(socket),
                service_fn(|req| {
                    let stream_sender = stream_sender.clone();
                    let socket_info = socket_info.clone();
                    let issue = issue.clone();
                    async move {
                        // Obtain the host from the request headers
                        let Some(host) = req
                            .headers()
                            .get(header::HOST)
                            .and_then(|h| h.to_str().ok())
                        else {
                            return Ok(response_error(ErrorFormat::Html, HttpErrors::BadRequest));
                        };
                        // ACME Challenge
                        if let Some(issue) =
                            &issue.filter(|_| req.uri().path().starts_with(ACME_CHALLENGE_PATH))
                        {
                            if let Some((token, key_authorization)) = issue
                                .challenge("main", host)
                                .and_then(|c| c.get_http_challenge())
                            {
                                if req.uri().path() == format!("{ACME_CHALLENGE_PATH}{}", token) {
                                    let response = hyper::Response::new(key_authorization);
                                    let (mut parts, body) = response.into_parts();
                                    parts.status = StatusCode::OK;
                                    parts.headers.insert(
                                        header::CONTENT_TYPE,
                                        header::HeaderValue::from_static("text/plain"),
                                    );
                                    return Ok(hyper::Response::from_parts(parts, body.into()));
                                }
                            }
                        }
                        // WebSocket
                        if let Some(_token) = req
                            .headers()
                            .get("NL-TOKEN")
                            .filter(|_| {
                                req.headers()
                                    .get(header::UPGRADE)
                                    .eq(&Some(&header::HeaderValue::from_static("websocket")))
                            })
                            .and_then(|t| t.to_str().ok())
                            .map(|t| t.to_owned())
                        {
                            let req_version = req.version();
                            let key = req
                                .headers()
                                .get(header::SEC_WEBSOCKET_KEY)
                                .map(|t| tungstenite::handshake::derive_accept_key(t.as_bytes()))
                                .unwrap();
                            tokio::spawn(async {
                                let stream = TokioIo::new(upgrade::on(req).await.unwrap());
                                let ws_stream = WebSocketStream::from_raw_socket(
                                    stream,
                                    tungstenite::protocol::Role::Server,
                                    None,
                                )
                                .await;
                                let (tx, rx) = ws_stream.split();
                                rx.forward(tx).await.unwrap();
                            });

                            Ok(Response::builder()
                                .version(req_version)
                                .status(StatusCode::SWITCHING_PROTOCOLS)
                                .header(header::CONNECTION, "Upgrade")
                                .header(header::UPGRADE, "websocket")
                                .header(header::SEC_WEBSOCKET_ACCEPT, key)
                                .body(Full::new(Bytes::new()))
                                .unwrap())
                        } else {
                            // HTTP - WebSocket Not Found
                            let socket_info = socket_info.clone();
                            let (http_response_sender, http_response_receiver) =
                                tokio::sync::oneshot::channel::<hyper::Response<Full<Bytes>>>();
                            let msg =
                                TransportStream::HttpProxy(req, socket_info, http_response_sender);
                            stream_sender.send(msg).unwrap();
                            Ok::<Response<Full<Bytes>>, Infallible>(
                                http_response_receiver.await.unwrap(),
                            )
                        }
                    }
                }),
            )
            .with_upgrades()
            .await
            .unwrap();
        });
        Ok(Http {
            receiver: stream_receiver,
            task,
        })
    }
}
