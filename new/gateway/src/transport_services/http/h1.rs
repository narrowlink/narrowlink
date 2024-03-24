use std::{convert::Infallible, sync::Arc};

use futures::StreamExt;
use http_body_util::Full;
use hyper::{body::Bytes, header, service::service_fn, upgrade, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio_tungstenite::WebSocketStream;

use crate::{
    error::{GatewayError, NetworkError},
    transport_services::{CertificateIssue, TransportStream},
    AsyncSocket,
};

use super::Http;

impl Http {
    pub fn h1(
        socket: impl AsyncSocket,
        issue: Option<Arc<impl CertificateIssue + Send + Sync + 'static>>,
    ) -> Result<Http, GatewayError> {
        let socket_info = socket
            .info()
            .map(Arc::new)
            .map_err(NetworkError::InvalidSocket)?;

        let (stream_sender, stream_receiver) =
            tokio::sync::mpsc::unbounded_channel::<TransportStream>();
        let task = tokio::spawn(async move {
            let http = hyper::server::conn::http1::Builder::new();
            http.serve_connection(
                hyper_util::rt::tokio::TokioIo::new(socket),
                service_fn(|req| {
                    let stream_sender = stream_sender.clone();
                    let socket_info = socket_info.clone();
                    let issue = issue
                        .clone()
                        .filter(|_| req.uri().path().starts_with("/.well-known/acme-challenge"));

                    async move {
                        let host = req
                            .headers()
                            .get(header::HOST)
                            .and_then(|h| h.to_str().ok());
                        if let Some(issue) = &issue {
                            if let Some((token, key_authorization)) = issue
                                .challenge("main", host.unwrap())
                                .and_then(|c| c.get_http_challenge())
                            {
                                if req.uri().path()
                                    == format!("/.well-known/acme-challenge/{}", token)
                                {
                                    return Ok(Response::builder()
                                        .status(StatusCode::OK)
                                        .header(header::CONTENT_TYPE, "text/plain")
                                        .body(Full::new(Bytes::from(key_authorization)))
                                        .unwrap());
                                }
                            }
                        }

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
                            // let ws_stream = WebSocketStream::from_raw_socket(
                            //     Box::new(server_stream) as Box<dyn AsyncSocket>,
                            //     tungstenite::protocol::Role::Server,
                            //     None,
                            // )
                            // .await;
                            Ok(Response::builder()
                                .version(req_version)
                                .status(StatusCode::SWITCHING_PROTOCOLS)
                                .header(header::CONNECTION, "Upgrade")
                                .header(header::UPGRADE, "websocket")
                                .header(header::SEC_WEBSOCKET_ACCEPT, key)
                                .body(Full::new(Bytes::new()))
                                .unwrap())
                        } else {
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
        //         println!("Hello, world!");
        //     }
        // }
        // todo!()
        Ok(Http {
            receiver: stream_receiver,
            task,
        })
    }
}
