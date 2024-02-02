use std::{convert::Infallible, sync::Arc};

use futures::StreamExt;
use http_body_util::Full;
use hyper::{body::Bytes, header, service::service_fn, upgrade, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio_tungstenite::WebSocketStream;

use crate::{transport_services::TransportStream, AsyncSocket};

use super::HTTP;

pub struct H1<S>(S);

impl<S> H1<S>
where
    S: AsyncSocket,
{
    pub fn new(socket: S) -> HTTP<S> {
        let (stream_sender, stream_receiver) =
            tokio::sync::mpsc::unbounded_channel::<TransportStream<S>>();
        let socket_info = Arc::new(socket.info().unwrap());

        let task = tokio::spawn(async move {
            let http = hyper::server::conn::http1::Builder::new();
            http.serve_connection(
                hyper_util::rt::tokio::TokioIo::new(socket),
                service_fn(|req| {
                    let stream_sender = stream_sender.clone();
                    let socket_info = socket_info.clone();
                    async move {
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
                            let msg = TransportStream::<S>::HttpProxy(
                                req,
                                socket_info,
                                http_response_sender,
                            );
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
        HTTP {
            receiver: stream_receiver,
            task,
        }
    }
}
