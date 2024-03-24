use std::{convert::Infallible, sync::Arc};

use http_body_util::Full;
use hyper::{body::Bytes, service::service_fn, Response};
use hyper_util::rt::TokioExecutor;

use crate::{
    error::{GatewayError, GatewayNetworkError},
    transport_services::{AsyncSocket, TransportStream},
};

use super::Http;

impl Http {
    pub fn h2(socket: impl AsyncSocket) -> Result<Http, GatewayError> {
        let socket_info = socket
            .info()
            .map(Arc::new)
            .map_err(GatewayNetworkError::InvalidSocket)?;
        let (stream_sender, stream_receiver) =
            tokio::sync::mpsc::unbounded_channel::<TransportStream>();

        let task = tokio::spawn(async move {
            let http = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
            http.serve_connection(
                hyper_util::rt::tokio::TokioIo::new(socket),
                service_fn(|req| {
                    let stream_sender = stream_sender.clone();
                    let socket_info = socket_info.clone();
                    async move {
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
                }),
            )
            // .with_upgrades()
            .await;
        });
        Ok(Http {
            receiver: stream_receiver,
            task,
        })
    }
}
