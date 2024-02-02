use std::{convert::Infallible, sync::Arc};

use http_body_util::Full;
use hyper::{body::Bytes, service::service_fn, Response};
use hyper_util::rt::{TokioExecutor};

use crate::{transport_services::TransportStream, AsyncSocket};

use super::HTTP;


pub struct H2<S>(S);

impl<S> H2<S>
where
    S: AsyncSocket,
{
    pub fn new(socket: S) -> HTTP<S> {
        let (stream_sender, stream_receiver) =
            tokio::sync::mpsc::unbounded_channel::<TransportStream<S>>();
        let socket_info = Arc::new(socket.info().unwrap());

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
                }),
            )
            // .with_upgrades()
            .await
            .unwrap();
        });
        HTTP {
            receiver: stream_receiver,
            task,
        }
    }
}
