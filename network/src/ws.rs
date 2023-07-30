use bytes::{BufMut, BytesMut};
use futures_util::{Future, FutureExt, SinkExt, StreamExt};
use hyper::{client::conn, http::HeaderValue, Body, HeaderMap, Request, StatusCode};
use log::{debug, trace, warn};
use narrowlink_types::ServiceType;
use std::{
    collections::HashMap,
    io::{self, Error, ErrorKind},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    task::JoinHandle,
};
use tokio_tungstenite::WebSocketStream;
use tungstenite::Message;

use crate::{
    error::NetworkError,
    transport::{StreamType, TlsConfiguration, UnifiedSocket},
    AsyncSocket,
};

const KEEP_ALIVE_TIME: u64 = 20;

pub enum WsMode {
    Server(tokio::time::Interval),
    Client(HeaderMap, JoinHandle<()>),
}

pub struct WsConnection {
    ws_stream: WebSocketStream<Box<dyn AsyncSocket>>,
    remaining_bytes: Option<BytesMut>,
    mode: WsMode,
}

impl WsConnection {
    pub async fn from(server_stream: impl AsyncSocket) -> Result<Self, NetworkError> {
        // let x: Box<dyn AsyncSocket> = Box::new(server_stream);
        let ws_stream = WebSocketStream::from_raw_socket(
            Box::new(server_stream) as Box<dyn AsyncSocket>,
            tungstenite::protocol::Role::Server,
            None,
        )
        .await;

        Ok(Self {
            ws_stream,
            remaining_bytes: None,
            mode: WsMode::Server(tokio::time::interval(core::time::Duration::from_secs(
                KEEP_ALIVE_TIME,
            ))),
        })
    }
    pub async fn new(
        host: &str,
        headers: HashMap<&'static str, String>,
        service_type: ServiceType,
    ) -> Result<Self, NetworkError> {
        let sni = if let Some(sni) = host.split(':').next() {
            sni
        } else {
            host
        };
        let transport_type = if let ServiceType::Wss = service_type {
            StreamType::Tls(TlsConfiguration {
                sni: sni.to_owned(),
            })
        } else {
            StreamType::Tcp
        };
        let stream = UnifiedSocket::new(host, transport_type).await?;

        let (mut request_sender, connection) = conn::handshake(stream).await?;
        let conn_handler = tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("Error in connection: {}", e);
            }
        });
        let mut request = Request::builder()
            // .uri(uri)
            .header(
                "Host",
                host.strip_suffix(":443")
                    .or(host.strip_suffix(":80"))
                    .unwrap_or(host),
            )
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header(
                "Sec-WebSocket-Key",
                tungstenite::handshake::client::generate_key(),
            );
        for (key, value) in headers.iter() {
            let headers = request.headers_mut().unwrap();
            headers.insert(*key, HeaderValue::from_str(value).unwrap());
        }
        let request = request.method("GET").body(Body::from(""))?;
        let response = request_sender.send_request(request).await?;
        let response_headers = response.headers().clone();
        trace!("response status: {}", response.status().to_string());
        if response.status() != StatusCode::SWITCHING_PROTOCOLS {
            trace!(
                "response body: {}",
                String::from_utf8_lossy(
                    hyper::body::to_bytes(response.into_body()).await?.as_ref()
                )
            );
            return Err(NetworkError::UnableToUpgrade);
        }

        let upgraded = hyper::upgrade::on(response).await?;
        let ws_stream = tokio_tungstenite::WebSocketStream::from_raw_socket(
            Box::new(upgraded) as Box<dyn AsyncSocket>,
            tungstenite::protocol::Role::Client,
            None,
        )
        .await;
        Ok(Self {
            ws_stream,
            remaining_bytes: None,
            mode: WsMode::Client(response_headers, conn_handler),
        })
    }
    pub fn get_header(&self, key: &str) -> Option<&str> {
        if let WsMode::Client(response_headers, _) = &self.mode {
            response_headers.get(key).and_then(|v| v.to_str().ok())
        } else {
            None
        }
    }
    pub fn drive_key(key: &[u8]) -> String {
        tungstenite::handshake::derive_accept_key(key)
    }
}

impl AsyncRead for WsConnection {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if let Some(remaining_buf) = self.remaining_bytes.as_mut() {
                if buf.remaining() < remaining_buf.len() {
                    let buffer = remaining_buf.split_to(buf.remaining());
                    buf.put_slice(&buffer);
                } else {
                    buf.put_slice(remaining_buf);
                    self.remaining_bytes = None::<BytesMut>;
                }
                return Poll::Ready(Ok(()));
            }

            match self.ws_stream.poll_next_unpin(cx) {
                Poll::Ready(d) => match d {
                    Some(Ok(data)) => {
                        if let Message::Binary(bin) = data {
                            if buf.remaining() < bin.len() {
                                // todo max size 64 << 20
                                let mut bytes =
                                    BytesMut::with_capacity(bin.len() - buf.remaining());
                                bytes.put(&bin[buf.remaining()..]);
                                self.remaining_bytes = Some(bytes);
                                buf.put_slice(&bin[..buf.remaining()]);
                            } else {
                                buf.put_slice(&bin);
                            }

                            return Poll::Ready(Ok(()));
                        } else {
                            continue;
                        }
                    }
                    Some(Err(_e)) => io::Error::from(io::ErrorKind::UnexpectedEof),
                    None => return Poll::Ready(Ok(())),
                },
                Poll::Pending => {
                    if let WsMode::Server(interval) = &mut self.mode {
                        match interval.poll_tick(cx) {
                            Poll::Ready(_) => {
                                match self.ws_stream.send(Message::Ping(vec![0])).poll_unpin(cx) {
                                    Poll::Ready(Ok(_)) => continue,
                                    Poll::Ready(Err(_e)) => {
                                        return Poll::Ready(Err(Error::new(
                                            ErrorKind::Other,
                                            "Ping Error!",
                                        )))
                                    }
                                    Poll::Pending => return Poll::Pending,
                                }
                            }
                            Poll::Pending => return Poll::Pending,
                        }
                    } else {
                        return Poll::Pending;
                    }
                }
            };
        }
    }
}

impl AsyncWrite for WsConnection {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match Pin::new(&mut self.ws_stream.send(Message::binary(buf)))
            .poll(cx)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?
        {
            Poll::Ready(_) => Poll::Ready(Ok(buf.len())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        self.ws_stream
            .poll_flush_unpin(cx)
            .map_err(|_| io::Error::from(io::ErrorKind::UnexpectedEof))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        self.ws_stream
            .poll_close_unpin(cx)
            .map_err(|_| io::Error::from(io::ErrorKind::UnexpectedEof))
    }
}

impl futures_util::Stream for WsConnection {
    type Item = Result<String, NetworkError>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        loop {
            match self.ws_stream.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(msg))) => {
                    if let Message::Text(msg) = msg {
                        return Poll::Ready(Some(Ok(msg)));
                    } else {
                        continue;
                    }
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e.into()))),
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => {
                    if let WsMode::Server(interval) = &mut self.mode {
                        match interval.poll_tick(cx) {
                            Poll::Ready(_) => {
                                match self.ws_stream.send(Message::Ping(vec![0])).poll_unpin(cx) {
                                    Poll::Ready(Ok(_)) => continue,
                                    Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e.into()))),
                                    Poll::Pending => return Poll::Pending,
                                }
                            }
                            Poll::Pending => return Poll::Pending,
                        }
                    } else {
                        return Poll::Pending;
                    }
                }
            }
        }
    }
}
impl futures_util::Sink<String> for WsConnection {
    type Error = NetworkError;

    fn poll_ready(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.ws_stream.poll_ready_unpin(cx).map_err(|e| e.into())
    }

    fn start_send(mut self: std::pin::Pin<&mut Self>, item: String) -> Result<(), Self::Error> {
        self.ws_stream
            .start_send_unpin(Message::Text(item))
            .map_err(|e| e.into())
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.ws_stream.poll_flush_unpin(cx).map_err(|e| e.into())
    }

    fn poll_close(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.ws_stream.poll_close_unpin(cx).map_err(|e| e.into())
    }
}

pub struct WsConnectionBinary {
    ws_stream: WebSocketStream<Box<dyn AsyncSocket>>,
    // remaining_bytes: Option<BytesMut>,
    mode: WsMode,
}

impl WsConnectionBinary {
    pub async fn from(server_stream: impl AsyncSocket) -> Result<Self, NetworkError> {
        // let x: Box<dyn AsyncSocket> = Box::new(server_stream);
        let ws_stream = WebSocketStream::from_raw_socket(
            Box::new(server_stream) as Box<dyn AsyncSocket>,
            tungstenite::protocol::Role::Server,
            None,
        )
        .await;

        Ok(Self {
            ws_stream,
            // remaining_bytes: None,
            mode: WsMode::Server(tokio::time::interval(core::time::Duration::from_secs(
                KEEP_ALIVE_TIME,
            ))),
        })
    }
    pub async fn new(
        host: &str,
        // uri: &str,
        headers: HashMap<&'static str, String>,
        service_type: ServiceType,
    ) -> Result<Self, NetworkError> {
        let sni = if let Some(sni) = host.split(':').next() {
            sni
        } else {
            host
        };
        let transport_type = if let ServiceType::Wss = service_type {
            StreamType::Tls(TlsConfiguration {
                sni: sni.to_owned(),
            })
        } else {
            StreamType::Tcp
        };
        let stream = UnifiedSocket::new(host, transport_type).await?;

        let (mut request_sender, connection) = conn::handshake(stream).await?;
        let conn_handler = tokio::spawn(async move {
            if let Err(e) = connection.await {
                warn!("Error in connection: {}", e);
            }
        });

        let mut request = Request::builder()
            // .uri(uri)
            .header(
                "Host",
                host.strip_suffix(":443")
                    .or(host.strip_suffix(":80"))
                    .unwrap_or(host),
            )
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header(
                "Sec-WebSocket-Key",
                tungstenite::handshake::client::generate_key(),
            );
        for (key, value) in headers.iter() {
            let headers = request.headers_mut().unwrap();
            headers.insert(*key, HeaderValue::from_str(value).unwrap());
        }
        let request = request.method("GET").body(Body::from(""))?;
        let response = request_sender.send_request(request).await?;
        let response_headers = response.headers().clone();
        debug!("ws connection status: {}", response.status());
        if response.status() != StatusCode::SWITCHING_PROTOCOLS {
            trace!(
                "response body: {}",
                String::from_utf8_lossy(
                    hyper::body::to_bytes(response.into_body()).await?.as_ref()
                )
            );
            return Err(NetworkError::UnableToUpgrade);
        }
        let upgraded = hyper::upgrade::on(response).await?;
        let ws_stream = tokio_tungstenite::WebSocketStream::from_raw_socket(
            Box::new(upgraded) as Box<dyn AsyncSocket>,
            tungstenite::protocol::Role::Client,
            None,
        )
        .await;
        Ok(Self {
            ws_stream,
            // remaining_bytes: None,
            mode: WsMode::Client(response_headers, conn_handler),
        })
    }
    pub fn get_header(&self, key: &str) -> Option<&str> {
        if let WsMode::Client(response_headers, _) = &self.mode {
            response_headers.get(key).and_then(|v| v.to_str().ok())
        } else {
            None
        }
    }
    pub fn drive_key(key: &[u8]) -> String {
        tungstenite::handshake::derive_accept_key(key)
    }
}

impl futures_util::Stream for WsConnectionBinary {
    type Item = Result<Vec<u8>, NetworkError>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        loop {
            match self.ws_stream.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(msg))) => {
                    if let Message::Binary(msg) = msg {
                        return Poll::Ready(Some(Ok(msg)));
                    } else {
                        continue;
                    }
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e.into()))),
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => {
                    if let WsMode::Server(interval) = &mut self.mode {
                        match interval.poll_tick(cx) {
                            Poll::Ready(_) => {
                                match self.ws_stream.send(Message::Ping(vec![0])).poll_unpin(cx) {
                                    Poll::Ready(Ok(_)) => continue,
                                    Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e.into()))),
                                    Poll::Pending => return Poll::Pending,
                                }
                            }
                            Poll::Pending => return Poll::Pending,
                        }
                    } else {
                        return Poll::Pending;
                    }
                }
            }
        }
    }
}
impl futures_util::Sink<Vec<u8>> for WsConnectionBinary {
    type Error = NetworkError;

    fn poll_ready(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.ws_stream.poll_ready_unpin(cx).map_err(|e| e.into())
    }

    fn start_send(mut self: std::pin::Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        self.ws_stream
            .start_send_unpin(Message::Binary(item))
            .map_err(|e| e.into())
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.ws_stream.poll_flush_unpin(cx).map_err(|e| e.into())
    }

    fn poll_close(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.ws_stream.poll_close_unpin(cx).map_err(|e| e.into())
    }
}
