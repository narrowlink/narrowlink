mod input_stream;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod tun;
use either::Either;
use futures_util::{
    future::{pending, Ready},
    stream::{self, Once},
    StreamExt,
};
use ipstack::stream::IpStackStream;
use narrowlink_network::AsyncSocket;
use narrowlink_types::generic::{self};
use proxy_stream::ProxyStream;

use tracing::info;
use udp_stream::UdpListener;

use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::{net::TcpListener, sync::Notify};

use crate::error::ClientError;

use input_stream::InputStream;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use tun::{RouteCommand, TunListener};

pub enum TunnelInstruction {
    Connect(bool, (String, u16)),             // udp, endpoint
    Forward(bool, SocketAddr, (String, u16)), // udp, local, endpoint
    Proxy(SocketAddr),                        // endpoint
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Tun(bool, IpAddr, Option<IpAddr>), // default_gateway, addr, map
    None,
}

pub struct TunnelFactory {
    instruction: TunnelInstruction,
    listener: Option<TunnelListener>,
    wait: Option<Arc<Notify>>,
    hosts: HashSet<IpAddr>,
}

pub enum TunnelListener {
    Connect(Once<Ready<InputStream>>, bool, (String, u16)),
    Forward(Either<TcpListener, UdpListener>, (String, u16)),
    Proxy(TcpListener),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Tun(TunListener),
}

impl TunnelFactory {
    pub fn new(instruction: TunnelInstruction) -> Self {
        Self {
            instruction,
            listener: None,
            wait: Some(Arc::new(Notify::new())),
            hosts: HashSet::new(),
        }
    }
    pub async fn start(&mut self) -> Result<(), ClientError> {
        if self.listener.is_some() {
            return Ok(());
        }
        match &self.instruction {
            TunnelInstruction::Connect(udp, (dst_addr, dst_port)) => {
                self.listener = Some(TunnelListener::Connect(
                    stream::once(futures_util::future::ready(InputStream::default())),
                    *udp,
                    (dst_addr.clone(), *dst_port),
                ));
            }
            TunnelInstruction::Forward(udp, local, endpoint) => {
                let listener = if *udp {
                    let listener = UdpListener::bind(*local).await?;
                    if let Ok(addr) = listener.local_addr() {
                        info!("Listen on: udp://{}:{}", addr.ip(), addr.port());
                    }

                    either::Right(listener)
                } else {
                    let listener = TcpListener::bind(*local).await?;
                    if let Ok(addr) = listener.local_addr() {
                        info!("Listen on: tcp://{}:{}", addr.ip(), addr.port());
                    }
                    either::Left(listener)
                };
                self.listener = Some(TunnelListener::Forward(listener, endpoint.clone()));
            }
            TunnelInstruction::Proxy(endpoint) => {
                let listener = TcpListener::bind(endpoint).await?;
                if let Ok(addr) = listener.local_addr() {
                    info!("Listen on: socks5://{}:{}", addr.ip(), addr.port());
                }
                self.listener = Some(TunnelListener::Proxy(listener));
            }
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TunnelInstruction::Tun(default_gateway, addr, map) => {
                let tun = TunListener::new(*addr, *map).await?;
                if let Some(s) = tun.route_sender() {
                    for ip in self.hosts.iter() {
                        s.send(RouteCommand::Add(*ip)).unwrap();
                    }
                }
                tun.my_routes(*default_gateway);
                self.listener = Some(TunnelListener::Tun(tun));
            }
            TunnelInstruction::None => Err(ClientError::Unexpected(0))?,
        };
        if let Some(wait) = self.wait.take() {
            wait.notify_waiters();
        }
        Ok(())
    }
    pub fn stop(&mut self) {
        self.wait = Some(Arc::new(Notify::new()));
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        self.listener.take();
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(TunnelListener::Tun(t)) = self.listener.take() {
            t.my_routes(false);
        };
    }
    pub async fn accept(
        &mut self,
    ) -> Result<(Box<dyn AsyncSocket>, generic::Connect), ClientError> {
        if let Some(wait) = self.wait.as_ref() {
            wait.notified().await;
        };
        match &mut self.listener {
            Some(TunnelListener::Connect(stream, udp, (dst_addr, dst_port))) => {
                let s = match stream.next().await {
                    Some(s) => s,
                    None => pending().await,
                };
                Ok((
                    Box::new(s),
                    generic::Connect {
                        host: dst_addr.clone(),
                        port: *dst_port,
                        protocol: if *udp {
                            generic::Protocol::UDP
                        } else {
                            generic::Protocol::TCP
                        },
                        cryptography: None,
                        sign: None,
                    },
                ))
            }
            Some(TunnelListener::Proxy(l)) => {
                let interrupted_stream = match ProxyStream::new(proxy_stream::ProxyType::SOCKS5)
                    .accept(l.accept().await?.0)
                    .await
                {
                    Ok(s) => s,
                    Err(_e) => return Err(ClientError::InvalidSocksRequest),
                };
                let addr: (String, u16) = interrupted_stream.addr().into();
                let protocol =
                    if interrupted_stream.command() == proxy_stream::Command::UdpAssociate {
                        generic::Protocol::UDP
                    } else {
                        generic::Protocol::TCP
                    };
                Ok((
                    Box::new(
                        interrupted_stream
                            .connect()
                            .await
                            .map_err(|_| ClientError::InvalidSocksRequest)?,
                    ),
                    generic::Connect {
                        host: addr.0,
                        port: addr.1,
                        protocol,
                        cryptography: None,
                        sign: None,
                    },
                ))
            }
            Some(TunnelListener::Forward(listener, end_point)) => {
                let (socket, protocol): (Box<dyn AsyncSocket>, generic::Protocol) = match listener {
                    either::Left(tcp_listener) => {
                        let (socket, _local_addr) = tcp_listener.accept().await?;
                        (Box::new(socket), generic::Protocol::UDP)
                    }
                    either::Right(udp_listener) => {
                        let (socket, _local_addr) = udp_listener.accept().await?;
                        (Box::new(socket), generic::Protocol::TCP)
                    }
                };
                let addr: (String, u16) = end_point.clone();
                Ok((
                    Box::new(socket),
                    generic::Connect {
                        host: addr.0,
                        port: addr.1,
                        protocol,
                        cryptography: None,
                        sign: None,
                    },
                ))
            }
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Some(TunnelListener::Tun(tun_listener)) => {
                let stream = tun_listener.accept().await.unwrap();
                let peer_addr = stream.peer_addr();
                let (stream, udp): (Box<dyn AsyncSocket>, bool) = match stream {
                    IpStackStream::Tcp(tcp) => (Box::new(tcp), false),
                    IpStackStream::Udp(udp) => (Box::new(udp), true),
                };

                Ok((
                    stream,
                    generic::Connect {
                        host: peer_addr.ip().to_string(),
                        port: peer_addr.port(),
                        protocol: if udp {
                            generic::Protocol::UDP
                        } else {
                            generic::Protocol::TCP
                        },
                        cryptography: None,
                        sign: None,
                    },
                ))
            }
            None => Err(ClientError::UnableToConnect),
        }
    }
    pub fn add_host(&mut self, ip: IpAddr) {
        self.hosts.insert(ip);
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(TunnelListener::Tun(tun)) = self.listener.as_ref() {
            if let Some(s) = tun.route_sender() {
                let _ = s.send(RouteCommand::Add(ip));
            };
        }
    }
    #[allow(dead_code)]
    pub fn del_host(&mut self, ip: IpAddr) {
        self.hosts.remove(&ip);
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(TunnelListener::Tun(tun)) = self.listener.as_ref() {
            if let Some(s) = tun.route_sender() {
                let _ = s.send(RouteCommand::Del(ip));
            };
        }
    }
}
