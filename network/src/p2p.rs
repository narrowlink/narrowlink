use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use async_recursion::async_recursion;
use narrowlink_types::{
    generic::{Connect, Protocol},
    NatType, Peer2PeerRequest,
};
use quinn::{Connection, RecvStream, SendStream};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UdpSocket,
};
use tracing::warn;

use crate::error::NetworkError;
#[derive(PartialEq)]
pub enum Command {
    IPv4TCP = 0x01,
    IPv6TCP = 0x02,
    DomainTCP = 0x03,
    IPv4UDP = 0x04,
    IPv6UDP = 0x05,
    DomainUDP = 0x06,
}

impl Command {
    fn from_u8(val: u8) -> Result<Self, NetworkError> {
        match val {
            0x01 => Ok(Self::IPv4TCP),
            0x02 => Ok(Self::IPv6TCP),
            0x03 => Ok(Self::DomainTCP),
            0x04 => Ok(Self::IPv4UDP),
            0x05 => Ok(Self::IPv6UDP),
            0x06 => Ok(Self::DomainUDP),
            _ => Err(NetworkError::P2PInvalidCommand),
        }
    }
}
pub enum Request {
    // Todo: Add signature and salt
    Ip(SocketAddr, bool),   // bool is UDP
    Dns(String, u16, bool), // bool is UDP
}

impl Request {
    pub async fn read(mut reader: impl AsyncRead + Unpin) -> Result<Self, NetworkError> {
        let cmd = Command::from_u8(reader.read_u8().await?)?;
        match cmd {
            Command::DomainTCP | Command::DomainUDP => {
                let len = reader.read_u8().await?;
                let mut buf = vec![0; len as usize + 2];
                reader.read_exact(&mut buf).await?;
                let domain = String::from_utf8(buf[..buf.len() - 2].to_vec())
                    .map_err(|_| NetworkError::P2PInvalidDomain)?;
                let port = u16::from_be_bytes([buf[buf.len() - 2], buf[buf.len() - 1]]);
                Ok(Self::Dns(domain, port, cmd == Command::DomainUDP))
            }
            Command::IPv4TCP | Command::IPv4UDP => {
                let mut buf = vec![0; 4 + 2];
                reader.read_exact(&mut buf).await?;
                let ipv4 = std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let port = u16::from_be_bytes([buf[buf.len() - 2], buf[buf.len() - 1]]);
                Ok(Self::Ip(
                    SocketAddr::new(ipv4.into(), port),
                    cmd == Command::IPv4UDP,
                ))
            }
            Command::IPv6TCP | Command::IPv6UDP => {
                let mut buf = vec![0; 16 + 2];
                reader.read_exact(&mut buf).await?;
                let ipv6 = std::net::Ipv6Addr::new(
                    u16::from_be_bytes([buf[0], buf[1]]),
                    u16::from_be_bytes([buf[2], buf[3]]),
                    u16::from_be_bytes([buf[4], buf[5]]),
                    u16::from_be_bytes([buf[6], buf[7]]),
                    u16::from_be_bytes([buf[8], buf[9]]),
                    u16::from_be_bytes([buf[10], buf[11]]),
                    u16::from_be_bytes([buf[12], buf[13]]),
                    u16::from_be_bytes([buf[14], buf[15]]),
                );
                let port = u16::from_be_bytes([buf[buf.len() - 2], buf[buf.len() - 1]]);
                Ok(Self::Ip(
                    SocketAddr::new(ipv6.into(), port),
                    cmd == Command::IPv6UDP,
                ))
            }
        }
    }
    pub async fn write(&self, mut writer: impl AsyncWrite + Unpin) -> Result<(), NetworkError> {
        match self {
            Request::Ip(ip, udp) => {
                let cmd = if ip.is_ipv4() {
                    if *udp {
                        Command::IPv4UDP
                    } else {
                        Command::IPv4TCP
                    }
                } else if *udp {
                    Command::IPv6UDP
                } else {
                    Command::IPv6TCP
                };
                writer.write_u8(cmd as u8).await?;
                match ip {
                    SocketAddr::V4(ipv4) => {
                        writer.write_all(&ipv4.ip().octets()).await?;
                    }
                    SocketAddr::V6(ipv6) => {
                        writer.write_all(&ipv6.ip().octets()).await?;
                    }
                }
                writer.write_u16(ip.port()).await?;
            }
            Request::Dns(domain, port, udp) => {
                let cmd = if *udp {
                    Command::DomainUDP
                } else {
                    Command::DomainTCP
                };
                writer.write_u8(cmd as u8).await?;
                writer.write_u8(domain.len() as u8).await?;
                writer.write_all(domain.as_bytes()).await?;
                writer.write_u16(*port).await?
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Response {
    Success = 0x00,
    InvalidRequest = 0x01,
    AccessDenied = 0x02,
    Failed = 0xFF,
}

impl Response {
    pub async fn read(mut reader: impl AsyncRead + Unpin) -> Result<Self, NetworkError> {
        let val = reader.read_u8().await?;
        match val {
            0x00 => Ok(Self::Success),
            0x01 => Ok(Self::InvalidRequest),
            0xFF => Ok(Self::Failed),
            _ => Err(NetworkError::P2PInvalidCommand),
        }
    }
    pub async fn write(&self, mut writer: impl AsyncWrite + Unpin) -> Result<(), NetworkError> {
        writer.write_u8(*self as u8).await?;
        Ok(())
    }
}

impl From<&Request> for Connect {
    fn from(r: &Request) -> Self {
        let (host, port, is_udp) = match r {
            Request::Ip(ip, udp) => (ip.ip().to_string(), ip.port(), udp),
            Request::Dns(domain, port, udp) => (domain.to_owned(), *port, udp),
        };
        Connect {
            host,
            port,
            protocol: if *is_udp {
                Protocol::UDP
            } else {
                Protocol::TCP
            },
            cryptography: None,
            sign: None,
        }
    }
}

impl From<&Connect> for Request {
    fn from(connect: &Connect) -> Self {
        match connect.protocol {
            Protocol::TCP | Protocol::HTTP | Protocol::HTTPS | Protocol::TLS => {
                match connect.host.parse::<IpAddr>() {
                    Ok(ip) => Request::Ip(SocketAddr::new(ip, connect.port), false),
                    Err(_) => Request::Dns(connect.host.to_owned(), connect.port, false),
                }
            }
            Protocol::UDP | Protocol::DTLS | Protocol::QUIC => match connect.host.parse::<IpAddr>()
            {
                Ok(ip) => Request::Ip(SocketAddr::new(ip, connect.port), true),
                Err(_) => Request::Dns(connect.host.to_owned(), connect.port, true),
            },
        }
    }
}

pub struct QuicBiSocket {
    send: SendStream,
    recv: RecvStream,
    remote_addr: SocketAddr,
}

impl QuicBiSocket {
    pub async fn open(stream: &Connection) -> Result<Self, NetworkError> {
        let remote_addr = stream.remote_address();
        let (send, recv) = stream.open_bi().await.unwrap();
        // .map_err(|_| NetworkError::QuicError)?;
        Ok(Self {
            send,
            recv,
            remote_addr,
        })
    }
    pub async fn accept(stream: &Connection) -> Result<Self, NetworkError> {
        let remote_addr = stream.remote_address();
        let (send, recv) = stream
            .accept_bi()
            .await
            .map_err(|_| NetworkError::QuicError)?;
        Ok(Self {
            send,
            recv,
            remote_addr,
        })
    }
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}

impl AsyncRead for QuicBiSocket {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicBiSocket {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        std::pin::Pin::new(&mut self.send).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.send).poll_shutdown(cx)
    }
}
#[async_recursion]
pub async fn udp_punched_socket(
    p2p: &Peer2PeerRequest,
    handshake_key: &[u8],
    left: bool,
    inner: bool,
) -> Result<(UdpSocket, SocketAddr), NetworkError> {
    let unspecified_ip = if p2p.peer_ip.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };

    let (puncher, dyn_my_port, dyn_peer_port) = match (p2p.nat, p2p.peer_nat) {
        (NatType::Easy, NatType::Easy) => (left, true, true),
        (NatType::Easy, NatType::Hard) => (true, false, true),
        (NatType::Easy, NatType::Unknown) => (true, false, true),
        (NatType::Hard, NatType::Easy) => (false, true, false),
        (NatType::Hard, NatType::Hard) => (left, left, !left),
        (NatType::Hard, NatType::Unknown) => (false, true, false),
        (NatType::Unknown, NatType::Easy) => (false, true, false),
        (NatType::Unknown, NatType::Hard) => (true, false, true),
        (NatType::Unknown, NatType::Unknown) => (left, left, !left),
    };

    if !puncher {
        tokio::time::sleep(Duration::from_millis(1000)).await;
    }

    let mut sockets = Vec::new();
    dbg!(p2p.seed_port);
    let mut socket: Option<UdpSocket> = None;
    for s in 1..p2p.seq + 1 {
        let my_port = if dyn_my_port {
            if left {
                p2p.seed_port - s
            } else {
                p2p.seed_port + s
            }
        } else {
            p2p.seed_port
        };
        let peer_port = if dyn_peer_port {
            if left {
                p2p.seed_port + s
            } else {
                p2p.seed_port - s
            }
        } else {
            p2p.seed_port
        };
        dbg!(my_port);
        dbg!(peer_port);
        if socket.is_none() || dyn_my_port {
            match UdpSocket::bind(SocketAddr::new(unspecified_ip, my_port)).await {
                Ok(s) => socket.replace(s),
                Err(e) => {
                    warn!("Error binding socket on {}, {}", my_port, e.to_string());
                    continue;
                }
            };
        }

        if let Some(socket) = socket.as_ref() {
            let buf = if puncher {
                vec![0]
            } else {
                handshake_key[0..3].to_vec()
            };
            if let Err(e) = socket
                .send_to(&buf, SocketAddr::new(p2p.peer_ip, peer_port))
                .await
            {
                warn!("Error sending to peer: {}", e);
            };
        }
        if s == p2p.seq || dyn_my_port {
            if let Some(socket) = socket.take() {
                sockets.push(Box::pin(async { socket.readable().await.map(|_| socket) }));
            }
        }
    }
    loop {
        let Ok((socket, _size, remaining_sockets)) = tokio::time::timeout(
            Duration::from_secs(15),
            futures_util::future::select_all(sockets),
        )
        .await
        else {
            warn!("Timeout waiting for response from peer");
            if !inner && p2p.nat == p2p.peer_nat && p2p.nat == NatType::Unknown {
                return udp_punched_socket(p2p, handshake_key, !left, true).await;
            }
            return Err(NetworkError::P2PTimeout);
        };
        let socket = match socket {
            Ok(socket) => socket,
            Err(e) => {
                warn!("Error reading from socket: {}", e);
                sockets = remaining_sockets;
                continue;
            }
        };

        let mut buf = vec![0u8; 3];
        let peer = match socket.recv_from(&mut buf).await {
            Ok((_, peer)) => peer,
            Err(e) => {
                warn!("Error receiving from socket: {}", e);
                sockets = remaining_sockets;
                continue;
            }
        };

        if puncher && handshake_key[0..3] == buf[0..3] {
            if let Err(e) = socket.send_to(&handshake_key[3..6], peer).await {
                warn!("Error sending to peer: {}", e);
                sockets = remaining_sockets;
                continue;
            }
        } else if handshake_key[3..6] == buf[0..3] {
        } else {
            warn!("Invalid response from peer");
            sockets = remaining_sockets;
            continue;
        };
        return Ok((socket, peer));
    }
}
