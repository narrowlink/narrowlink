use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    // sync::{atomic::AtomicU32, Arc},
    time::Duration,
};

use async_recursion::async_recursion;
use narrowlink_types::{
    generic::{Connect, CryptographicAlgorithm, Protocol, SigningAlgorithm},
    NatType, Peer2PeerRequest,
};
use quinn::{ClientConfig, Connection, Endpoint, EndpointConfig, RecvStream, SendStream};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UdpSocket,
};
use tracing::{debug, field::debug, info, warn};

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
    Ip(
        SocketAddr,
        bool,
        Option<(CryptographicAlgorithm, SigningAlgorithm)>,
    ), // bool is UDP
    Dns(
        String,
        u16,
        bool,
        Option<(CryptographicAlgorithm, SigningAlgorithm)>,
    ), // bool is UDP
}

impl Request {
    pub async fn read(mut reader: impl AsyncRead + Unpin) -> Result<Self, NetworkError> {
        let cmd = Command::from_u8(reader.read_u8().await?)?;
        let req = match cmd {
            Command::DomainTCP | Command::DomainUDP => {
                let len = reader.read_u8().await?;
                let mut buf = vec![0; len as usize + 2];
                reader.read_exact(&mut buf).await?;
                let domain = String::from_utf8(buf[..buf.len() - 2].to_vec())
                    .map_err(|_| NetworkError::P2PInvalidDomain)?;
                let port = u16::from_be_bytes([buf[buf.len() - 2], buf[buf.len() - 1]]);
                Self::Dns(domain, port, cmd == Command::DomainUDP, None)
            }
            Command::IPv4TCP | Command::IPv4UDP => {
                let mut buf = vec![0; 4 + 2];
                reader.read_exact(&mut buf).await?;
                let ipv4 = std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let port = u16::from_be_bytes([buf[buf.len() - 2], buf[buf.len() - 1]]);
                Self::Ip(
                    SocketAddr::new(ipv4.into(), port),
                    cmd == Command::IPv4UDP,
                    None,
                )
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
                Self::Ip(
                    SocketAddr::new(ipv6.into(), port),
                    cmd == Command::IPv6UDP,
                    None,
                )
            }
        };
        if reader.read_u8().await? == 1 {
            let mut buf = vec![0; 24 + 32];
            reader.read_exact(&mut buf).await?;
            let crypto = CryptographicAlgorithm::XChaCha20Poly1305(
                buf[..24]
                    .try_into()
                    .map_err(|_| NetworkError::P2PInvalidCrypto)?,
            );
            let sign = SigningAlgorithm::HmacSha256(
                buf[24..]
                    .try_into()
                    .map_err(|_| NetworkError::P2PInvalidCrypto)?,
            );
            let req = match req {
                Self::Ip(ip, udp, _) => Self::Ip(ip, udp, Some((crypto, sign))),
                Self::Dns(domain, port, udp, _) => {
                    Self::Dns(domain, port, udp, Some((crypto, sign)))
                }
            };
            Ok(req)
        } else {
            Ok(req)
        }
    }
    pub async fn write(&self, mut writer: impl AsyncWrite + Unpin) -> Result<(), NetworkError> {
        match self {
            Request::Ip(ip, udp, crypt) => {
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
                if let Some(c) = crypt {
                    writer.write_u8(1).await?;
                    match c {
                        (
                            CryptographicAlgorithm::XChaCha20Poly1305(iv),
                            SigningAlgorithm::HmacSha256(key),
                        ) => {
                            writer.write_all(iv).await?;
                            writer.write_all(key).await?;
                        }
                    }
                } else {
                    writer.write_u8(0).await?;
                }
            }
            Request::Dns(domain, port, udp, crypt) => {
                let cmd = if *udp {
                    Command::DomainUDP
                } else {
                    Command::DomainTCP
                };
                writer.write_u8(cmd as u8).await?;
                writer.write_u8(domain.len() as u8).await?;
                writer.write_all(domain.as_bytes()).await?;
                writer.write_u16(*port).await?;
                if let Some(c) = crypt {
                    writer.write_u8(1).await?;
                    match c {
                        (
                            CryptographicAlgorithm::XChaCha20Poly1305(iv),
                            SigningAlgorithm::HmacSha256(key),
                        ) => {
                            writer.write_all(iv).await?;
                            writer.write_all(key).await?;
                        }
                    }
                } else {
                    writer.write_u8(0).await?;
                }
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

impl ToString for Response {
    fn to_string(&self) -> String {
        match self {
            Self::Success => "Success".to_owned(),
            Self::InvalidRequest => "InvalidRequest".to_owned(),
            Self::AccessDenied => "AccessDenied".to_owned(),
            Self::Failed => "Failed".to_owned(),
        }
    }
}

impl Response {
    pub async fn read(mut reader: impl AsyncRead + Unpin) -> Result<Self, NetworkError> {
        let val = reader.read_u8().await?;
        match val {
            0x00 => Ok(Self::Success),
            0x01 => Ok(Self::InvalidRequest),
            0x02 => Ok(Self::AccessDenied),
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
        let (host, port, is_udp, crypt) = match r {
            Request::Ip(ip, udp, crypt) => (ip.ip().to_string(), ip.port(), udp, crypt),
            Request::Dns(domain, port, udp, crypt) => (domain.to_owned(), *port, udp, crypt),
        };
        let (cryptography, sign) = if let Some((c, s)) = crypt {
            (Some(c.clone()), Some(s.clone()))
        } else {
            (None, None)
        };
        Connect {
            host,
            port,
            protocol: if *is_udp {
                Protocol::UDP
            } else {
                Protocol::TCP
            },
            cryptography,
            sign,
        }
    }
}

impl From<&Connect> for Request {
    fn from(connect: &Connect) -> Self {
        let crypt = if let (Some(c), Some(s)) = (&connect.cryptography, &connect.sign) {
            Some((c.clone(), s.clone()))
        } else {
            None
        };
        match connect.protocol {
            Protocol::TCP | Protocol::HTTP | Protocol::HTTPS | Protocol::TLS => {
                match connect.host.parse::<IpAddr>() {
                    Ok(ip) => Request::Ip(SocketAddr::new(ip, connect.port), false, crypt),
                    Err(_) => Request::Dns(connect.host.to_owned(), connect.port, false, crypt),
                }
            }
            Protocol::UDP | Protocol::DTLS | Protocol::QUIC => match connect.host.parse::<IpAddr>()
            {
                Ok(ip) => Request::Ip(SocketAddr::new(ip, connect.port), true, crypt),
                Err(_) => Request::Dns(connect.host.to_owned(), connect.port, true, crypt),
            },
        }
    }
}

pub struct QuicStream {
    con: Connection,
    // number_of_streams: Arc<AtomicU32>,
}

impl QuicStream {
    pub async fn new_client(
        remote_addr: SocketAddr,
        socket: UdpSocket, // tokio udpsocket
        cert: Vec<u8>,
    ) -> Result<Self, NetworkError> {
        debug!("Connecting to {}", remote_addr);
        let mut end = Endpoint::new(
            EndpointConfig::default(),
            None,
            socket.into_std()?,
            Arc::new(quinn::TokioRuntime),
        )?;
        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(&rustls::Certificate(cert))
            .map_err(|_| NetworkError::TlsError)?;
        let mut config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        config.enable_sni = false;
        end.set_default_client_config(ClientConfig::new(Arc::new(config)));

        let con = end
            .connect(remote_addr, &remote_addr.ip().to_string())
            .map_err(|_| NetworkError::QuicError)?
            .await
            .map_err(|_| NetworkError::QuicError)?;
        Ok(Self { con })
    }
    pub async fn new_server(
        socket: UdpSocket, // tokio udpsocket
        cert: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Self, NetworkError> {
        debug("Accepting connection");
        let mut server_config = quinn::ServerConfig::with_single_cert(
            vec![rustls::Certificate(cert)],
            rustls::PrivateKey(key),
        )
        .map_err(|_| NetworkError::TlsError)?;
        if let Some(conf) = std::sync::Arc::get_mut(&mut server_config.transport) {
            conf.keep_alive_interval(Some(Duration::from_secs(5)));
            // conf.max_concurrent_uni_streams(0_u8.into());
        };
        let end = Endpoint::new(
            EndpointConfig::default(),
            Some(server_config),
            socket.into_std()?,
            Arc::new(quinn::TokioRuntime),
        )?;
        let con = end
            .accept()
            .await
            .ok_or(NetworkError::QuicError)?
            .await
            .map_err(|_| NetworkError::QuicError)?;
        Ok(Self { con })
    }
    pub async fn open_bi(&self) -> Result<QuicBiSocket, NetworkError> {
        let (send, recv) = self
            .con
            .open_bi()
            .await
            .map_err(|_| NetworkError::QuicError)?;
        // self.number_of_streams.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(QuicBiSocket {
            send,
            recv,
            // number_of_streams: self.number_of_streams.clone(),
        })
    }
    pub async fn accept_bi(&self) -> Result<QuicBiSocket, NetworkError> {
        let (send, recv) = self
            .con
            .accept_bi()
            .await
            .map_err(|_| NetworkError::QuicError)?;
        // self.number_of_streams.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(QuicBiSocket {
            send,
            recv,
            // number_of_streams: self.number_of_streams.clone(),
        })
    }
    pub fn remote_addr(&self) -> SocketAddr {
        self.con.remote_address()
    }
}

pub struct QuicBiSocket {
    send: SendStream,
    recv: RecvStream,
    // number_of_streams: Arc<AtomicU32>,
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

// impl Drop for QuicBiSocket {
//     fn drop(&mut self) {
//         self.number_of_streams.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
//     }
// }

#[async_recursion]
pub async fn udp_punched_socket(
    p2p: &Peer2PeerRequest,
    handshake_key: &[u8],
    left: bool,
    inner: bool,
) -> Result<(UdpSocket, SocketAddr), NetworkError> {
    debug!("P2P: {:?}", p2p);
    let unspecified_ip = if p2p.peer_ip.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    #[cfg(unix)]
    let no_file_limit = rlimit::getrlimit(rlimit::Resource::NOFILE)
        .map(|(n, _)| n)
        .ok();

    #[cfg(unix)]
    if p2p.seq > 128 && no_file_limit.is_some() {
        _ = rlimit::increase_nofile_limit(512);
    }

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
                debug!(
                    "Punching peer {}:{} -> {}:{}",
                    unspecified_ip, my_port, p2p.peer_ip, peer_port
                );
                vec![0]
            } else {
                debug!(
                    "Discovering peer {}:{} -> {}:{}",
                    unspecified_ip, my_port, p2p.peer_ip, peer_port
                );
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
        if sockets.is_empty() {
            #[cfg(unix)]
            no_file_limit.and_then(|n| rlimit::increase_nofile_limit(n).ok());
            return Err(NetworkError::P2PFailed);
        };
        let Ok((socket, _size, remaining_sockets)) = tokio::time::timeout(
            Duration::from_secs(if p2p.seq > 128 { 15 } else { 5 }),
            futures_util::future::select_all(sockets),
        )
        .await
        else {
            warn!("Timeout waiting for response from peer");
            if !inner && p2p.nat == p2p.peer_nat {
                info!("Trying to punch peer from other side");
                if puncher {
                    tokio::time::sleep(Duration::from_millis(1000)).await;
                }
                return udp_punched_socket(p2p, handshake_key, !left, true).await;
            }
            #[cfg(unix)]
            no_file_limit.and_then(|n| rlimit::increase_nofile_limit(n).ok());
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
            if let Ok(local_addr) = socket.local_addr() {
                debug!(
                    "Confirming p2p channel peer {}:{} -> {}:{}",
                    local_addr.ip(),
                    local_addr.port(),
                    peer.ip(),
                    peer.port()
                );
            }
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
        #[cfg(unix)]
        no_file_limit.and_then(|n| rlimit::increase_nofile_limit(n).ok());
        return Ok((socket, peer));
    }
}
