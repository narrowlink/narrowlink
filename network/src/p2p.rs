use std::net::SocketAddr;

use quinn::{Connection, RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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

#[derive(Clone, Copy)]
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

pub struct QuicBiSocket {
    send: SendStream,
    recv: RecvStream,
    remote_addr: SocketAddr,
}

impl QuicBiSocket {
    pub async fn open(stream: Connection) -> Result<Self, NetworkError> {
        let remote_addr = stream.remote_address();
        let (send, recv) = stream
            .open_bi()
            .await
            .map_err(|_| NetworkError::QuicError)?;
        Ok(Self {
            send,
            recv,
            remote_addr,
        })
    }
    pub async fn accept(stream: Connection) -> Result<Self, NetworkError> {
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
