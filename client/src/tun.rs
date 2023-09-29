use std::{
    collections::{hash_map::Entry, HashMap},
    io::Cursor,
    net::{IpAddr, SocketAddr},
};

use etherparse::{Ipv4Header, SlicedPacket, TcpHeader, UdpHeader};
use futures_util::FutureExt;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    select,
    sync::mpsc,
};
use tun::AsyncDevice;

use crate::error::ClientError;

const MTU: usize = 1500;

#[derive(Debug)]
pub enum TunStream {
    Tcp(TunTcpStream),
    // Udp(UdpStream),
}
pub struct TunListener {
    device: AsyncDevice,
    #[allow(clippy::all)]
    tcp_streams: HashMap<(SocketAddr, SocketAddr, bool), mpsc::Sender<(TcpHeader, Vec<u8>)>>,
    // udp_streams: HashMap<(SocketAddr, SocketAddr, bool), mpsc::Sender<Packet>>,
    packet_receiver: mpsc::Receiver<Vec<u8>>,
    packet_sender: mpsc::Sender<Vec<u8>>,
}

impl TunListener {
    pub fn new() -> Self {
        let mut config = tun::Configuration::default();

        config
            .address((10, 0, 0, 1))
            // .destination((10, 0, 0, 1))
            // .netmask((255, 255, 255, 255))
            .mtu(MTU as i32)
            .up();

        let device = tun::create_as_async(&config).unwrap();
        let (packet_sender, packet_receiver) = mpsc::channel::<Vec<u8>>(100);
        Self {
            device,
            tcp_streams: HashMap::new(),
            // udp_streams: HashMap::new(),
            packet_receiver,
            packet_sender,
        }
    }
    pub async fn accept(&mut self) -> Result<(TunStream, SocketAddr), ClientError> {
        loop {
            select! {
                packet = Packet::from_async_read(&mut self.device) =>{
                    match &packet.transport {
                        Transport::Tcp(tcp) => match self.tcp_streams.entry(packet.get_network_tuple()) {
                            Entry::Occupied(s) => {
                                if !tcp.syn {
                                    let ss = s.get();
                                    // dbg!(ss.is_closed());
                                    ss.send((tcp.clone(),packet.payload)).await.unwrap();
                                }
                            },
                            Entry::Vacant(c) => {
                                if !tcp.syn {
                                    continue
                                    // panic!("not syn")
                                    // return Err(());
                                }
                                let tcp_stream = TunTcpStream::new(
                                    packet.get_src_address(),
                                    packet.get_dst_address(),
                                    tcp,
                                    self.packet_sender.clone(),
                                );
                                c.insert(tcp_stream.get_sender());
                                return Ok((TunStream::Tcp(tcp_stream),packet.get_dst_address()));
                            }
                        },
                        Transport::Udp(_udp) => {
                            dbg!("todo");
                            continue
                        }
                    }
                }
                bytes = self.packet_receiver.recv() => {
                    match bytes{
                        Some(msg) => {
                            self.device.write_all(&msg).await.unwrap();
                        }
                        None => {
                            todo!();
                        }
                    }
                }
            };
        }
    }
}

impl Default for TunListener {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct TunTcpStream {
    src: SocketAddr,
    dst: SocketAddr,
    state: ConnectionState,
    send_seq: SendSequence,
    recv_seq: RecvSequence,
    // irs: u32, // initial receive sequence number
    // iss: u32, // initial send sequence number
    sender: mpsc::Sender<(TcpHeader, Vec<u8>)>,
    receiver: mpsc::Receiver<(TcpHeader, Vec<u8>)>,
    tun_sender: mpsc::Sender<Vec<u8>>,
}

impl TunTcpStream {
    pub fn new(
        src: SocketAddr,
        dst: SocketAddr,
        tcp: &TcpHeader,
        tun_sender: mpsc::Sender<Vec<u8>>,
    ) -> Self {
        let (sender, receiver) = mpsc::channel(100);
        let recv_seq = RecvSequence {
            nxt: tcp.sequence_number + 1, // Next sequence number expected on an incoming segment
            wnd: tcp.window_size,         // Receive window
                                          // up: 0,                        // Urgent pointer
        };
        let iss = 100;
        let send_seq = SendSequence {
            una: iss,  // Unacknowledged sequence number
            nxt: iss,  // Next sequence number to be sent
            wnd: 1024, // Send window
            // up: 0,     // Urgent pointer
            wl1: 0, // Segment sequence number used for last window update
            wl2: 0, // Segment acknowledgment number used for last window update
        };
        Self {
            src,
            dst,
            state: ConnectionState::SynReceived,
            send_seq,
            recv_seq,
            // irs: tcp.sequence_number, // initial receive sequence number
            // iss: 100,                 // initial send sequence number
            sender,
            receiver,
            tun_sender,
        }
    }
    pub fn get_sender(&self) -> mpsc::Sender<(TcpHeader, Vec<u8>)> {
        self.sender.clone()
    }
}

impl AsyncRead for TunTcpStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        loop {
            if matches!(self.state, ConnectionState::SynReceived) {
                let mut packet = Packet::new_tcp(self.dst, self.src);
                let tcp = packet.tcp().unwrap();
                tcp.sequence_number = self.send_seq.nxt;
                tcp.acknowledgment_number = self.recv_seq.nxt;
                tcp.window_size = self.recv_seq.wnd;
                tcp.syn = true;
                tcp.ack = true;
                let b = packet.as_bytes();
                let send = Box::pin(self.tun_sender.send(b)).poll_unpin(cx);
                match send {
                    std::task::Poll::Ready(Ok(_)) => {
                        self.send_seq.nxt += 1;
                        self.send_seq.una += 1;
                        self.state = ConnectionState::Established;
                        continue;
                    }
                    std::task::Poll::Ready(Err(_)) => todo!(),
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                }
            };
            if matches!(self.state, ConnectionState::Established) {
                match self.receiver.poll_recv(cx) {
                    std::task::Poll::Ready(Some((tcp, payload))) => {
                        if tcp.ack
                            && [
                                tcp.syn, tcp.fin, tcp.rst, tcp.psh, tcp.urg, tcp.ece, tcp.cwr,
                            ]
                            .iter()
                            .all(|v| v == &false)
                        {
                            self.send_seq.una = tcp.acknowledgment_number;
                            self.send_seq.wnd = tcp.window_size;
                            continue;
                        }
                        if tcp.ack
                            && tcp.psh
                            && [tcp.syn, tcp.fin, tcp.rst, tcp.urg, tcp.ece, tcp.cwr]
                                .iter()
                                .all(|v| v == &false)
                        {
                            buf.put_slice(&payload);
                            let mut packet = Packet::new_tcp(self.dst, self.src);
                            let tcp = packet.tcp().unwrap();
                            tcp.sequence_number = self.send_seq.nxt;
                            tcp.acknowledgment_number = self.recv_seq.nxt + payload.len() as u32;
                            tcp.window_size = self.recv_seq.wnd;
                            tcp.ack = true;
                            let b = packet.as_bytes();
                            let plen = payload.len();
                            let send = Box::pin(self.tun_sender.send(b)).poll_unpin(cx);
                            match send {
                                std::task::Poll::Ready(Ok(_)) => {
                                    dbg!(plen);
                                    self.recv_seq.nxt += plen as u32;
                                    return std::task::Poll::Ready(Ok(()));
                                }
                                std::task::Poll::Ready(Err(_)) => todo!(),
                                std::task::Poll::Pending => return std::task::Poll::Pending,
                            };
                        }
                        if tcp.fin
                            && tcp.ack
                            && [tcp.syn, tcp.psh, tcp.rst, tcp.urg, tcp.ece, tcp.cwr]
                                .iter()
                                .all(|v| v == &false)
                        {}
                    }
                    std::task::Poll::Ready(None) => {
                        dbg!("none");
                        return std::task::Poll::Ready(Ok(()));
                    }
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                }
            }
        }
    }
}

impl AsyncWrite for TunTcpStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let mut packet = Packet::new_tcp(self.dst, self.src);
        let tcp = packet.tcp().unwrap();
        tcp.sequence_number = self.send_seq.nxt;
        tcp.acknowledgment_number = self.recv_seq.nxt;
        tcp.window_size = self.recv_seq.wnd;
        tcp.psh = true;
        tcp.ack = true;

        let re = MTU - (14 + 20 + 20);
        let llen = if self.send_seq.wnd < re as u16 {
            self.send_seq.wnd as usize
        } else {
            re
        };

        packet.payload = buf.to_vec().iter().take(llen).cloned().collect();
        // dbg!(packet.payload.len());
        let b = packet.as_bytes();
        let plen = packet.payload.len();
        let send = Box::pin(self.tun_sender.send(b)).poll_unpin(cx);
        match send {
            std::task::Poll::Ready(Ok(_)) => {
                self.send_seq.nxt += plen as u32;
                // dbg!(plen);
                std::task::Poll::Ready(Ok(buf.len()))
            }
            std::task::Poll::Ready(Err(_)) => todo!(),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        // dbg!("flush");
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        dbg!("shutdown");
        std::task::Poll::Ready(Ok(()))
    }
}

#[derive(Debug, Clone)]
pub enum TunProtocol {
    Ipv4,
}
#[derive(Debug, Clone)]
pub enum TunFlags {
    Tun,
}

impl TunFlags {
    pub fn from(bytes: [u8; 2]) -> Result<Self, ()> {
        match bytes {
            [0x00, 0x00] => Ok(TunFlags::Tun),
            _ => Err(()),
        }
    }
}

impl TunProtocol {
    pub fn from(bytes: [u8; 2]) -> Result<Self, ()> {
        match bytes {
            [0x00, 0x02] => Ok(TunProtocol::Ipv4),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Ip {
    Ipv4(Ipv4Header),
}

impl Ip {
    pub fn source(&self) -> IpAddr {
        match self {
            Ip::Ipv4(ip) => ip.source.into(),
        }
    }
    pub fn destination(&self) -> IpAddr {
        match self {
            Ip::Ipv4(ip) => ip.destination.into(),
        }
    }
}
#[derive(Debug, Clone)]
pub enum Transport {
    Tcp(TcpHeader),
    Udp(UdpHeader),
}

#[derive(Debug, Clone)]
pub struct Packet {
    pub tun_flags: TunFlags,
    pub tun_protocol: TunProtocol,
    pub ip: Ip,
    pub transport: Transport,
    pub payload: Vec<u8>,
}

impl Packet {
    pub fn new_tcp(src: SocketAddr, dst: SocketAddr) -> Self {
        let mut tcp = TcpHeader::default();
        tcp.source_port = src.port();
        tcp.destination_port = dst.port();
        let mut ip = Ipv4Header::default();
        ip.time_to_live = 20;
        match (src.ip(), dst.ip()) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                ip.source = src.octets();
                ip.destination = dst.octets();
            }
            _ => todo!(),
        }
        ip.protocol = 6;
        Self {
            tun_flags: TunFlags::Tun,
            tun_protocol: TunProtocol::Ipv4,
            ip: Ip::Ipv4(ip),
            transport: Transport::Tcp(tcp),
            payload: vec![],
        }
    }
    pub async fn from_async_read<R: AsyncReadExt + Unpin>(mut reader: R) -> Self {
        let mut buf = vec![0u8; MTU];
        let pos = reader.read(&mut buf).await.unwrap();
        let tun_flags = TunFlags::from([buf[0], buf[1]]).unwrap();
        let tun_protocol = TunProtocol::from([buf[2], buf[3]]).unwrap();

        let packet = SlicedPacket::from_ip(&buf[4..pos]).unwrap();
        let payload = packet.payload.to_vec();
        let ipv4 = if let Some(etherparse::InternetSlice::Ipv4(ip, _)) = packet.ip {
            ip.to_header()
        } else {
            panic!("Not ipv4")
        };
        let transport = match packet.transport {
            Some(etherparse::TransportSlice::Tcp(tcp)) => Transport::Tcp(tcp.to_header()),
            Some(etherparse::TransportSlice::Udp(udp)) => Transport::Udp(udp.to_header()),
            _ => todo!(),
        };
        Self {
            tun_flags,
            tun_protocol,
            ip: Ip::Ipv4(ipv4),
            transport,
            payload,
        }
    }
    pub fn tcp(&mut self) -> Option<&mut TcpHeader> {
        match self.transport {
            Transport::Tcp(ref mut tcp) => Some(tcp),
            _ => None,
        }
    }
    pub fn is_tcp(&self) -> bool {
        matches!(&self.transport, Transport::Tcp(_))
    }
    #[allow(dead_code)]
    pub fn udp(&self) -> Option<&UdpHeader> {
        match &self.transport {
            Transport::Udp(udp) => Some(udp),
            _ => None,
        }
    }
    #[allow(dead_code)]
    pub fn is_udp(&self) -> bool {
        matches!(&self.transport, Transport::Udp(_))
    }
    pub fn get_src_address(&self) -> SocketAddr {
        let port = match &self.transport {
            Transport::Tcp(tcp) => tcp.source_port,
            Transport::Udp(udp) => udp.source_port,
        };
        SocketAddr::new(self.ip.source(), port)
    }
    pub fn get_dst_address(&self) -> SocketAddr {
        let port = match &self.transport {
            Transport::Tcp(tcp) => tcp.destination_port,
            Transport::Udp(udp) => udp.destination_port,
        };
        SocketAddr::new(self.ip.destination(), port)
    }
    pub fn get_network_tuple(&self) -> (SocketAddr, SocketAddr, bool) {
        (
            self.get_src_address(),
            self.get_dst_address(),
            self.is_tcp(),
        )
    }
    pub fn as_bytes(&mut self) -> Vec<u8> {
        let mut buf = vec![0u8; MTU];
        let mut cursor = Cursor::new(&mut buf[..]);
        std::io::Write::write(&mut cursor, &[0x00, 0x00, 0x00, 0x02]).unwrap();
        let ip = match &mut self.ip {
            Ip::Ipv4(ip) => {
                match &self.transport {
                    Transport::Tcp(t) => {
                        ip.payload_len = t.header_len() + self.payload.len() as u16
                    }
                    Transport::Udp(_) => todo!(),
                }
                ip.write(&mut cursor).unwrap();
                ip
            }
        };
        // self.ip.write(&mut cursor).unwrap();
        match &mut self.transport {
            Transport::Tcp(ref mut tcp) => {
                let checksum = tcp.calc_checksum_ipv4(ip, &self.payload).unwrap();
                tcp.checksum = checksum;
                tcp.write(&mut cursor).unwrap()
            }
            Transport::Udp(ref mut udp) => {
                let checksum = udp.calc_checksum_ipv4(ip, &self.payload).unwrap();
                udp.checksum = checksum;
                udp.write(&mut cursor).unwrap()
            }
        };
        std::io::Write::write(&mut cursor, &self.payload).unwrap();
        let p = cursor.position() as usize;

        // buf.shrink_to(cursor.position() as usize);
        buf[..p].to_vec()
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct SendSequence {
    una: u32, // unacknowledged sequence number
    nxt: u32, // next sequence number to be sent
    wnd: u16, // send window
    // up: u16,  // send urgent pointer
    wl1: u32, // segment sequence number used for last window update
    wl2: u32, // segment acknowledgment number used for last window update
}
#[derive(Debug)]
pub struct RecvSequence {
    nxt: u32, // next sequence number expected on an incoming segments, and is the left or lower edge of the receive window
    wnd: u16, // receive window
              // up: u16,  // receive urgent pointer
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum ConnectionState {
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
}
