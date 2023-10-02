use std::{
    collections::{hash_map::Entry, HashMap},
    net::{IpAddr, SocketAddr},
    pin::Pin,
};

use futures_util::{FutureExt, SinkExt, StreamExt};
use net_route::{Handle, Route};
use netstack_lwip::NetStack;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc::{self, UnboundedSender},
};
use tracing::warn;

use crate::error::ClientError;

const MTU: usize = 1500;

pub enum TunStream {
    Tcp(TunTcpStream),
    Udp(TunUdpStream),
}
pub struct TunListener {
    tcp: netstack_lwip::TcpListener,
    udp: TunUdpListener,
    _task: tokio::task::JoinHandle<Result<(), std::io::Error>>,
    route: Option<TunRoute>,
}

pub enum RouteCommand {
    Add(IpAddr),
    Del(IpAddr),
}

pub struct TunRoute {
    _task: tokio::task::JoinHandle<Result<(), std::io::Error>>,
    route_sender: UnboundedSender<RouteCommand>,
}

impl TunRoute {
    pub async fn new() -> Result<Self, std::io::Error> {
        let handle: Handle = Handle::new()?;
        let Some(default_gw) = handle.default_route().await? else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "No default gateway found",
            ));
        };

        let (tx, mut rx) = mpsc::unbounded_channel();
        let (route_tx, mut route_rx) = mpsc::unbounded_channel::<RouteCommand>();
        ctrlc::set_handler(move || tx.send(()).expect("Could not send signal on channel."))
            .expect("Error setting Ctrl-C handler");
        let task = tokio::spawn(async move {
            let mut init = false;
            let mut routes = Vec::new();
            loop {
                tokio::select! {
                    _ = rx.recv() => {
                        for route in routes {
                            handle.delete(&route).await.unwrap();
                        }
                        handle.add(&default_gw).await.unwrap();
                        std::process::exit(0x0)
                    },
                    Some(cmd) = route_rx.recv() =>{
                        if !init {
                            handle.delete(&default_gw).await?;
                            let new_default_gateway =
                                Route::new(default_gw.destination, 0).with_gateway("10.0.0.1".parse().unwrap());
                            handle.add(&new_default_gateway).await.unwrap();
                            routes.push(new_default_gateway);
                            init = true;
                        }
                        match cmd {
                            RouteCommand::Add(ip) => {
                                let r = Route::new(ip, 32).with_gateway(default_gw.gateway.unwrap());
                                if handle.add(&r).await.is_ok(){
                                    routes.push(r);
                                }
                            },
                            RouteCommand::Del(ip) => {
                                if let Some(index) = routes.iter().position(|x| x.destination == ip){
                                    routes.remove(index);
                                }
                            }
                        }
                        continue;
                    }
                };
            }
        });
        Ok(Self {
            _task: task,
            route_sender: route_tx,
        })
    }
    pub fn get_sender(&self) -> UnboundedSender<RouteCommand> {
        self.route_sender.clone()
    }
}

impl TunListener {
    pub async fn new() -> Self {
        let mut config = tun::Configuration::default();

        config
            .address((10, 0, 0, 1))
            .destination((10, 0, 0, 1))
            // .netmask((255, 255, 255, 255))
            .mtu(MTU as i32)
            .up();
        let device = tun::create_as_async(&config).unwrap();
        let route = TunRoute::new()
            .await
            .map_err(|e| {
                warn!("Unable to manage routes");
                e
            })
            .ok();
        let (stack, tcp, udp) = NetStack::new().unwrap();
        let (udp_writer, mut udp_reader) = mpsc::channel::<Vec<u8>>(10);
        let task = tokio::spawn(async move {
            let (mut stack_sink, mut stack_stream) = stack.split();
            let (mut reader, mut writer) = tokio::io::split(device);
            let mut buffer = vec![0u8; MTU];
            loop {
                tokio::select! {
                    res = stack_stream.next() => {
                        match res {
                            Some(v)=>writer.write_all(&v.map(|mut pkt|{pkt.splice(0..0, vec![0x00, 0x00, 0x00, 0x02]);pkt})?).await?,
                            None=>{
                                let _ = stack_sink.close().await;
                                let _ = writer.shutdown().await;
                                return Ok::<(),std::io::Error>(())
                            }
                        };
                    },
                    res = udp_reader.recv() => {

                        match res {
                            Some(mut v)=>writer.write_all({v.splice(0..0, vec![0x00, 0x00, 0x00, 0x02]);&v}).await?,
                            None=>{
                                let _ = stack_sink.close().await;
                                let _ = writer.shutdown().await;
                                return Ok::<(),std::io::Error>(())
                            }
                        };
                    },
                    res = reader.read(&mut buffer) => {
                        match res {
                            Ok(len)=>stack_sink.send((buffer[4..len]).to_vec()).await?,
                            Err(e)=>{
                                let _ = stack_sink.close().await;
                                let _ = writer.shutdown().await;
                                return Err(e)
                            }
                        };
                    },
                }
            }
        });

        Self {
            tcp,
            udp: TunUdpListener::new(udp, udp_writer),
            _task: task,
            route,
        }
    }
    pub async fn accept(&mut self) -> Result<(TunStream, SocketAddr), ClientError> {
        loop {
            tokio::select! {
                stream = self.udp.accept() => {
                    let addr = stream.get_dst_addr();
                    return Ok((TunStream::Udp(stream), addr));
                }
                res = self.tcp.next() => {
                    let (stream, _src_addr, dst_adr) = res.unwrap();
                    return Ok((TunStream::Tcp(TunTcpStream{inner:stream}), dst_adr));
                }
            }
        }
    }
    pub fn route_sender(&self) -> Option<UnboundedSender<RouteCommand>> {
        self.route.as_ref().map(|f| f.get_sender())
    }
}

pub struct TunTcpStream {
    inner: netstack_lwip::TcpStream,
}

impl AsyncRead for TunTcpStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TunTcpStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub struct TunUdpListener {
    inner: Box<netstack_lwip::UdpSocket>,
    packet_sender: mpsc::Sender<Vec<u8>>,
    streams: HashMap<(SocketAddr, SocketAddr), mpsc::Sender<Vec<u8>>>,
}

impl TunUdpListener {
    pub fn new(inner: Box<netstack_lwip::UdpSocket>, packet_sender: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            inner,
            packet_sender,
            streams: HashMap::new(),
        }
    }
    pub async fn accept(&mut self) -> TunUdpStream {
        while let Some((data, src_addr, dst_addr)) = self.inner.next().await {
            match self.streams.entry((src_addr, dst_addr)) {
                Entry::Occupied(stream) => {
                    stream.get().send(data).await.unwrap();
                }
                Entry::Vacant(v) => {
                    let stream = TunUdpStream::new(src_addr, dst_addr, self.packet_sender.clone());
                    let sender = stream.sender();
                    sender.send(data).await.unwrap();
                    v.insert(sender);
                    return stream;
                }
            }
        }
        todo!()
    }
}

pub struct TunUdpStream {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::Sender<Vec<u8>>,
    packet_sender: mpsc::Sender<Vec<u8>>,
}

impl TunUdpStream {
    pub fn new(
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        packet_sender: mpsc::Sender<Vec<u8>>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(10);
        Self {
            src_addr,
            dst_addr,
            rx,
            tx,
            packet_sender,
        }
    }
    pub fn sender(&self) -> mpsc::Sender<Vec<u8>> {
        self.tx.clone()
    }
    pub fn get_src_addr(&self) -> SocketAddr {
        self.src_addr
    }
    pub fn get_dst_addr(&self) -> SocketAddr {
        self.dst_addr
    }
}

impl AsyncRead for TunUdpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(v)) => {
                buf.put_slice(&v);
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Broken Pipe",
            ))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl AsyncWrite for TunUdpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let mut buffer = vec![0u8; MTU];
        let mut cursor = std::io::Cursor::new(&mut buffer);
        let addr = match self.dst_addr {
            SocketAddr::V4(v4) => v4.ip().octets(),
            SocketAddr::V6(_v6) => {
                todo!()
            }
        };

        let payload = if buf.len() < MTU - 32 {
            buf
        } else {
            &buf[0..MTU - 32]
        };

        let packet = etherparse::PacketBuilder::ipv4(
            addr,          //source ip
            [10, 0, 0, 1], //desitionation ip
            20,
        ) //time to life
        .udp(
            self.dst_addr.port(), //source port
            self.src_addr.port(),
        );
        let len = packet.size(payload.len());
        packet.write(&mut cursor, payload).unwrap();
        // buffer.splice(0..0, vec![0x00, 0x00, 0x00, 0x01]);
        match Box::pin(self.packet_sender.send(buffer[..len].to_vec())).poll_unpin(cx) {
            std::task::Poll::Ready(_) => std::task::Poll::Ready(Ok(payload.len())),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}
