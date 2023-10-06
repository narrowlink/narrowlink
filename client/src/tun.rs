use std::{
    collections::{hash_map::Entry, HashMap},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    time::SystemTime,
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

const UDP_TIMEOUT: u64 = 5;
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
    local_addr: IpAddr,
    remote_addr: Option<IpAddr>,
}

pub enum RouteCommand {
    Add(IpAddr),
    Del(IpAddr),
}

pub struct TunRoute {
    _task: tokio::task::JoinHandle<Result<(), std::io::Error>>,
    route_sender: UnboundedSender<RouteCommand>,
    my_routes_sender: UnboundedSender<bool>,
}

impl TunRoute {
    pub async fn new(local_addr: Ipv4Addr) -> Result<Self, std::io::Error> {
        let handle: Handle = Handle::new()?;
        let Some(default_gw) = handle.default_route().await? else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "No default gateway found",
            ));
        };
        let (my_routes_sender, mut my_routes_receiver) = mpsc::unbounded_channel::<bool>();
        let (route_tx, mut route_rx) = mpsc::unbounded_channel::<RouteCommand>();
        use signal_hook::consts::signal::{SIGABRT, SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGTSTP};
        let mut signals =
            signal_hook_tokio::Signals::new([SIGTERM, SIGINT, SIGQUIT, SIGTSTP, SIGABRT, SIGHUP])?;
        let task = tokio::spawn(async move {
            let mut init = false;
            let mut my_routes = false;
            let mut routes = Vec::new();
            loop {
                tokio::select! {
                    Some(signal) = signals.next() => {
                        if (signal == SIGTERM || signal == SIGINT || signal == SIGQUIT || signal == SIGTSTP || signal == SIGABRT || signal == SIGHUP) && my_routes {
                            for route in &routes {
                                handle.delete(route).await.unwrap();
                            }
                            handle.add(&default_gw).await.unwrap();
                        }
                        std::process::exit(0x0)
                    },
                    Some(route_action) = my_routes_receiver.recv() => {
                        if route_action && !my_routes{
                            if !init {
                                routes.push(Route::new(default_gw.destination, 0).with_gateway(IpAddr::V4(local_addr)));
                                init = true;
                            }
                            handle.delete(&default_gw).await?;
                            for route in &routes {
                                handle.add(route).await.unwrap();
                            }
                            my_routes = true;
                        }else if !route_action && my_routes{
                            for route in &routes {
                                handle.delete(route).await.unwrap();
                            }
                            handle.add(&default_gw).await.unwrap();
                            my_routes = false;
                        }
                    },
                    Some(cmd) = route_rx.recv() =>{
                        match cmd {
                            RouteCommand::Add(ip) => {
                                let r = Route::new(ip, 32).with_gateway(default_gw.gateway.unwrap());
                                if my_routes {
                                    let _ = handle.add(&r).await;
                                }
                                routes.push(r);

                            },
                            RouteCommand::Del(ip) => {
                                if let Some(index) = routes.iter().position(|x| x.destination == ip){
                                    if my_routes {
                                        handle.delete(&routes[index]).await.unwrap();
                                    }
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
            my_routes_sender,
        })
    }
    pub fn get_sender(&self) -> UnboundedSender<RouteCommand> {
        self.route_sender.clone()
    }
    pub fn my_routes(&self, my_routes: bool) {
        let _ = self.my_routes_sender.send(my_routes);
    }
}

impl TunListener {
    pub async fn new(local_addr: IpAddr, remote_addr: Option<IpAddr>) -> Self {
        let mut config = tun::Configuration::default();

        let ipv4 = match local_addr {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_v6) => {
                todo!()
            }
        };
        config
            .address(ipv4)
            .destination(ipv4)
            // .netmask((255, 255, 255, 255))
            .mtu(MTU as i32)
            .up();
        let device = tun::create_as_async(&config).unwrap();
        let route = TunRoute::new(ipv4)
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
            local_addr,
            remote_addr,
        }
    }
    pub async fn accept(&mut self) -> Result<(TunStream, SocketAddr), ClientError> {
        loop {
            tokio::select! {
                stream = self.udp.accept() => {
                    let mut addr = stream.get_dst_addr();
                    if addr.ip() == self.local_addr {
                        if let Some(remote_addr) = self.remote_addr {
                            addr = SocketAddr::new(remote_addr, addr.port());
                        }
                    }
                    return Ok((TunStream::Udp(stream), addr));
                }
                res = self.tcp.next() => {
                    let (stream, _src_addr, mut dst_adr) = res.unwrap();
                    if dst_adr.ip() == self.local_addr {
                        if let Some(remote_addr) = self.remote_addr {
                            dst_adr = SocketAddr::new(remote_addr, dst_adr.port());
                        }
                    }
                    return Ok((TunStream::Tcp(TunTcpStream{inner:stream}), dst_adr));
                }
            }
        }
    }
    pub fn route_sender(&self) -> Option<UnboundedSender<RouteCommand>> {
        self.route.as_ref().map(|f| f.get_sender())
    }
    pub fn my_routes(&self, my_routes: bool) {
        if let Some(route) = self.route.as_ref() {
            route.my_routes(my_routes);
        }
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
    timout_rx: mpsc::Receiver<(SocketAddr, SocketAddr)>,
    timout_tx: mpsc::Sender<(SocketAddr, SocketAddr)>,
}

impl TunUdpListener {
    pub fn new(inner: Box<netstack_lwip::UdpSocket>, packet_sender: mpsc::Sender<Vec<u8>>) -> Self {
        let (timout_tx, timout_rx) = mpsc::channel::<(SocketAddr, SocketAddr)>(10);
        Self {
            inner,
            packet_sender,
            streams: HashMap::new(),
            timout_rx,
            timout_tx,
        }
    }
    pub async fn accept(&mut self) -> TunUdpStream {
        loop {
            tokio::select! {
                Some((data, src_addr, dst_addr)) = self.inner.next() =>{
                    match self.streams.entry((src_addr, dst_addr)) {
                        Entry::Occupied(stream) => {
                            stream.get().send(data).await.unwrap();
                        }
                        Entry::Vacant(v) => {
                            let stream = TunUdpStream::new(src_addr, dst_addr, self.packet_sender.clone(),self.timout_tx.clone());
                            let sender = stream.sender();
                            sender.send(data).await.unwrap();
                            v.insert(sender);
                            return stream;
                        }
                    }
                }
                Some((src_addr, dst_addr)) = self.timout_rx.recv() =>{
                    self.streams.remove(&(src_addr, dst_addr));
                }
            }
        }
    }
}

pub struct TunUdpStream {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::Sender<Vec<u8>>,
    packet_sender: mpsc::Sender<Vec<u8>>,
    last_seen: SystemTime,
    timout_checker: tokio::time::Interval,
    timout_tx: mpsc::Sender<(SocketAddr, SocketAddr)>,
    timeout: bool,
}

impl TunUdpStream {
    pub fn new(
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        packet_sender: mpsc::Sender<Vec<u8>>,
        timout_tx: mpsc::Sender<(SocketAddr, SocketAddr)>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(10);
        Self {
            src_addr,
            dst_addr,
            rx,
            tx,
            packet_sender,
            last_seen: SystemTime::now(),
            timout_checker: tokio::time::interval(tokio::time::Duration::from_secs(UDP_TIMEOUT)),
            timout_tx,
            timeout: false,
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
        loop {
            if self.timeout {
                return match Box::pin(self.timout_tx.send((self.src_addr, self.dst_addr)))
                    .poll_unpin(cx)
                {
                    std::task::Poll::Ready(_) => std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "Timed out",
                    ))),
                    std::task::Poll::Pending => std::task::Poll::Pending,
                };
            };
            match self.rx.poll_recv(cx) {
                std::task::Poll::Ready(Some(v)) => {
                    buf.put_slice(&v);
                    self.last_seen = SystemTime::now();
                    return std::task::Poll::Ready(Ok(()));
                }
                std::task::Poll::Ready(None) => {
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "Broken Pipe",
                    )))
                }
                std::task::Poll::Pending => match self.timout_checker.poll_tick(cx) {
                    std::task::Poll::Ready(_) => {
                        if SystemTime::now()
                            .duration_since(self.last_seen)
                            .ok()
                            .filter(|d| d.as_secs() > UDP_TIMEOUT)
                            .is_some()
                        {
                            self.timeout = true;
                        }
                        continue;
                    }
                    _ => return std::task::Poll::Pending,
                },
            }
        }
    }
}

impl AsyncWrite for TunUdpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
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
        self.last_seen = SystemTime::now();
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
