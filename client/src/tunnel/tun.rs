use std::{
    io,
    net::{IpAddr, Ipv4Addr},
    pin::Pin,
    sync::Arc,
};

use futures_util::{Future, FutureExt, StreamExt};
use ipstack::stream::IpStackStream;
use net_route::{Handle, Route};
// use netstack_lwip::NetStack;
use tokio::{
    signal,
    sync::{
        mpsc::{self, UnboundedSender},
        Notify,
    },
};
use tracing::warn;

use crate::error::ClientError;

// const MTU: usize = 1500;
const MTU: usize = 65535;

#[allow(unused)] // temp - todo implement map addr
pub struct TunListener {
    // tcp: netstack_lwip::TcpListener,
    // udp: TunUdpListener,
    // _task: tokio::task::JoinHandle<Result<(), io::Error>>,
    ipstack: ipstack::IpStack,
    route: Option<TunRoute>,
    local_addr: IpAddr,
}

pub enum RouteCommand {
    Add(IpAddr),
    Del(IpAddr),
}

pub struct TunRoute {
    _task: tokio::task::JoinHandle<Result<(), io::Error>>,
    route_sender: UnboundedSender<RouteCommand>,
    my_routes_sender: UnboundedSender<(bool, Arc<Notify>)>,
}

trait SignalTrait: Future<Output = Option<()>> + Send {}
impl<T> SignalTrait for T where T: Future<Output = Option<()>> + Send {}

impl TunRoute {
    pub async fn new(local_addr: Ipv4Addr, _ifaceid: u32) -> Result<Self, io::Error> {
        let handle: Handle = Handle::new()?;
        let Some(default_gw) = handle.default_route().await? else {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "No default gateway found",
            ));
        };

        let (my_routes_sender, mut my_routes_receiver) =
            mpsc::unbounded_channel::<(bool, Arc<Notify>)>();
        let (route_tx, mut route_rx) = mpsc::unbounded_channel::<RouteCommand>();
        let mut signals: Vec<Pin<Box<dyn SignalTrait>>> = Vec::new();

        #[cfg(target_family = "windows")]
        {
            signals.push(Box::pin(async move {
                if let Ok(mut s) = signal::windows::ctrl_c() {
                    s.recv().await
                } else {
                    None
                }
            }));
            signals.push(Box::pin(async move {
                if let Ok(mut s) = signal::windows::ctrl_close() {
                    s.recv().await
                } else {
                    None
                }
            }));
        }

        #[cfg(target_family = "unix")]
        for signal_number in [1, 2, 3, 6, 15, 20] {
            signals.push(Box::pin(async move {
                if let Ok(mut s) =
                    signal::unix::signal(signal::unix::SignalKind::from_raw(signal_number))
                {
                    s.recv().await
                } else {
                    None
                }
            }));
        }

        let mut signal_stream = futures_util::future::select_all(signals).into_stream();
        let task = tokio::spawn(async move {
            let mut init = false;
            let mut my_routes = false;
            let mut routes = Vec::new();
            loop {
                tokio::select! {
                    _ = signal_stream.next() => {
                        if my_routes {
                            for route in &routes {
                                let _ = handle.delete(route).await;
                            }
                            handle.add(&default_gw).await.unwrap();
                        }
                        std::process::exit(0x0)
                    },
                    Some((route_action, notify)) = my_routes_receiver.recv() => {
                        if route_action && !my_routes{
                            if !init {
                                #[cfg(target_family = "windows")]
                                routes.push(Route::new(default_gw.destination, 0).with_gateway(IpAddr::V4(local_addr)).with_ifindex(_ifaceid));
                                #[cfg(target_family = "unix")]
                                routes.push(Route::new(default_gw.destination, 0).with_gateway(IpAddr::V4(local_addr)));
                                init = true;
                            }
                            handle.delete(&default_gw).await?;
                            for route in &routes {
                                handle.add(route).await.unwrap(); // handle!!
                            }
                            my_routes = true;
                        }else if !route_action && my_routes{
                            for route in &routes {
                                let _ = handle.delete(route).await;
                            }
                            handle.add(&default_gw).await.unwrap();
                            my_routes = false;
                        }
                        notify.notify_waiters();
                    },
                    Some(cmd) = route_rx.recv() =>{
                        match cmd {
                            RouteCommand::Add(ip) => {
                                #[cfg(target_family = "windows")]
                                let r = Route::new(ip, 32).with_gateway(default_gw.gateway.unwrap()).with_ifindex(default_gw.ifindex.unwrap());
                                #[cfg(target_family = "unix")]
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
    pub async fn my_routes(&self, my_routes: bool) {
        let notify = Arc::new(Notify::new());
        let _ = self.my_routes_sender.send((my_routes, notify.clone()));
        notify.notified().await;
    }
}

impl TunListener {
    pub async fn new(local_addr: IpAddr) -> Result<Self, ClientError> {
        #[cfg(not(target_family = "windows"))]
        let mut config = tun::Configuration::default();
        let ipv4 = match local_addr {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_v6) => {
                todo!()
            }
        };
        #[cfg(not(target_family = "windows"))]
        config
            .address(ipv4)
            // .destination(ipv4)
            .netmask((255, 255, 255, 255))
            .mtu(MTU as i32)
            .up();
        #[cfg(target_os = "linux")]
        config.platform(|config| {
            config.packet_information(true);
        });
        #[cfg(not(target_family = "windows"))]
        let device = tun::create_as_async(&config).map_err(ClientError::UnableToCreateTun)?;
        #[cfg(target_family = "windows")]
        let device = wintun::WinTunDevice::new(ipv4, Ipv4Addr::new(255, 255, 255, 255));
        
        #[cfg(not(target_family = "windows"))]
        let route = TunRoute::new(ipv4, 0);

        #[cfg(target_family = "windows")]
        let route = TunRoute::new(ipv4, device.get_adapter_index());


        let route = route
            .await
            .map_err(|e| {
                warn!("Unable to manage routes");
                e
            })
            .ok();
        let ip_stack = ipstack::IpStack::new(device, MTU as u16, cfg!(target_family = "unix"));
        Ok(Self {
            ipstack: ip_stack,
            route,
            local_addr,
        })
    }
    pub async fn accept(&mut self) -> Result<IpStackStream, ClientError> {
        Ok(self.ipstack.accept().await?)
    }
    pub fn route_sender(&self) -> Option<UnboundedSender<RouteCommand>> {
        self.route.as_ref().map(|f| f.get_sender())
    }
    pub async fn my_routes(&self, my_routes: bool) {
        if let Some(route) = self.route.as_ref() {
            route.my_routes(my_routes).await;
        }
    }
}

#[cfg(target_family = "windows")]
mod wintun {
    use std::{net::Ipv4Addr, sync::Arc, task::ready, thread};

    use tokio::io::{AsyncRead, AsyncWrite};

    pub struct WinTunDevice {
        session: Arc<wintun::Session>,
        receiver: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
        iface_id: u32,
        _task: thread::JoinHandle<()>,
    }

    impl WinTunDevice {
        pub fn new(ip: Ipv4Addr, netmask: Ipv4Addr) -> WinTunDevice {
            let wintun = unsafe { wintun::load() }.unwrap();
            let adapter =
                wintun::Adapter::create(&wintun, "Narrowlink", "Narrowlink", None).unwrap();
            adapter.set_address(ip).unwrap();
            adapter.set_netmask(netmask).unwrap();
            let iface_id = adapter.get_adapter_index().unwrap();
            // adapter.set_gateway(Some(ip)).unwrap();
            let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY).unwrap());
            let (receiver_tx, receiver_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
            let session_reader = session.clone();
            let task = thread::spawn(move || {
                loop {
                    let packet = session_reader.receive_blocking().unwrap();
                    let bytes = packet.bytes().to_vec();
                    // dbg!(&bytes);
                    receiver_tx.send(bytes).unwrap();
                }
            });
            WinTunDevice {
                session,
                receiver: receiver_rx,
                iface_id,
                _task: task,
            }
        }
        pub(crate) fn get_adapter_index(&self) -> u32 {
            self.iface_id
        }
    }

    impl AsyncRead for WinTunDevice {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            match ready!(self.receiver.poll_recv(cx)) {
                Some(bytes) => {
                    buf.put_slice(&bytes);
                    std::task::Poll::Ready(Ok(()))
                }
                None => std::task::Poll::Ready(Ok(())),
            }
        }
    }

    impl AsyncWrite for WinTunDevice {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<Result<usize, std::io::Error>> {
            let mut write_pack = self.session.allocate_send_packet(buf.len() as u16)?;
            write_pack.bytes_mut().copy_from_slice(buf.as_ref());
            self.session.send_packet(write_pack);
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), std::io::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), std::io::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
    }
}
