use std::{
    io,
    net::{IpAddr, Ipv4Addr},
    pin::Pin,
    time::Duration,
};

use futures_util::{Future, FutureExt, StreamExt};
use ipstack::IpStackStream;
use route_manager::{AsyncRouteManager, Route};
use tokio::{
    signal,
    sync::{
        mpsc::{self, UnboundedSender},
        oneshot,
    },
};
use tracing::warn;

use crate::error::ClientError;

// const MTU: usize = 1500;
const MTU: usize = 65535;

#[allow(unused)]
pub struct TunListener {
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
    my_routes_sender: UnboundedSender<(bool, oneshot::Sender<io::Result<()>>)>,
}

trait RouteManager {
    async fn add(&mut self, route: &Route) -> io::Result<()>;
    async fn delete(&mut self, route: &Route) -> io::Result<()>;
}

impl RouteManager for AsyncRouteManager {
    async fn add(&mut self, route: &Route) -> io::Result<()> {
        AsyncRouteManager::add(self, route).await
    }
    async fn delete(&mut self, route: &Route) -> io::Result<()> {
        AsyncRouteManager::delete(self, route).await
    }
}

struct RouteState {
    original: Route,
    original_removed: bool,
    installed: Vec<Route>,
}

impl RouteState {
    async fn restore(&mut self, manager: &mut impl RouteManager) -> io::Result<()> {
        let mut errors = Vec::new();
        let mut remaining = Vec::new();
        for route in self.installed.drain(..).rev() {
            if let Err(error) = manager.delete(&route).await {
                errors.push(format!("remove {route}: {error}"));
                remaining.push(route);
            }
        }
        self.installed = remaining;
        if self.original_removed {
            match manager.add(&self.original).await {
                Ok(()) => self.original_removed = false,
                Err(error) => errors.push(format!("restore default route: {error}")),
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(errors.join("; ")))
        }
    }

    async fn activate(
        &mut self,
        manager: &mut impl RouteManager,
        routes: &[Route],
    ) -> io::Result<()> {
        // Finish any previous incomplete rollback before trying another activation.
        if self.original_removed || !self.installed.is_empty() {
            self.restore(manager).await?;
        }
        manager.delete(&self.original).await?;
        self.original_removed = true;
        for route in routes {
            if let Err(error) = manager.add(route).await {
                return match self.restore(manager).await {
                    Ok(()) => Err(error),
                    Err(rollback) => Err(io::Error::other(format!(
                        "{error}; rollback failed: {rollback}"
                    ))),
                };
            }
            self.installed.push(route.clone());
        }
        Ok(())
    }
}

trait SignalTrait: Future<Output = Option<()>> + Send {}
impl<T> SignalTrait for T where T: Future<Output = Option<()>> + Send {}

fn default_route(routes: Vec<Route>) -> Option<Route> {
    let candidates: Vec<_> = routes
        .into_iter()
        .filter(|route| route.prefix() == 0 && route.destination().is_unspecified())
        .filter(|route| {
            cfg!(target_os = "linux") || !route.gateway().is_some_and(|ip| ip.is_unspecified())
        })
        .collect();
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    let candidates = {
        let mut candidates = candidates;
        #[cfg(target_os = "windows")]
        candidates.sort_by_key(|route| route.metric());
        #[cfg(target_os = "linux")]
        candidates.sort_by_key(|route| route.destination().is_ipv6());
        candidates
    };
    candidates.into_iter().next()
}

#[cfg(test)]
mod route_tests {
    use super::*;
    use std::collections::HashSet;

    #[derive(Default)]
    struct FakeManager {
        routes: HashSet<IpAddr>,
        fail_add: Option<IpAddr>,
        fail_delete: Option<IpAddr>,
    }

    impl RouteManager for FakeManager {
        async fn add(&mut self, route: &Route) -> io::Result<()> {
            if self.fail_add == Some(route.destination()) {
                return Err(io::Error::other("add failed"));
            }
            self.routes.insert(route.destination());
            Ok(())
        }
        async fn delete(&mut self, route: &Route) -> io::Result<()> {
            if self.fail_delete == Some(route.destination()) {
                return Err(io::Error::other("delete failed"));
            }
            self.routes.remove(&route.destination());
            Ok(())
        }
    }

    fn route(ip: &str) -> Route {
        Route::new(ip.parse().unwrap(), 0)
    }

    #[tokio::test]
    async fn failed_activation_restores_original_and_removes_added_routes() {
        let original = route("0.0.0.0");
        let first = route("192.0.2.1");
        let failed = route("192.0.2.2");
        let mut manager = FakeManager {
            routes: HashSet::from([original.destination()]),
            fail_add: Some(failed.destination()),
            ..Default::default()
        };
        let mut state = RouteState {
            original: original.clone(),
            original_removed: false,
            installed: vec![],
        };
        assert!(state
            .activate(&mut manager, &[first, failed])
            .await
            .is_err());
        assert_eq!(manager.routes, HashSet::from([original.destination()]));
        assert!(!state.original_removed && state.installed.is_empty());
    }

    #[tokio::test]
    async fn failed_restore_can_be_retried() {
        let original = route("0.0.0.0");
        let tunnel = route("192.0.2.1");
        let mut manager = FakeManager {
            routes: HashSet::from([original.destination()]),
            ..Default::default()
        };
        let mut state = RouteState {
            original: original.clone(),
            original_removed: false,
            installed: vec![],
        };
        state.activate(&mut manager, &[tunnel]).await.unwrap();
        manager.fail_add = Some(original.destination());
        assert!(state.restore(&mut manager).await.is_err());
        assert!(state.original_removed);
        manager.fail_add = None;
        state.restore(&mut manager).await.unwrap();
        assert_eq!(manager.routes, HashSet::from([original.destination()]));
    }

    #[tokio::test]
    async fn failed_route_removal_is_retained_for_retry() {
        let original = route("0.0.0.0");
        let tunnel = route("192.0.2.1");
        let mut manager = FakeManager {
            routes: HashSet::from([original.destination()]),
            ..Default::default()
        };
        let mut state = RouteState {
            original: original.clone(),
            original_removed: false,
            installed: vec![],
        };
        state
            .activate(&mut manager, &[tunnel.clone()])
            .await
            .unwrap();
        manager.fail_delete = Some(tunnel.destination());
        assert!(state.restore(&mut manager).await.is_err());
        assert_eq!(state.installed.len(), 1);
        manager.fail_delete = None;
        state.restore(&mut manager).await.unwrap();
        assert_eq!(manager.routes, HashSet::from([original.destination()]));
    }

    #[tokio::test]
    async fn deletion_failure_keeps_original_route() {
        let original = route("0.0.0.0");
        let mut manager = FakeManager {
            routes: HashSet::from([original.destination()]),
            fail_delete: Some(original.destination()),
            ..Default::default()
        };
        let mut state = RouteState {
            original: original.clone(),
            original_removed: false,
            installed: vec![],
        };
        assert!(state
            .activate(&mut manager, &[route("192.0.2.1")])
            .await
            .is_err());
        assert_eq!(manager.routes, HashSet::from([original.destination()]));
        assert!(!state.original_removed && state.installed.is_empty());
    }

    #[tokio::test]
    async fn stopped_route_task_returns_error() {
        let (sender, receiver) = mpsc::unbounded_channel();
        drop(receiver);
        let (route_sender, _) = mpsc::unbounded_channel();
        let route = TunRoute {
            _task: tokio::spawn(async { Ok(()) }),
            route_sender,
            my_routes_sender: sender,
        };
        assert!(route.my_routes(true).await.is_err());
    }

    #[test]
    fn selects_default_instead_of_specific_route() {
        let specific = Route::new("192.0.2.0".parse().unwrap(), 24);
        let default =
            Route::new("0.0.0.0".parse().unwrap(), 0).with_gateway("192.0.2.1".parse().unwrap());
        let selected = default_route(vec![specific, default]).unwrap();
        assert_eq!(selected.gateway(), Some("192.0.2.1".parse().unwrap()));
        assert!(default_route(vec![Route::new("192.0.2.0".parse().unwrap(), 24)]).is_none());
    }
}

impl TunRoute {
    pub async fn new(local_addr: Ipv4Addr, _ifaceid: u32) -> Result<Self, io::Error> {
        let mut handle = AsyncRouteManager::new()?;
        let Some(default_gw) = default_route(handle.list().await?) else {
            return Err(io::Error::other("No default gateway found"));
        };

        let (my_routes_sender, mut my_routes_receiver) =
            mpsc::unbounded_channel::<(bool, oneshot::Sender<io::Result<()>>)>();
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
            let mut state = RouteState {
                original: default_gw.clone(),
                original_removed: false,
                installed: Vec::new(),
            };
            let mut init = false;
            let mut my_routes = false;
            let mut routes = Vec::new();
            loop {
                tokio::select! {
                    _ = signal_stream.next() => {
                        if let Err(e) = state.restore(&mut handle).await {
                            warn!("Unable to recover routes: {}", e);
                        }
                        std::process::exit(0x0)
                    },
                    Some((route_action, response)) = my_routes_receiver.recv() => {
                        let result = if route_action && !my_routes{
                            if !init {
                                #[cfg(target_family = "windows")]
                                routes.push(Route::new(default_gw.destination(), 0).with_gateway(IpAddr::V4(local_addr)).with_if_index(_ifaceid));
                                #[cfg(target_family = "unix")]
                                routes.push(Route::new(default_gw.destination(), 0).with_gateway(IpAddr::V4(local_addr)));
                                init = true;
                            }
                            let result = state.activate(&mut handle, &routes).await;
                            my_routes = result.is_ok();
                            result
                        }else if !route_action && my_routes{
                            let result = state.restore(&mut handle).await;
                            if result.is_ok() { my_routes = false; }
                            result
                        } else if !route_action {
                            state.restore(&mut handle).await
                        } else { Ok(()) };
                        let _ = response.send(result);
                    },
                    Some(cmd) = route_rx.recv() =>{
                        match cmd {
                            RouteCommand::Add(ip) => {
                                let Some(gateway_address) = default_gw.gateway() else{
                                    warn!("No default gateway found");
                                    continue;
                                };
                                #[cfg(target_family = "windows")]
                                let Some(gateway_ifindex) = default_gw.if_index() else{
                                    warn!("Unable to get default gateway interface index");
                                    continue;
                                };
                                #[cfg(target_family = "windows")]
                                let r = Route::new(ip, 32).with_gateway(gateway_address).with_if_index(gateway_ifindex);
                                #[cfg(target_family = "unix")]
                                let r = Route::new(ip, 32).with_gateway(gateway_address);
                                if my_routes {
                                    match handle.add(&r).await {
                                        Ok(()) => state.installed.push(r.clone()),
                                        Err(e) => { warn!("Unable to add route: {}", e); continue; }
                                    }
                                }
                                routes.push(r);

                            },
                            RouteCommand::Del(ip) => {
                                if let Some(index) = routes.iter().position(|x| x.destination() == ip){
                                    if my_routes {
                                        if let Err(e) = handle.delete(&routes[index]).await{
                                            warn!("Unable to delete route: {}", e);
                                            continue;
                                        }
                                        if let Some(i) = state.installed.iter().position(|r| r.destination() == ip) { state.installed.remove(i); }
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
    pub async fn my_routes(&self, my_routes: bool) -> io::Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.my_routes_sender
            .send((my_routes, sender))
            .map_err(|_| io::Error::other("route task stopped"))?;
        receiver
            .await
            .map_err(|_| io::Error::other("route task stopped"))?
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
            .destination(ipv4)
            .netmask((255, 255, 255, 255))
            .mtu(MTU as u16)
            .up();
        #[cfg(target_os = "linux")]
        config.platform(|config| {
            config.packet_information(true);
        });
        #[cfg(not(target_family = "windows"))]
        let device = tun::create_as_async(&config).map_err(ClientError::UnableToCreateTun)?;
        #[cfg(target_family = "windows")]
        let device = wintun::WinTunDevice::new(ipv4, Ipv4Addr::new(255, 255, 255, 255))?;

        #[cfg(not(target_family = "windows"))]
        let route = TunRoute::new(ipv4, 0);

        #[cfg(target_family = "windows")]
        let route = TunRoute::new(ipv4, device.get_adapter_index());

        let route = route
            .await
            .inspect_err(|_e| warn!("Unable to manage routes"))
            .ok();

        let mut ipstack_config = ipstack::IpStackConfig::default();
        ipstack_config.mtu(MTU as u16)?;
        ipstack_config.packet_information(cfg!(target_family = "unix"));
        ipstack_config.udp_timeout(Duration::from_secs(5));
        let ip_stack = ipstack::IpStack::new(ipstack_config, device);

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
    pub async fn my_routes(&self, my_routes: bool) -> io::Result<()> {
        if let Some(route) = self.route.as_ref() {
            route.my_routes(my_routes).await
        } else if my_routes {
            Err(io::Error::other("route management is unavailable"))
        } else {
            Ok(())
        }
    }
}

#[cfg(target_family = "windows")]
mod wintun {
    use std::{net::Ipv4Addr, sync::Arc, task::ready, thread};

    use tokio::io::{AsyncRead, AsyncWrite};

    use crate::error::ClientError;

    pub struct WinTunDevice {
        session: Arc<wintun::Session>,
        receiver: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
        iface_id: u32,
        _task: thread::JoinHandle<()>,
    }

    impl WinTunDevice {
        pub fn new(ip: Ipv4Addr, netmask: Ipv4Addr) -> Result<WinTunDevice, ClientError> {
            let wintun = unsafe { wintun::load() }.map_err(|_| ClientError::WinTunDLLNotFound)?;
            let adapter = wintun::Adapter::create(&wintun, "Narrowlink", "Narrowlink", None)?;
            adapter.set_address(ip)?;
            adapter.set_netmask(netmask)?;
            let iface_id = adapter.get_adapter_index()?;
            let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY)?);
            let (receiver_tx, receiver_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
            let session_reader = session.clone();
            let task = thread::spawn(move || loop {
                let Ok(packet) = session_reader.receive_blocking() else {
                    break;
                };
                _ = receiver_tx.send(packet.bytes().to_vec());
            });
            Ok(WinTunDevice {
                session,
                receiver: receiver_rx,
                iface_id,
                _task: task,
            })
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
