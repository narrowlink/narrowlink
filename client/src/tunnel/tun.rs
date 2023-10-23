use std::{
    io,
    net::{IpAddr, Ipv4Addr},
};

use futures_util::{FutureExt, StreamExt};
use ipstack::stream::IpStackStream;
use net_route::{Handle, Route};
// use netstack_lwip::NetStack;
use tokio::sync::mpsc::{self, UnboundedSender};
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
    map_addr: Option<IpAddr>,
}

pub enum RouteCommand {
    Add(IpAddr),
    Del(IpAddr),
}

pub struct TunRoute {
    _task: tokio::task::JoinHandle<Result<(), io::Error>>,
    route_sender: UnboundedSender<RouteCommand>,
    my_routes_sender: UnboundedSender<bool>,
}

impl TunRoute {
    pub async fn new(local_addr: Ipv4Addr) -> Result<Self, io::Error> {
        let handle: Handle = Handle::new()?;
        let Some(default_gw) = handle.default_route().await? else {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "No default gateway found",
            ));
        };
        let (my_routes_sender, mut my_routes_receiver) = mpsc::unbounded_channel::<bool>();
        let (route_tx, mut route_rx) = mpsc::unbounded_channel::<RouteCommand>();
        let mut signals = Vec::new();

        for signal_number in [1, 2, 3, 6, 15, 20] {
            signals.push(Box::pin(async move {
                if let Ok(mut signal) = tokio::signal::unix::signal(
                    tokio::signal::unix::SignalKind::from_raw(signal_number),
                ) {
                    signal.recv().await
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
                    Some(route_action) = my_routes_receiver.recv() => {
                        if route_action && !my_routes{
                            if !init {
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
    pub async fn new(local_addr: IpAddr, map_addr: Option<IpAddr>) -> Result<Self, ClientError> {
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
        let device = tun::create_as_async(&config).map_err(ClientError::UnableToCreateTun)?;
        let route = TunRoute::new(ipv4)
            .await
            .map_err(|e| {
                warn!("Unable to manage routes");
                e
            })
            .ok();
        let ip_stack = ipstack::IpStack::new(device, MTU as u16, true);
        Ok(Self {
            ipstack: ip_stack,
            route,
            local_addr,
            map_addr,
        })
    }
    pub async fn accept(&mut self) -> Result<IpStackStream, ClientError> {
        Ok(self.ipstack.accept().await)
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
