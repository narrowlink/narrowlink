use std::{collections::HashMap, net::SocketAddr};

use futures_util::{stream::SplitSink, SinkExt};
use narrowlink_network::{error::NetworkError, event::NarrowEvent};
use narrowlink_types::{
    agent::{ConstSystemInfo, DynSystemInfo, EventInBound, EventOutBound, SystemInfo},
    generic::Connect,
    publish::PublishHost,
};

pub struct Agent {
    pub name: String,
    pub publish_map: HashMap<String, HashMap<u16, Connect>>,
    pub socket_addr: SocketAddr,
    pub forward_addr: Option<String>,
    pub system_info: Option<SystemInfo>,
    pub ping: u16,
    pub since: u64,
    sender: SplitSink<NarrowEvent<EventInBound, EventOutBound>, EventInBound>,
}

impl Agent {
    pub fn new(
        name: String,
        publishes: Vec<PublishHost>,
        socket_addr: SocketAddr,
        forward_addr: Option<String>,
        sender: SplitSink<NarrowEvent<EventInBound, EventOutBound>, EventInBound>,
    ) -> Self {
        let mut publish_map = HashMap::new();
        for publish in publishes {
            publish_map
                .entry(publish.host)
                .or_insert_with(HashMap::new)
                .insert(publish.port, publish.connect);
        }
        let since = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            name,
            publish_map,
            socket_addr,
            forward_addr,
            system_info: None,
            ping: 0,
            since,
            sender,
        }
    }

    pub fn name(&self) -> String {
        self.name.clone()
    }
    pub async fn send(&mut self, msg: EventInBound) -> Result<(), NetworkError> {
        self.sender.send(msg).await
    }
    pub fn domain(&self, domain: &str, port: u16) -> Option<Connect> {
        self.publish_map
            .get(domain)
            .and_then(|map| map.get(&port))
            .cloned()
    }
    pub fn dyn_sys_update(&mut self, dyn_sys_info: DynSystemInfo) {
        if let Some(sys_info) = &mut self.system_info {
            sys_info.dynamic = dyn_sys_info;
        }
    }
    pub fn const_sys_update(&mut self, sys_info: ConstSystemInfo) {
        self.system_info = Some(SystemInfo {
            constant: sys_info,
            dynamic: Default::default(),
        });
    }
    pub fn pingupdate(&mut self, ping: u16) {
        self.ping = ping;
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        drop(self.sender.close());
    }
}
