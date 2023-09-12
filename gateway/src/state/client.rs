use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use futures_util::{stream::SplitSink, SinkExt};
use narrowlink_types::{
    client::{ConstSystemInfo, EventInBound, EventOutBound, SystemInfo},
    policy::Policies,
    NatType,
};

use narrowlink_network::{error::NetworkError, event::NarrowEvent};
use uuid::Uuid;

pub struct Client {
    pub name: String,
    session_id: Uuid,
    policies: Policies,
    socket_addr: SocketAddr,
    forward_addr: Option<String>,
    system_info: Option<SystemInfo>,
    sender: SplitSink<NarrowEvent<EventInBound, EventOutBound>, EventInBound>,
}

impl Client {
    pub fn new(
        name: String,
        session_id: Uuid,
        policies: Policies,
        socket_addr: SocketAddr,
        forward_addr: Option<String>,
        sender: SplitSink<NarrowEvent<EventInBound, EventOutBound>, EventInBound>,
    ) -> Client {
        Client {
            name,
            session_id,
            policies,
            socket_addr,
            forward_addr,
            system_info: None,
            sender,
        }
    }
    #[allow(dead_code)] // todo to get list of clients
    pub fn name(&self) -> String {
        self.name.to_owned()
    }
    pub async fn send(&mut self, msg: EventInBound) -> Result<(), NetworkError> {
        self.sender.send(msg).await
    }
    pub fn const_sys_update(&mut self, sys_info: ConstSystemInfo) {
        self.system_info = Some(SystemInfo { constant: sys_info });
    }
    pub fn get_session_id(&self) -> Uuid {
        self.session_id
    }
    pub fn get_policy(&self) -> Policies {
        self.policies.clone()
    }
    pub fn get_real_ip(&self) -> IpAddr {
        if let Some(addr) = self
            .forward_addr
            .as_ref()
            .and_then(|a| IpAddr::from_str(a).ok())
        {
            addr
        } else {
            self.socket_addr.ip()
        }
    }
    pub fn get_local_addr(&self) -> Option<SocketAddr> {
        self.system_info.as_ref().map(|i| i.constant.local_addr)
    }
    pub fn nat_type(&self) -> NatType {
        // refactor needed
        if self
            .forward_addr
            .as_ref()
            .and_then(|a| IpAddr::from_str(a).ok())
            .is_some()
        {
            NatType::Unknown
        } else if let Some(system_info) = self.system_info.as_ref() {
            if system_info.constant.local_addr.port() == self.socket_addr.port() {
                NatType::Easy
            } else {
                NatType::Hard
            }
        } else {
            NatType::Unknown
        }
    }
}
