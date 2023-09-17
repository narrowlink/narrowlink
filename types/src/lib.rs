use std::net::IpAddr;

use serde::{Deserialize, Serialize};

pub mod agent;
// pub mod api;
pub mod client;
pub mod error;
pub mod generic;
pub mod policy;
pub mod publish;
pub mod token;
pub trait GetResponse {
    type Item;

    fn response(&self) -> Option<Self::Item>;
}

#[derive(Deserialize, Debug, Clone, Serialize, Default)]
pub enum ServiceType {
    Ws,
    #[default]
    Wss,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Peer2PeerRequest {
    // Todo: policy
    pub peer_ip: IpAddr,
    pub seed_port: u16,
    pub seq: u16,
    pub peer_nat: NatType, // peer nat type
    pub nat: NatType,      // nat type
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
    pub policies: Vec<policy::Policy>,
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone, Copy)]
pub enum NatType {
    Easy,
    Hard,
    Unknown,
}
