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
pub struct Peer2Peer {
    // Todo: policy
    pub peer_ip: IpAddr,
    pub peer_port: u16,
    pub sequences: u16,
    pub peer_nat_type: NatType,
    pub nat_type: NatType,
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone,Copy)]
pub enum NatType {
    Easy,
    Hard,
    Unknown,
}
