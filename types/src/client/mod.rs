mod data;
mod event;
use std::net::SocketAddr;

pub use data::InBound as DataInBound;
pub use data::OutBound as DataOutBound;
pub use event::InBound as EventInBound;
pub use event::OutBound as EventOutBound;
pub use event::Request as EventRequest;
pub use event::Response as EventResponse;
use serde::Deserialize;
use serde::Serialize;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SystemInfo {
    pub constant: ConstSystemInfo,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ConstSystemInfo {
    pub local_addr: SocketAddr,
}
