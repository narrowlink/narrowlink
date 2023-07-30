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
