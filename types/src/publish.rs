use serde::{Deserialize, Serialize};

use crate::generic::Connect;

#[derive(Debug, Serialize, Deserialize)]
pub struct PublishHost {
    pub host: String,
    pub port: u16,
    pub connect: Connect,
}
