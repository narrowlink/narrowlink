use futures_util::{stream::SplitSink, SinkExt};
use narrowlink_types::{
    client::{ConstSystemInfo, EventInBound, EventOutBound, SystemInfo},
    policy::Policies,
};

use narrowlink_network::{error::NetworkError, event::NarrowEvent};
use uuid::Uuid;

pub struct Client {
    pub name: String,
    session_id: Uuid,
    policies: Policies,
    system_info: Option<SystemInfo>,
    sender: SplitSink<NarrowEvent<EventInBound, EventOutBound>, EventInBound>,
}

impl Client {
    pub fn new(
        name: String,
        session_id: Uuid,
        policies: Policies,
        sender: SplitSink<NarrowEvent<EventInBound, EventOutBound>, EventInBound>,
    ) -> Client {
        Client {
            name,
            session_id,
            policies,
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
}
