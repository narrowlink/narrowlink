use std::net::SocketAddr;
use uuid::Uuid;

include!(concat!(env!("OUT_DIR"), "/negotiatation.rs"));
impl Publish {
    pub fn new(uid: Uuid, socketaddr: SocketAddr) -> Publish {
        let (mut ip, port) = match socketaddr {
            SocketAddr::V4(v4) => (v4.ip().octets().to_vec(), v4.port()),
            SocketAddr::V6(v6) => (v6.ip().octets().to_vec(), v6.port()),
        };
        ip.extend_from_slice(&mut port.to_be_bytes());
        Publish {
            uid: uid.as_bytes().to_vec(),
            socketaddr: ip,
        }
    }
    pub fn uid(&self) -> Uuid {
        Uuid::from_slice(&self.uid).unwrap()
    }
    pub fn socketaddr(&self) -> SocketAddr {
        if self.socketaddr.len() == 6 {
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&self.socketaddr[..4]);
            let port = u16::from_be_bytes([self.socketaddr[4], self.socketaddr[5]]);
            SocketAddr::new(ip.into(), port)
        } else if self.socketaddr.len() == 18 {
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&self.socketaddr[..16]);
            let port = u16::from_be_bytes([self.socketaddr[16], self.socketaddr[17]]);
            SocketAddr::new(ip.into(), port)
        } else {
            panic!("invalid socketaddr")
        }
    }
}
