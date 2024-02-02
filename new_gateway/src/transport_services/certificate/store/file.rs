use pem::Pem;
use rustls::sign::CertifiedKey;
use sha3::{Digest, Sha3_256};
use std::fmt::Write;
use tokio::fs;

use crate::{
    error::GatewayError,
    transport_services::certificate::{CertificateCache, CertificateStorage, DashMapCache},
};
pub struct CertificateFileStorage {
    path: String,
    // cache: Box<dyn CertificateCache>,
}

impl CertificateFileStorage {
    pub fn new(path: String) -> Self {
        Self {
            path,
            // cache: Box::new(cache),
        }
    }
}

impl Default for CertificateFileStorage {
    fn default() -> Self {
        Self::new("../certificates".to_string())
    }
}
#[async_trait::async_trait]
impl CertificateStorage for CertificateFileStorage {
    async fn load_pem(&self, account: &str, domain: &str) -> Result<Vec<Pem>, GatewayError> {
        dbg!(domain);
        let domain_hash =
            Sha3_256::digest(domain.as_bytes())
                .iter()
                .fold(String::new(), |mut acc, x| {
                    let _ = write!(acc, "{:02x}", x);
                    acc
                });

        let pem_path = format!("{}/{}/{}.pem", self.path, account, domain_hash);
        dbg!(&pem_path);
        let pem = pem::parse_many(fs::read_to_string(pem_path).await.unwrap()).unwrap();
        Ok(pem)
    }

    // fn cache(&self) -> &Box<dyn CertificateCache> {
    //     &self.cache
    // }
}
