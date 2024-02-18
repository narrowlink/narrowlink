use std::{
    fmt::{Debug, Write},
    sync::Arc,
};

use crate::error::GatewayError;
use core::fmt::{self, Display, Formatter};
use pem::Pem;
use rustls::{crypto, server::ResolvesServerCert, sign::CertifiedKey, ServerConfig};
use serde::de::DeserializeOwned;
use sha3::{Digest, Sha3_256};
mod issue;
mod store;
pub use issue::AcmeService;
pub use store::CertificateFileStorage;

use self::issue::CertificateIssue;

#[async_trait::async_trait]
pub trait CertificateStorage {
    async fn set_default_account_credentials(&self, account: &str) -> Result<(), GatewayError>;
    async fn get_default_account_credentials(&self) -> Result<String, GatewayError>;
    async fn get_pem(&self, account: &str, domain: &str) -> Result<Vec<Pem>, GatewayError>;
    async fn put_pem(
        &self,
        account: &str,
        domain: &str,
        account_credentials: Option<&str>,
        pems: Vec<Pem>,
    ) -> Result<(), GatewayError>;
    async fn set_failed(&self, account: &str, domain: &str) -> Result<(), GatewayError>;
    async fn is_failed(&self, account: &str, domain: &str) -> bool;
    async fn set_pending(&self, account: &str, domain: &str) -> Result<(), GatewayError>;
    async fn is_pending(&self, account: &str, domain: &str) -> bool;
    fn domain_hash(&self, domain: &str) -> String {
        Sha3_256::digest(domain.as_bytes())
            .iter()
            .fold(String::new(), |mut acc, x| {
                let _ = write!(acc, "{:02x}", x);
                acc
            })
    }
}

pub trait CertificateCache {
    fn get(&self, account: &str, domain: &str) -> Option<Arc<CertifiedKey>>;
    fn put(&self, account: &str, domain: &str, config: CertifiedKey);
    fn remove(&self, account: &str, domain: &str);
}

pub struct DashMapCache(Arc<dashmap::DashMap<String, Arc<CertifiedKey>>>);

impl CertificateCache for DashMapCache {
    fn get(&self, account: &str, domain: &str) -> Option<Arc<CertifiedKey>> {
        self.0
            .get(&format!("{}:{}", account, domain))
            .map(|x| x.value().clone())
    }
    fn put(&self, account: &str, domain: &str, config: CertifiedKey) {
        self.0
            .insert(format!("{}:{}", account, domain), Arc::new(config));
    }
    fn remove(&self, account: &str, domain: &str) {
        self.0.remove(&format!("{}:{}", account, domain));
    }
}

impl Default for DashMapCache {
    fn default() -> Self {
        Self(Arc::new(dashmap::DashMap::new()))
    }
}

pub struct CertificateResolver {
    storage: Arc<dyn CertificateStorage + Send + Sync>,
    cache: Box<dyn CertificateCache + Send + Sync>,
    issue: Option<Box<dyn CertificateIssue + Send + Sync>>,
}

impl CertificateResolver {
    pub fn new(
        storage: Arc<impl CertificateStorage + 'static + Send + Sync>,
        cache: impl CertificateCache + 'static + Send + Sync,
    ) -> Self {
        Self {
            storage,
            cache: Box::new(cache),
            issue: None,
        }
    }
    pub fn set_certificate_issuer(
        &mut self,
        issue: Option<impl CertificateIssue + Send + Sync + 'static>,
    ) {
        self.issue = issue.map(|x| Box::new(x) as _);
    }
    pub async fn load_and_cache(&self, account: &str, domain: &str) -> Result<(), GatewayError> {
        let pem = self.storage.get_pem(account, domain).await.unwrap();
        let mut certificate_chain = Vec::new();
        let mut private_key = None;
        for i in pem {
            match i.tag() {
                "CERTIFICATE" => {
                    certificate_chain.push(rustls::pki_types::CertificateDer::from(
                        i.contents().to_vec(),
                    ));
                }
                "PRIVATE KEY" => {
                    private_key.replace(rustls::pki_types::PrivateKeyDer::from(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(i.contents().to_vec()),
                    ));
                }
                _ => continue,
            }
        }
        let Some(private_key) = private_key else {
            return Err(GatewayError::Invalid(
                "Unable to find private key from pem file",
            ));
        };
        let signer = crypto::ring::sign::any_supported_type(&private_key).unwrap();
        if certificate_chain.is_empty() {
            return Err(GatewayError::Invalid("Invalid Pem FIle"));
        }
        let certificate_key = CertifiedKey::new(certificate_chain, signer);
        self.cache.put(account, domain, certificate_key);
        Ok(())
    }
    fn unload(&self, account: &str, domain: &str) {
        self.cache.remove(account, domain);
    }
    fn get_certified_key(&self, account: &str, domain: &str) -> Option<Arc<CertifiedKey>> {
        self.cache.get(account, domain)
    }
}

impl ResolvesServerCert for CertificateResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        client_hello
            .server_name()
            .and_then(|sni| self.get_certified_key("main", sni))
    }
}

impl Display for CertificateResolver {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "CertificateResolver")
    }
}

impl Debug for CertificateResolver {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "CertificateResolver")
    }
}
