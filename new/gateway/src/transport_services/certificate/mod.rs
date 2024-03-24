use std::{
    fmt::{Debug, Write},
    sync::Arc,
};

use crate::{
    error::{CertificateError, GatewayError},
    transport_services::tls::alpn::ACME_TLS_ALPN_NAME,
};
use core::fmt::{self, Display, Formatter};
use pem::Pem;
use rustls::{crypto, server::ResolvesServerCert, sign::CertifiedKey};
use sha3::{Digest, Sha3_256};
mod issue;
mod store;
mod validation;
use self::validation::CertificateValidation;
pub use issue::{AcmeService, CertificateIssue};
pub use store::CertificateFileStorage;

#[async_trait::async_trait]
pub trait CertificateStorage: Send + Sync {
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
    // async fn set_success(&self, account: &str, domain: &str) -> Result<(), GatewayError>;
    // async fn is_success(&self, account: &str, domain: &str) -> bool;
    fn domain_hash(&self, domain: &str) -> String {
        Sha3_256::digest(domain.as_bytes())
            .iter()
            .fold(String::new(), |mut acc, x| {
                let _ = write!(acc, "{:02x}", x);
                acc
            })
    }
    async fn get_certificate_key(
        &self,
        account: &str,
        domain: &str,
    ) -> Result<CertifiedKey, GatewayError> {
        let pems = self.get_pem(account, domain).await?;
        let mut certificate_chain = Vec::new();
        let mut private_key = None;

        for i in pems {
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

        let signer = crypto::ring::sign::any_supported_type(
            &private_key.ok_or(CertificateError::PrivateKeyNotFound)?,
        )
        .unwrap();

        if certificate_chain.is_empty() {
            return Err(CertificateError::CertificateNotFound.into());
        }

        Ok(CertifiedKey::new(certificate_chain, signer))
    }
}

pub trait CertificateCache {
    fn get(&self, account: &str, domain: &str) -> Option<Arc<CertifiedKey>>;
    fn put(&self, account: &str, domain: &str, config: CertifiedKey);
    fn remove(&self, account: &str, domain: &str) -> Option<CertifiedKey>;
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
    fn remove(&self, account: &str, domain: &str) -> Option<CertifiedKey> {
        self.0
            .remove(&format!("{}:{}", account, domain))
            .map(|c| Arc::<CertifiedKey>::unwrap_or_clone(c.1))
    }
}

impl Default for DashMapCache {
    fn default() -> Self {
        Self(Arc::new(dashmap::DashMap::new()))
    }
}
pub enum CertificateResolveStatus {
    Success,
    PendingIssue,
}

pub struct CertificateResolver {
    storage: Arc<dyn CertificateStorage + Send + Sync>,
    cache: Box<dyn CertificateCache + Send + Sync>,
    issue: Option<Arc<dyn CertificateIssue + Send + Sync>>,
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
        issue: Option<Arc<impl CertificateIssue + Send + Sync + 'static>>,
    ) {
        self.issue = issue.map(|x| x as _);
    }
    pub async fn load_and_cache(
        &self,
        account: &str,
        domain: &str,
    ) -> Result<CertificateResolveStatus, GatewayError> {
        match self.storage.get_certificate_key(account, domain).await {
            Ok(certificate_key) => {
                let days_until_expiration = certificate_key.days_until_expiration();
                dbg!("ss");
                if let Some(issue) = self.issue.as_ref().filter(|_| days_until_expiration == 0) {
                    issue.issue(account, domain);
                    todo!("renew certificate");
                    Ok(CertificateResolveStatus::PendingIssue)
                } else {
                    self.cache.put(account, domain, certificate_key);
                    if let Some(_issue) = self.issue.as_ref().filter(|_| days_until_expiration < 7)
                    {
                        todo!("renew certificate");
                    }
                    dbg!("success");
                    Ok(CertificateResolveStatus::Success)
                }
            }
            Err(e) => {
                if let Some(issue) = self.issue.as_ref() {
                    issue.issue(account, domain);
                    // todo!("renew certificate");
                    Ok(CertificateResolveStatus::PendingIssue)
                } else {
                    Err(e)
                }
            }
        }
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
        let sni = client_hello.server_name()?;
        let alpn = client_hello.alpn()?;
        let account = "main";
        if let Some(acme) = &self.issue {
            if alpn.collect::<Vec<_>>().contains(&ACME_TLS_ALPN_NAME) {
                return acme
                    .challenge(account, sni)
                    .and_then(|c| c.get_tls_challenge().map(Arc::new));
            } else {
                acme.remove_from_cache(account, sni)
                    .map(|certified_key| self.cache.put(account, sni, certified_key));
            }
        }
        self.get_certified_key(account, sni)
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
