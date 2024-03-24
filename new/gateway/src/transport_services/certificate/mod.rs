use std::{fmt::Debug, sync::Arc};

use crate::{error::GatewayError, transport_services::tls::alpn::ACME_TLS_ALPN_NAME};
use core::fmt::{self, Display, Formatter};
use rustls::{server::ResolvesServerCert, sign::CertifiedKey};
pub mod cache;
mod issue;
mod store;
mod validation;
use self::{cache::CertificateCache, store::CertificateStorage, validation::CertificateValidation};
pub use issue::{AcmeService, CertificateIssue};
pub use store::CertificateFileStorage;

pub enum CertificateResolveStatus {
    Success,
    Renew,
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
        uid: &str,
        domain: &str,
    ) -> Result<CertificateResolveStatus, GatewayError> {
        match self.storage.get_certificate_key(uid, domain).await {
            Ok(certificate_key) => {
                let days_until_expiration = certificate_key.days_until_expiration();
                if let Some(issue) = self.issue.as_ref().filter(|_| days_until_expiration == 0) {
                    issue.issue(uid, domain);
                    Ok(CertificateResolveStatus::PendingIssue)
                } else {
                    self.cache.put(uid, domain, certificate_key);
                    if let Some(issue) = self.issue.as_ref().filter(|_| days_until_expiration < 7) {
                        issue.issue(uid, domain);
                        Ok(CertificateResolveStatus::Renew)
                    } else {
                        Ok(CertificateResolveStatus::Success)
                    }
                }
            }
            Err(e) => {
                let issue = self.issue.as_ref().ok_or(e)?;
                issue.issue(uid, domain);
                Ok(CertificateResolveStatus::PendingIssue)
            }
        }
    }

    fn unload(&self, uid: &str, domain: &str) {
        self.cache.remove(uid, domain);
    }
    fn get_certified_key(&self, uid: &str, domain: &str) -> Option<Arc<CertifiedKey>> {
        self.cache.get(uid, domain)
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
