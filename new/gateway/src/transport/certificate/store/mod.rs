mod file;
use crate::error::GatewayCertificateError;
pub use file::CertificateFileStorage;
use pem::Pem;
use rustls::{
    crypto,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    sign::CertifiedKey,
};
use sha3::{Digest, Sha3_256};
use std::fmt::Write;

#[async_trait::async_trait]
pub trait CertificateStorage: Send + Sync {
    async fn set_account_credentials(
        &self,
        account: &str,
        uid: &str,
    ) -> Result<(), GatewayCertificateError>;
    async fn get_account_credentials(&self, uid: &str) -> Result<String, GatewayCertificateError>;
    async fn set_default_account_credentials(
        &self,
        account: &str,
    ) -> Result<(), GatewayCertificateError> {
        self.set_account_credentials(account, "main").await
    }
    async fn get_default_account_credentials(&self) -> Result<String, GatewayCertificateError> {
        self.get_account_credentials("main").await
    }
    async fn get_pem(&self, uid: &str, domain: &str) -> Result<Vec<Pem>, GatewayCertificateError>;
    async fn put_pem(
        &self,
        uid: &str,
        domain: &str,
        pems: Vec<Pem>,
    ) -> Result<(), GatewayCertificateError>;
    async fn set_failed(&self, uid: &str, domain: &str) -> Result<(), GatewayCertificateError>;
    async fn is_failed(&self, uid: &str, domain: &str) -> bool;
    async fn set_pending(&self, uid: &str, domain: &str) -> Result<(), GatewayCertificateError>;
    async fn is_pending(&self, uid: &str, domain: &str) -> bool;
    fn domain_hash(&self, domain: &str) -> String {
        Sha3_256::digest(domain.as_bytes())
            .iter()
            .fold(String::new(), |mut acc, x| {
                let _ = write!(acc, "{:02x}", x);
                acc
            })
    }
    fn get_private_key(&self, pem: &Vec<Pem>) -> Option<PrivateKeyDer<'static>> {
        for i in pem {
            if i.tag() == "PRIVATE KEY" {
                return Some(PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
                    i.contents().to_vec(),
                )));
            }
        }
        None
    }
    fn get_certificate_chain(&self, pem: &Vec<Pem>) -> Option<Vec<CertificateDer<'static>>> {
        let mut certificate_chain = Vec::new();
        for i in pem {
            if i.tag() == "CERTIFICATE" {
                certificate_chain.push(CertificateDer::from(i.contents().to_vec()));
            }
        }
        if certificate_chain.is_empty() {
            return None;
        }
        Some(certificate_chain)
    }
    async fn get_certified_key(
        &self,
        pem: &Vec<Pem>,
    ) -> Result<CertifiedKey, GatewayCertificateError> {
        let key = self
            .get_private_key(&pem)
            .ok_or(GatewayCertificateError::PrivateKeyNotFound)?;
        let cert = self
            .get_certificate_chain(&pem)
            .ok_or(GatewayCertificateError::CertificateNotFound)?;
        let signer = crypto::ring::sign::any_supported_type(&key).unwrap();

        Ok(CertifiedKey::new(cert, signer))
    }
}
