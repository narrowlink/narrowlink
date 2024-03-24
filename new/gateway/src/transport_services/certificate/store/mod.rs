mod file;
use crate::error::GatewayCertificateError;
pub use file::CertificateFileStorage;
use pem::Pem;
use rustls::{crypto, sign::CertifiedKey};
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
    async fn get_pem(
        &self,
        account: &str,
        domain: &str,
    ) -> Result<Vec<Pem>, GatewayCertificateError>;
    async fn put_pem(
        &self,
        uid: &str,
        domain: &str,
        account_credentials: Option<&str>,
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
    async fn get_certificate_key(
        &self,
        uid: &str,
        domain: &str,
    ) -> Result<CertifiedKey, GatewayCertificateError> {
        let pems = self.get_pem(uid, domain).await?;
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
            &private_key.ok_or(GatewayCertificateError::PrivateKeyNotFound)?,
        )
        .unwrap();

        if certificate_chain.is_empty() {
            return Err(GatewayCertificateError::CertificateNotFound.into());
        }

        Ok(CertifiedKey::new(certificate_chain, signer))
    }
}
