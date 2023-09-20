mod acme;

pub mod file_storage;
pub mod manager;
use std::{sync::Arc, time::Duration};

use async_trait::async_trait;

use instant_acme::{Account, AccountCredentials};

use pem::Pem;

pub(crate) use acme::ACMEChallengeType;
use rustls::ServerConfig;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::error::GatewayError;

pub const ACME_TLS_ALPN_NAME: &[u8] = b"acme-tls/1";

#[async_trait]
pub trait CertificateStorage {
    async fn set_default_account_credentials(
        &self,
        account: AccountCredentials,
    ) -> Result<(), GatewayError>;
    async fn get_default_account_credentials(&self) -> Result<AccountCredentials, GatewayError>;
    async fn put(
        &self,
        account: &str,
        domain: &str,
        acme_account: Option<AccountCredentials>,
        pems: Vec<Pem>,
    ) -> Result<(), GatewayError>;
    async fn get(
        &self,
        account: &str,
        domain: &str,
    ) -> Result<(Certificate, Option<AccountCredentials>), GatewayError>;
    async fn get_acme_account_credentials(
        &self,
        account: &str,
        domain: &str,
    ) -> Option<AccountCredentials>;
    async fn set_failed(&self, account: &str, domain: &str) -> Result<(), GatewayError>;
    async fn is_failed(&self, account: &str, domain: &str) -> Result<bool, GatewayError>;
    async fn set_pending(&self, account: &str, domain: &str) -> Result<(), GatewayError>;
    async fn is_pending(&self, account: &str, domain: &str) -> Result<bool, GatewayError>;
    async fn get_default_account(&self) -> Result<Account, GatewayError> {
        let account_credentials = self.get_default_account_credentials().await?;
        Ok(Account::from_credentials(account_credentials).await?)
    }
    async fn get_acme_account(&self, account: &str, domain: &str) -> Result<Account, GatewayError> {
        let account_credentials = self.get_acme_account_credentials(account, domain).await;
        if let Some(account_credentials) = account_credentials {
            Ok(Account::from_credentials(account_credentials).await?)
        } else {
            Err(GatewayError::Invalid("No account credentials found"))
        }
    }
}

pub struct Certificate {
    certificate_chain: Vec<rustls::Certificate>,
    // private_key: rustls::PrivateKey,
    config: Arc<ServerConfig>,
}

impl Certificate {
    pub fn from_pem_vec(v: Vec<Pem>) -> Result<Self, GatewayError> {
        let mut certificate_chain = Vec::new();
        let mut private_key = None;
        for i in v {
            match i.tag() {
                "CERTIFICATE" => {
                    certificate_chain.push(rustls::Certificate(i.contents().to_vec()));
                }
                "PRIVATE KEY" => {
                    private_key.replace(rustls::PrivateKey(i.contents().to_vec()));
                }
                _ => continue,
            }
        }
        let Some(private_key) = private_key else {
            return Err(GatewayError::Invalid(
                "Unable to find private key from pem file",
            ));
        };
        if certificate_chain.is_empty() {
            return Err(GatewayError::Invalid("Invalid Pem FIle"));
        }
        let mut config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certificate_chain.clone(), private_key.clone())?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Ok(Certificate {
            certificate_chain,
            // private_key,
            config: Arc::new(config),
        })
    }

    pub fn renew_needed(&self) -> bool {
        for certificate in self.certificate_chain.iter() {
            let Ok((_, cert)) = X509Certificate::from_der(certificate.as_ref()) else {
                return true;
            };
            if cert.is_ca() {
                continue;
            }

            if cert
                .validity()
                .time_to_expiration()
                .and_then(|d| {
                    d.unsigned_abs()
                        .checked_sub(Duration::from_secs(7 * 24 * 60 * 60))
                })
                .is_none()
            {
                return true;
            }
        }
        false
    }
    // pub fn domains(&self) -> Option<Vec<String>> {
    //     let mut domains = Vec::new();
    //     for certificate in self.certificate_chain.iter() {
    //         let (_, cert) = X509Certificate::from_der(certificate.as_ref()).ok()?;
    //         if cert.is_ca() {
    //             continue;
    //         }
    //         if let Ok(Some(san)) = cert.subject_alternative_name() {
    //             for name in &san.value.general_names {
    //                 if let GeneralName::DNSName(domain_name) = name {
    //                     domains.push(domain_name.to_string());
    //                 }
    //             }
    //         }
    //     }
    //     if domains.is_empty() {
    //         return None;
    //     }
    //     Some(domains)
    // }
    pub fn get_config(&self) -> Arc<ServerConfig> {
        self.config.clone()
    }
}

// impl Serialize for Certificate {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: serde::Serializer,
//     {
//         #[derive(Serialize)]
//         pub struct CertificateHelper {
//             certificate: Vec<Vec<u8>>,
//             private_key: Vec<u8>,
//         }

//         CertificateHelper::serialize(
//             &CertificateHelper {
//                 certificate: (&self
//                     .certificate_chain
//                     .iter()
//                     .map(|c| c.as_ref().to_vec())
//                     .collect::<Vec<Vec<u8>>>())
//                     .to_owned(),
//                 private_key: (&self.private_key.0).to_owned(),
//             },
//             serializer,
//         )
//     }
// }

// impl<'de> Deserialize<'de> for Certificate {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: serde::Deserializer<'de>,
//     {
//         Self::from_pem_vec(deserializer);
//         #[derive(Deserialize)]
//         pub struct CertificateHelper {
//             certificate: Vec<Vec<u8>>,
//             private_key: Vec<u8>,
//         }
//         let this = CertificateHelper::deserialize(deserializer)?;
//         Ok(Certificate {
//             certificate_chain: this
//                 .certificate
//                 .iter()
//                 .map(|c| rustls::Certificate(c.to_owned()))
//                 .collect::<Vec<rustls::Certificate>>(),
//             private_key: rustls::PrivateKey(this.private_key),
//         })
//     }
// }
