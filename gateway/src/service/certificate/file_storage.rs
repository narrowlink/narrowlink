use std::{
    io::{BufReader, BufWriter},
    time::SystemTime,
};

use askama::Result;
use async_trait::async_trait;
use instant_acme::AccountCredentials;
use pem::Pem;
use sha3::{Digest, Sha3_256};
use tokio::{fs, io::AsyncWriteExt};

use crate::error::GatewayError;

use super::{Certificate, CertificateStorage};

pub struct CertificateFileStorage {
    path: String,
}

impl CertificateFileStorage {
    pub fn new(path: &str) -> Self {
        Self { path: path.into() }
    }
}

#[async_trait]
impl CertificateStorage for CertificateFileStorage {
    async fn get_default_account_credentials(&self) -> Result<AccountCredentials, GatewayError> {
        let default_account_path = format!("{}/default.account", self.path);
        let defaul_account_file = std::fs::File::open(default_account_path)?;
        serde_json::de::from_reader(BufReader::new(defaul_account_file)).map_err(|e| e.into())
    }
    async fn set_default_account_credentials(
        &self,
        account: AccountCredentials,
    ) -> Result<(), GatewayError> {
        fs::create_dir_all(&self.path).await?;
        let default_account_path = format!("{}/default.account", self.path);

        Ok(serde_json::ser::to_writer(
            BufWriter::new(std::fs::File::create(default_account_path)?),
            &account,
        )?)
    }
    async fn put(
        &self,
        account: &str,
        domain: &str,
        acme_account_credentials: Option<AccountCredentials>,
        cert: Vec<Pem>,
    ) -> Result<(), GatewayError> {
        let base_path = format!("{}/{}", self.path, account);
        fs::create_dir_all(&base_path).await?;
        let domain_hash = Sha3_256::digest(domain.as_bytes())
            .iter()
            .map(|x| format!("{:02x}", x))
            .collect::<String>();
        if let Some(acme_account_credentials) = acme_account_credentials {
            let acme_account_path = format!("{}/{}.account", base_path, domain_hash);

            serde_json::ser::to_writer(
                BufWriter::new(std::fs::File::create(acme_account_path)?),
                &acme_account_credentials,
            )
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        }
        let pem_path = format!("{}/{}.pem", base_path, domain_hash);

        fs::File::create(pem_path)
            .await?
            .write_all(pem::encode_many(&cert).as_bytes())
            .await?;

        let failed_path = format!("{}/{}.failed", base_path, domain_hash);
        let pending_path = format!("{}/{}.pending", base_path, domain_hash);

        _ = fs::remove_file(failed_path).await;
        _ = fs::remove_file(pending_path).await?;

        Ok(())
    }
    async fn get(
        &self,
        account: &str,
        domain: &str,
    ) -> Result<(Certificate, Option<AccountCredentials>), GatewayError> {
        let domain_hash = Sha3_256::digest(domain.as_bytes())
            .iter()
            .map(|x| format!("{:02x}", x))
            .collect::<String>();
        let base_path = format!("{}/{}", self.path, account);
        let acme_account_path = format!("{}/{}.account", base_path, domain_hash);
        let pem_path = format!("{}/{}.pem", base_path, domain_hash);

        let cert =
            Certificate::from_pem_vec(pem::parse_many(fs::read_to_string(pem_path).await?)?)?;

        let acme_account = if cert.renew_needed() {
            if let Ok(acme_account_file) = std::fs::File::open(acme_account_path) {
                serde_json::de::from_reader(BufReader::new(acme_account_file)).ok()
            } else {
                None
            }
        } else {
            None
        };

        Ok((cert, acme_account))
    }
    async fn get_acme_account_credentials(
        &self,
        account: &str,
        domain: &str,
    ) -> Option<AccountCredentials> {
        let domain_hash = Sha3_256::digest(domain.as_bytes())
            .iter()
            .map(|x| format!("{:02x}", x))
            .collect::<String>();
        let acme_account_path = format!("{}/{}/{}.account", self.path, account, domain_hash);
        std::fs::File::open(acme_account_path)
            .ok()
            .and_then(|f| serde_json::de::from_reader(BufReader::new(f)).ok())
    }
    async fn set_failed(&self, account: &str, domain: &str) -> Result<(), GatewayError> {
        let domain_hash = Sha3_256::digest(domain.as_bytes())
            .iter()
            .map(|x| format!("{:02x}", x))
            .collect::<String>();
        let base_path = format!("{}/{}", self.path, account);
        fs::create_dir_all(&base_path).await?;
        let failed_path = format!("{}/{}.failed", base_path, domain_hash);
        let pending_path = format!("{}/{}.pending", base_path, domain_hash);
        Ok(fs::rename(pending_path, failed_path).await.map(|_| ())?)
    }
    async fn is_failed(&self, account: &str, domain: &str) -> bool {
        let domain_hash = Sha3_256::digest(domain.as_bytes())
            .iter()
            .map(|x| format!("{:02x}", x))
            .collect::<String>();
        let failed_path = format!("{}/{}/{}.failed", self.path, account, domain_hash);
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        std::fs::read_to_string(failed_path)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v + 60 * 60 > ts) // 1 hour
            .is_some()
    }
    async fn set_pending(&self, account: &str, domain: &str) -> Result<(), GatewayError> {
        let domain_hash = Sha3_256::digest(domain.as_bytes())
            .iter()
            .map(|x| format!("{:02x}", x))
            .collect::<String>();
        let base_path = format!("{}/{}", self.path, account);
        let pending_path = format!("{}/{}.pending", base_path, domain_hash);
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        fs::create_dir_all(&base_path).await?;
        Ok(fs::write(pending_path, ts.to_string()).await.map(|_| ())?)
    }
    async fn is_pending(&self, account: &str, domain: &str) -> bool {
        let domain_hash = Sha3_256::digest(domain.as_bytes())
            .iter()
            .map(|x| format!("{:02x}", x))
            .collect::<String>();
        let pending_path = format!("{}/{}/{}.pending", self.path, account, domain_hash);
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        std::fs::read_to_string(pending_path)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v + 120 > ts) // 120 seconds
            .is_some()
    }
}
