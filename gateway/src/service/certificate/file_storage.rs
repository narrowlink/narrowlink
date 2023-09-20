use std::{
    io::{BufReader, BufWriter},
    path::Path,
};

use askama::Result;
use async_trait::async_trait;
use instant_acme::AccountCredentials;
use pem::Pem;
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

        if let Some(acme_account_credentials) = acme_account_credentials {
            let acme_account_path = format!("{}/{}.account", base_path, domain);

            serde_json::ser::to_writer(
                BufWriter::new(std::fs::File::create(acme_account_path)?),
                &acme_account_credentials,
            )
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        }
        let pem_path = format!("{}/{}.pem", base_path, domain);

        fs::File::create(pem_path)
            .await?
            .write_all(pem::encode_many(&cert).as_bytes())
            .await?;

        let failed_path = format!("{}/{}.failed", base_path, domain);
        let pending_path = format!("{}/{}.pending", base_path, domain);

        _ = fs::remove_file(failed_path).await;
        _ = fs::remove_file(pending_path).await?;

        Ok(())
    }
    async fn get(
        &self,
        account: &str,
        domain: &str,
    ) -> Result<(Certificate, Option<AccountCredentials>), GatewayError> {
        let base_path = format!("{}/{}", self.path, account);
        let acme_account_path = format!("{}/{}.account", base_path, domain);
        let pem_path = format!("{}/{}.pem", base_path, domain);

        let cert =
            Certificate::from_pem_vec(pem::parse_many(fs::read_to_string(pem_path).await?)?)?;

        let acme_account = if cert.renew_needed() {
            if let Ok(acme_account_file) = std::fs::File::open(acme_account_path) {
                // let account_credentials :Option<AccountCredentials>= serde_json::de::from_reader(BufReader::new(
                //     acme_account_file,
                // )).ok();
                // todo!()
                // Account::from_credentials(serde_json::de::from_reader(BufReader::new(
                //     acme_account_file,
                // ))?)
                // .ok()
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
        let acme_account_path = format!("{}/{}/{}.account", self.path, account, domain);
        std::fs::File::open(acme_account_path).ok().and_then(|f| {
            serde_json::de::from_reader(BufReader::new(f)).ok()
            // .and_then(|credentials| Account::from_credentials(credentials).ok())
            // serde_json::de::from_reader(BufReader::new(acme_account_file))
        })
    }
    async fn set_failed(&self, account: &str, domain: &str) -> Result<(), GatewayError> {
        let base_path = format!("{}/{}", self.path, account);
        fs::create_dir_all(&base_path).await?;
        let failed_path = format!("{}/{}.failed", base_path, domain);
        let pending_path = format!("{}/{}.pending", base_path, domain);
        Ok(fs::rename(pending_path, failed_path).await.map(|_| ())?)
    }
    async fn is_failed(&self, account: &str, domain: &str) -> Result<bool, GatewayError> {
        let failed_path = format!("{}/{}/{}.failed", self.path, account, domain);
        Ok(Path::new(&failed_path).exists())
    }
    async fn set_pending(&self, account: &str, domain: &str) -> Result<(), GatewayError> {
        let base_path = format!("{}/{}", self.path, account);
        let pending_path = format!("{}/{}.pending", base_path, domain);
        fs::create_dir_all(&base_path).await?;
        Ok(fs::File::create(pending_path).await.map(|_| ())?)
    }
    async fn is_pending(&self, account: &str, domain: &str) -> Result<bool, GatewayError> {
        let pending_path = format!("{}/{}/{}.pending", self.path, account, domain);
        Ok(Path::new(&pending_path).exists())
    }
}
