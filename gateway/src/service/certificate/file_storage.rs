use std::io::{BufReader, BufWriter};

use askama::Result;
use async_trait::async_trait;
use instant_acme::Account;
use pem::Pem;
use tokio::{fs, io::AsyncWriteExt};

use crate::error::GatewayError;

use super::{Certificate, CertificateStorage};

pub struct CertificateFileStorage {
    path: std::path::PathBuf,
}

impl CertificateFileStorage {
    pub fn new(path: &str) -> Self {
        Self { path: path.into() }
    }
}

#[async_trait]
impl CertificateStorage for CertificateFileStorage {
    async fn get_default_account(&self) -> Result<Account, GatewayError> {
        let mut final_path = self.path.clone();
        fs::create_dir_all(&final_path).await?;
        final_path.push("default.account");
        let defaul_account_file = std::fs::File::open(final_path)?;
        Ok(Account::from_credentials(serde_json::de::from_reader(
            BufReader::new(defaul_account_file),
        )?)?)
    }
    async fn set_default_account(&self, account: Account) -> Result<(), GatewayError> {
        let mut final_path = self.path.clone();
        fs::create_dir_all(&final_path).await?;
        final_path.push("default.account");
        Ok(serde_json::ser::to_writer(
            BufWriter::new(std::fs::File::create(final_path)?),
            &account.credentials(),
        )?)
    }
    async fn put(
        &self,
        account: &str,
        service: &str,
        acme_account: Option<Account>,
        cert: Vec<Pem>,
    ) -> Result<(), GatewayError> {
        let mut final_path = self.path.clone();
        final_path.push(account);
        fs::create_dir_all(&final_path).await?;
        final_path.push(service);
        if let Some(acme_account) = acme_account {
            let mut acme_account_path = final_path.clone();
            acme_account_path.set_extension("account");

            serde_json::ser::to_writer(
                BufWriter::new(std::fs::File::create(acme_account_path)?),
                &acme_account.credentials(),
            )
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        }
        final_path.set_extension("pem");
        fs::File::create(final_path)
            .await?
            .write_all(pem::encode_many(&cert).as_bytes())
            .await?;
        Ok(())
    }
    async fn get(
        &self,
        account: &str,
        service: &str,
    ) -> Result<(Certificate, Option<Account>), GatewayError> {
        let mut final_path = self.path.clone();
        final_path.push(account);
        final_path.push(service);
        let mut acme_account_path = final_path.clone();
        final_path.set_extension("pem");

        let cert =
            Certificate::from_pem_vec(pem::parse_many(fs::read_to_string(final_path).await?)?)?;

        acme_account_path.set_extension("account");
        let acme_account = if cert.renew_needed() {
            if let Ok(acme_account_file) = std::fs::File::open(acme_account_path) {
                Account::from_credentials(serde_json::de::from_reader(BufReader::new(
                    acme_account_file,
                ))?)
                .ok()
            } else {
                None
            }
        } else {
            None
        };

        Ok((cert, acme_account))
    }
    async fn get_acme_account(&self, account: &str, service: &str) -> Option<Account> {
        let mut acme_account_path = self.path.clone();
        acme_account_path.push(account);
        acme_account_path.push(service);
        std::fs::File::open(acme_account_path)
            .ok()
            .and_then(|acme_account_file| {
                serde_json::de::from_reader(BufReader::new(acme_account_file))
                    .ok()
                    .and_then(|credentials| Account::from_credentials(credentials).ok())
                // serde_json::de::from_reader(BufReader::new(acme_account_file))
            })
    }
    async fn set_fail(&self, account: &str, service: &str) -> Result<(), GatewayError> {
        let mut final_path = self.path.clone();
        final_path.push(account);
        fs::create_dir_all(&final_path).await?;
        final_path.push(service);
        final_path.set_extension("fail");

        Ok(fs::File::create(final_path).await.map(|_| ())?)
    }
}