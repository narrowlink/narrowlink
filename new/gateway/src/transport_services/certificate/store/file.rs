use pem::Pem;
use rustls::CertificateError;
use std::time::SystemTime;
use tokio::{fs, io::AsyncWriteExt};

use crate::{
    error::{CertificateError as GWCertificateError, GatewayError},
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
    async fn get_default_account_credentials(&self) -> Result<String, GatewayError> {
        let default_account_path = format!("{}/default.account", self.path);
        Ok(fs::read_to_string(default_account_path).await.unwrap())
    }
    async fn set_default_account_credentials(&self, account: &str) -> Result<(), GatewayError> {
        fs::create_dir_all(&self.path).await.unwrap();
        let default_account_path = format!("{}/default.account", self.path);
        fs::File::create(default_account_path)
            .await
            .unwrap()
            .write_all(account.as_bytes())
            .await
            .unwrap();
        Ok(())
    }
    async fn get_pem(&self, account: &str, domain: &str) -> Result<Vec<Pem>, GatewayError> {
        let pem_path = format!("{}/{}/{}.pem", self.path, account, self.domain_hash(domain));
        dbg!(&pem_path);
        pem::parse_many(fs::read_to_string(pem_path).await.unwrap())
            .map_err(|e| GWCertificateError::InvalidPem(e).into())
    }
    async fn put_pem(
        &self,
        account: &str,
        domain: &str,
        account_credentials: Option<&str>,
        pem: Vec<Pem>,
    ) -> Result<(), GatewayError> {
        let base_path = format!("{}/{}", self.path, account);
        fs::create_dir_all(&base_path).await.unwrap();
        let domain_hash: String = self.domain_hash(domain);
        if let Some(account_credentials) = account_credentials {
            fs::File::create(format!("{}/{}.account", base_path, domain_hash))
                .await
                .unwrap()
                .write_all(account_credentials.as_bytes())
                .await
                .unwrap();
        }
        let pem_path = format!("{}/{}.pem", base_path, domain_hash);

        fs::File::create(pem_path)
            .await
            .unwrap()
            .write_all(pem::encode_many(&pem).as_bytes())
            .await
            .unwrap();

        let failed_path = format!("{}/{}.failed", base_path, domain_hash);
        let pending_path = format!("{}/{}.pending", base_path, domain_hash);

        _ = fs::remove_file(failed_path).await.unwrap();
        _ = fs::remove_file(pending_path).await.unwrap();

        Ok(())
    }
    async fn set_failed(&self, account: &str, domain: &str) -> Result<(), GatewayError> {
        let domain_hash = self.domain_hash(domain);
        let base_path = format!("{}/{}", self.path, account);
        fs::create_dir_all(&base_path).await.unwrap();
        let failed_path = format!("{}/{}.failed", base_path, domain_hash);
        let pending_path = format!("{}/{}.pending", base_path, domain_hash);
        Ok(fs::rename(pending_path, failed_path)
            .await
            .map(|_| ())
            .unwrap())
    }
    async fn is_failed(&self, account: &str, domain: &str) -> bool {
        let domain_hash = self.domain_hash(domain);
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
        let domain_hash = self.domain_hash(domain);
        let base_path = format!("{}/{}", self.path, account);
        let pending_path = format!("{}/{}.pending", base_path, domain_hash);
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        fs::create_dir_all(&base_path).await.unwrap();
        Ok(fs::write(pending_path, ts.to_string())
            .await
            .map(|_| ())
            .unwrap())
    }
    async fn is_pending(&self, account: &str, domain: &str) -> bool {
        let domain_hash = self.domain_hash(domain);
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
