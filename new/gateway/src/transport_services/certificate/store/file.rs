use pem::Pem;

use std::time::SystemTime;
use tokio::{fs, io::AsyncWriteExt, sync::RwLock};

use crate::{error::GatewayCertificateError, transport_services::certificate::CertificateStorage};
pub struct CertificateFileStorage {
    path: String,
    default_account: RwLock<Option<String>>,
}

impl CertificateFileStorage {
    pub fn new(path: String) -> Self {
        Self {
            path,
            default_account: RwLock::new(None),
        }
    }
}

impl Default for CertificateFileStorage {
    fn default() -> Self {
        Self::new("./certificates".to_string())
    }
}
#[async_trait::async_trait]
impl CertificateStorage for CertificateFileStorage {
    async fn get_account_credentials(&self, uid: &str) -> Result<String, GatewayCertificateError> {
        let default_account = self.default_account.read().await.clone();
        if let Some(account) = default_account {
            return Ok(account);
        } else {
            let default_account = fs::read_to_string(format!("{}/{}/account.json", self.path, uid))
                .await
                .map_err(GatewayCertificateError::AccountNotFound)?;
            self.default_account
                .write()
                .await
                .replace(default_account.clone());
            return Ok(default_account);
        }
    }
    async fn set_account_credentials(
        &self,
        account: &str,
        uid: &str,
    ) -> Result<(), GatewayCertificateError> {
        let base_path = format!("{}/{}", self.path, uid);
        fs::create_dir_all(&base_path).await?;
        let default_account_path = format!("{}/account.json", base_path);
        fs::File::create(default_account_path)
            .await?
            .write_all(account.as_bytes())
            .await?;
        self.default_account
            .write()
            .await
            .replace(account.to_string());
        Ok(())
    }
    async fn get_pem(&self, uid: &str, domain: &str) -> Result<Vec<Pem>, GatewayCertificateError> {
        pem::parse_many(
            fs::read_to_string(format!(
                "{}/{}/{}.pem",
                self.path,
                uid,
                self.domain_hash(domain)
            ))
            .await
            .map_err(|_| GatewayCertificateError::CertificateNotFound)?,
        )
        .map_err(GatewayCertificateError::InvalidPem)
    }
    async fn put_pem(
        &self,
        uid: &str,
        domain: &str,
        pem: Vec<Pem>,
    ) -> Result<(), GatewayCertificateError> {
        let base_path = format!("{}/{}", self.path, uid);
        fs::create_dir_all(&base_path).await?;
        let domain_hash: String = self.domain_hash(domain);
        let pem_path = format!("{}/{}.pem", base_path, domain_hash);

        fs::File::create(pem_path)
            .await?
            .write_all(pem::encode_many(&pem).as_bytes())
            .await?;

        let failed_path = format!("{}/{}.failed", base_path, domain_hash);
        let pending_path = format!("{}/{}.pending", base_path, domain_hash);

        _ = fs::remove_file(failed_path).await;
        _ = fs::remove_file(pending_path).await;

        Ok(())
    }
    async fn set_failed(&self, uid: &str, domain: &str) -> Result<(), GatewayCertificateError> {
        let domain_hash = self.domain_hash(domain);
        let base_path = format!("{}/{}", self.path, uid);
        fs::create_dir_all(&base_path).await?;
        let failed_path = format!("{}/{}.failed", base_path, domain_hash);
        let pending_path = format!("{}/{}.pending", base_path, domain_hash);
        Ok(fs::rename(pending_path, failed_path).await?)
    }
    async fn is_failed(&self, uid: &str, domain: &str) -> bool {
        let domain_hash = self.domain_hash(domain);
        let failed_path = format!("{}/{}/{}.failed", self.path, uid, domain_hash);
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        fs::read_to_string(failed_path)
            .await
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v + 60 * 60 > ts) // 1 hour
            .is_some()
    }
    async fn set_pending(&self, uid: &str, domain: &str) -> Result<(), GatewayCertificateError> {
        let domain_hash = self.domain_hash(domain);
        let base_path = format!("{}/{}", self.path, uid);
        let pending_path = format!("{}/{}.pending", base_path, domain_hash);
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        fs::create_dir_all(&base_path).await?;
        Ok(fs::write(pending_path, ts.to_string()).await?)
    }
    async fn is_pending(&self, uid: &str, domain: &str) -> bool {
        let domain_hash = self.domain_hash(domain);
        let pending_path = format!("{}/{}/{}.pending", self.path, uid, domain_hash);
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        fs::read_to_string(pending_path)
            .await
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v + 120 > ts) // 120 seconds
            .is_some()
    }
}
