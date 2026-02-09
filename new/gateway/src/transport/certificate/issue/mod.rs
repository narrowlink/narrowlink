use std::sync::Arc;

use self::acme::AcmeChallenges;

use super::CertificateStorage;
mod acme;
pub use acme::AcmeService;
use rustls::sign::CertifiedKey;
enum CertificateIssueStatus {
    Success,
    Failure,
    Pending,
    NotAvailable,
}

#[async_trait::async_trait]
pub trait CertificateIssue {
    fn issue(&self, uid: &str, domain: &str, private_key: Option<Vec<u8>>) -> Option<()>;
    fn storage(&self) -> Arc<dyn CertificateStorage>;
    fn challenge(&self, uid: &str, domain: &str) -> Option<Arc<AcmeChallenges>>;
    fn remove_from_cache(&self, uid: &str, domain: &str) -> Option<CertifiedKey>;
    async fn status(&self, uid: &str, domain: &str) -> CertificateIssueStatus {
        if self.storage().is_failed(uid, domain).await {
            CertificateIssueStatus::Failure
        } else if self.storage().is_pending(uid, domain).await {
            CertificateIssueStatus::Pending
        } else if self.storage().get_pem(uid, domain).await.is_ok() {
            CertificateIssueStatus::Success
        } else {
            CertificateIssueStatus::NotAvailable
        }
    }
}
