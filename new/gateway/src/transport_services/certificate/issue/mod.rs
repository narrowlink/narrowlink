use std::sync::Arc;

use self::acme::AcmeKeyAuthorization;

use super::{CertificateResolver, CertificateStorage};
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
    fn issue(&self, account: &str, domain: &str) -> Option<()>;
    fn storage(&self) -> Arc<dyn CertificateStorage>;
    fn challenge(&self, account: &str, domain: &str) -> Option<Arc<AcmeKeyAuthorization>>;
    fn remove_from_cache(&self, account: &str, domain: &str) -> Option<CertifiedKey>;
    async fn status(&self, account: &str, domain: &str) -> CertificateIssueStatus {
        if self.storage().is_failed(account, domain).await {
            CertificateIssueStatus::Failure
        } else if self.storage().is_pending(account, domain).await {
            CertificateIssueStatus::Pending
        } else if self.storage().get_pem(account, domain).await.is_ok() {
            CertificateIssueStatus::Success
        } else {
            CertificateIssueStatus::NotAvailable
        }
    }
}
