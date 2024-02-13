use super::{CertificateResolver, CertificateStorage};
mod acme;
pub use acme::{AcmeConfig, ACME_TLS_ALPN_NAME};
enum CertificateIssueStatus {
    Success,
    Failure,
    Pending,
    NotAvailable,
}
trait CertificateIssue {
    async fn issue(&self, account: &str, domain: &str) -> Option<()>;
    fn status(&self, account: &str, domain: &str) -> CertificateIssueStatus;
    fn storage(&self) -> &dyn CertificateStorage;
}
