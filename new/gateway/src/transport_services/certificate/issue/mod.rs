use super::{CertificateResolver, CertificateStorage};
mod acme;
pub use acme::{AcmeService, ACME_TLS_ALPN_NAME};
enum CertificateIssueStatus {
    Success,
    Failure,
    Pending,
    NotAvailable,
}
pub trait CertificateIssue {
    fn issue(&self, account: &str, domain: &str) -> Option<()>;
    fn status(&self, account: &str, domain: &str) -> CertificateIssueStatus;
    fn storage(&self) -> &dyn CertificateStorage;
}
