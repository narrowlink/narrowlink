enum CertificateIssueStatus {
    Success,
    Failure,
    Pending,
    NotAvailable,
}
trait CertificateIssue {
    async fn issue(&self, account: &str, domain: &str) -> Option<()>;
    fn status(&self, account: &str, domain: &str) -> CertificateIssueStatus;
}
