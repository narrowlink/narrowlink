mod file;
pub use file::CertificateFileStorage;
trait CertificateStore {
    async fn get(&self, account: &str, domain: &str) -> Option<()>;
}
