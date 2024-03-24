use std::sync::Arc;

use rustls::sign::CertifiedKey;

pub trait CertificateCache {
    fn get(&self, uid: &str, domain: &str) -> Option<Arc<CertifiedKey>>;
    fn put(&self, uid: &str, domain: &str, config: CertifiedKey);
    fn remove(&self, uid: &str, domain: &str) -> Option<CertifiedKey>;
}

pub struct DashMapCache(Arc<dashmap::DashMap<String, Arc<CertifiedKey>>>);

impl CertificateCache for DashMapCache {
    fn get(&self, uid: &str, domain: &str) -> Option<Arc<CertifiedKey>> {
        self.0
            .get(&format!("{}:{}", uid, domain))
            .map(|x| x.value().clone())
    }
    fn put(&self, uid: &str, domain: &str, config: CertifiedKey) {
        self.0
            .insert(format!("{}:{}", uid, domain), Arc::new(config));
    }
    fn remove(&self, uid: &str, domain: &str) -> Option<CertifiedKey> {
        self.0
            .remove(&format!("{}:{}", uid, domain))
            .map(|c| Arc::<CertifiedKey>::unwrap_or_clone(c.1))
    }
}

impl Default for DashMapCache {
    fn default() -> Self {
        Self(Arc::new(dashmap::DashMap::new()))
    }
}