use std::time::SystemTime;

use rustls::sign::CertifiedKey;
use x509_parser::{certificate::X509Certificate, der_parser::asn1_rs::FromDer};

pub trait CertificateValidation {
    fn expiration(&self) -> u64;
    fn is_expired(&self) -> bool {
        self.days_until_expiration() == 0
    }
    fn days_until_expiration(&self) -> u64 {
        let expiration = self.expiration();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if expiration > now {
            (expiration - now) / 60 / 60 / 24
        } else {
            0
        }
    }
}

impl CertificateValidation for CertifiedKey {
    fn expiration(&self) -> u64 {
        let mut expiration = u64::MAX;
        for cert in &self.cert {
            if let Ok((_, parsed_cert)) = X509Certificate::from_der(&cert) {
                let not_after = parsed_cert.validity().not_after.timestamp().unsigned_abs();
                if not_after < expiration {
                    expiration = not_after;
                }
            }
        }
        expiration
    }
}
