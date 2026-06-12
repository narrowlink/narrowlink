use rcgen::{CertificateParams, DistinguishedName, KeyPair};
pub fn create_csr(domains: Vec<String>) -> Result<Vec<u8>, rcgen::Error> {
    let key_pair = KeyPair::generate()?;
    let mut params = CertificateParams::new(domains)?;
    params.distinguished_name = DistinguishedName::new();
    let csr = params.serialize_request(&key_pair)?;
    Ok(csr.der().to_vec())
}
