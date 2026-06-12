with open("gateway/src/service/certificate/acme.rs", "r") as f:
    content = f.read()

import re
replacement = """        let mut has_invalid = false;
        let mut any_valid = false;
        let mut challenges = Vec::new();

        {
            let mut auths_stream = order.authorizations();
            while let Some(auth) = auths_stream.next().await {
                let auth = auth.map_err(|_| GatewayError::ACMEFailed)?;
                if !matches!(
                    auth.status,
                    AuthorizationStatus::Pending | AuthorizationStatus::Valid
                ) {
                    has_invalid = true;
                }
                if matches!(auth.status, AuthorizationStatus::Valid) {
                    any_valid = true;
                } else {
                    let identifier = auth.identifier().to_string();
                    let challenge = auth
                        .challenge(instant_acme::ChallengeType::TlsAlpn01)
                        .ok_or(GatewayError::ACMEFailed)?;

                    let key_auth = challenge.key_authorization();
                    let digest = ring::digest::digest(
                        &ring::digest::SHA256,
                        key_auth.as_str().as_bytes(),
                    );
                    challenges.push((
                        challenge.url.clone(),
                        identifier.to_owned(),
                        digest.as_ref().to_vec(),
                    ));
                }
            }
        }

        if has_invalid {
            return Err(GatewayError::ACMEFailed);
        }

        if any_valid {
            let key_pair = suggested_private_key
                .and_then(|private_key| rcgen::KeyPair::try_from(private_key.secret_der()).ok())
                .unwrap_or_else(|| rcgen::KeyPair::generate().unwrap());
            let mut params = rcgen::CertificateParams::new(domains.clone()).map_err(|_| GatewayError::ACMEFailed)?;
            params.distinguished_name = rcgen::DistinguishedName::new();
            let csr = params.serialize_request(&key_pair).map_err(|_| GatewayError::ACMEFailed)?.der().to_vec();
            order.finalize_csr(&csr).await.map_err(|_| GatewayError::ACMEFailed)?;
            let cert_chain_pem = loop {
                match order.certificate().await.map_err(|_| GatewayError::ACMEFailed)? {
                    Some(cert_chain_pem) => break cert_chain_pem,
                    None => tokio::time::sleep(tokio::time::Duration::from_secs(1)).await,
                }
            };

            return pem::parse_many(cert_chain_pem).map_err(|_| GatewayError::ACMEFailed).and_then(
                |mut c| {
                    pem::parse(key_pair.serialize_pem()).map_err(|_| GatewayError::ACMEFailed).map(|p| {
                        c.push(p);
                        Some(c)
                    })
                },
            );
        }

        self.order = Some(order);
        Ok(None)
    }"""

content = re.sub(r'        use futures_util::StreamExt;.*?Ok\(None\)\n    \}', replacement, content, flags=re.DOTALL)

with open("gateway/src/service/certificate/acme.rs", "w") as f:
    f.write(content)

