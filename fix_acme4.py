with open("gateway/src/service/certificate/acme.rs", "r") as f:
    content = f.read()

import re

def replacer(match):
    return """
                let has_tls = auth.challenge(instant_acme::ChallengeType::TlsAlpn01).is_some();
                let has_http = auth.challenge(instant_acme::ChallengeType::Http01).is_some();
                if has_tls {
                    auth.challenge(instant_acme::ChallengeType::TlsAlpn01).unwrap().set_ready().await.map_err(|_| GatewayError::ACMEFailed)?;
                } else if has_http {
                    auth.challenge(instant_acme::ChallengeType::Http01).unwrap().set_ready().await.map_err(|_| GatewayError::ACMEFailed)?;
                }
"""

content = re.sub(
    r"let mut tls_alpn_challenge.*?challenge\.set_ready\(\)\.await.*?\}",
    replacer,
    content,
    flags=re.DOTALL
)

with open("gateway/src/service/certificate/acme.rs", "w") as f:
    f.write(content)
