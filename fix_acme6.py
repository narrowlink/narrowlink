with open("gateway/src/service/certificate/acme.rs", "r") as f:
    content = f.read()

import re

# Fix mutability in new_order
content = content.replace("let auth = auth.map_err(|_| GatewayError::ACMEFailed)?;", "let mut auth = auth.map_err(|_| GatewayError::ACMEFailed)?;")

# Fix check_challenge
replacement = """                let has_tls = auth.challenges.iter().any(|c| c.r#type == instant_acme::ChallengeType::TlsAlpn01);
                let has_http = auth.challenges.iter().any(|c| c.r#type == instant_acme::ChallengeType::Http01);
                
                if has_tls {
                    auth.challenge(instant_acme::ChallengeType::TlsAlpn01).unwrap().set_ready().await.map_err(|_| GatewayError::ACMEFailed)?;
                } else if has_http {
                    auth.challenge(instant_acme::ChallengeType::Http01).unwrap().set_ready().await.map_err(|_| GatewayError::ACMEFailed)?;
                }"""

content = re.sub(
    r"let has_tls = auth\.challenge.*?GatewayError::ACMEFailed\)\?;\n\s*\}",
    replacement,
    content,
    flags=re.DOTALL
)

with open("gateway/src/service/certificate/acme.rs", "w") as f:
    f.write(content)
