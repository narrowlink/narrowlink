with open("gateway/src/service/certificate/acme.rs", "r") as f:
    content = f.read()

content = content.replace("let auths_stream = order.authorizations();", "let mut auths_stream = order.authorizations();")
content = content.replace("if let Some(challenge) = auth.challenge(instant_acme::ChallengeType::TlsAlpn01) {\n                    challenge.set_ready().await", "let mut tls_alpn_challenge = auth.challenge(instant_acme::ChallengeType::TlsAlpn01);\n                if let Some(mut challenge) = tls_alpn_challenge {\n                    challenge.set_ready().await")
content = content.replace("} else if let Some(challenge) = auth.challenge(instant_acme::ChallengeType::Http01) {\n                    challenge.set_ready().await", "}\n                let mut http_challenge = auth.challenge(instant_acme::ChallengeType::Http01);\n                if let Some(mut challenge) = http_challenge {\n                    challenge.set_ready().await")

with open("gateway/src/service/certificate/acme.rs", "w") as f:
    f.write(content)
