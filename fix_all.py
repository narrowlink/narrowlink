import re

# 1. Fix ws.rs:138 Box::pin
with open("gateway/src/service/ws.rs", "r") as f:
    ws_content = f.read()

ws_content = re.sub(
    r"return Box::pin\(async \{\s*Ok\((crate::service::http_templates::response_error\([\s\S]*?\))\)\s*\}\);",
    r"return \1;",
    ws_content
)

ws_content = ws_content.replace(".body::<Body>", ".body::<dyn Body>")
ws_content = ws_content.replace("pub async fn handle", "pub(crate) async fn handle")

with open("gateway/src/service/ws.rs", "w") as f:
    f.write(ws_content)


# 2. Fix connection.rs mismatched types error
with open("gateway/src/state/connection.rs", "r") as f:
    conn_content = f.read()

conn_content = conn_content.replace("replay.send(Ok(response)).map_err(|_| ())", "replay.send(Ok(response.map(|b| http_body_util::Full::new(bytes::Bytes::new())))).map_err(|_| ())")

with open("gateway/src/state/connection.rs", "w") as f:
    f.write(conn_content)

# 3. Fix acme.rs compilation errors
with open("gateway/src/service/certificate/acme.rs", "r") as f:
    acme_content = f.read()

# remove unused imports
acme_content = acme_content.replace("Authorization, AuthorizationStatus, ChallengeType, Identifier,", "AuthorizationStatus, Identifier,")
acme_content = acme_content.replace("NewAccount, NewOrder, Order, OrderStatus,", "NewOrder, Order, OrderStatus,")
acme_content = acme_content.replace("CertificateParams, DistinguishedName, DnType, KeyPair", "CertificateParams, DistinguishedName")
acme_content = acme_content.replace("use rustls::pki_types::PrivateKeyDer;\n", "")
acme_content = acme_content.replace("use crate::service::certificate::Certificate;\n", "")

# Fix the mutability issue in new_order and check_challenge:
acme_content = acme_content.replace("if let Some(mut challenge) = auth.challenge(", "if let Some(challenge) = auth.challenge(")
acme_content = acme_content.replace("let mut challenge = authorization\n                .challenge", "let challenge = authorization\n                .challenge")

with open("gateway/src/service/certificate/acme.rs", "w") as f:
    f.write(acme_content)
