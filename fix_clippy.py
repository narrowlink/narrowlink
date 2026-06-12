import re
import glob

# Fix tun.rs
tun_path = "client/src/tunnel/tun.rs"
with open(tun_path, "r") as f:
    content = f.read()
content = content.replace("ipstack_config.mtu(MTU as u16);", "let _ = ipstack_config.mtu(MTU as u16);")
with open(tun_path, "w") as f:
    f.write(content)

# Fix acme.rs
acme_path = "gateway/src/service/certificate/acme.rs"
with open(acme_path, "r") as f:
    content = f.read()
content = content.replace("use futures_util::StreamExt;\n", "")
content = content.replace("pub struct ChallengeInfo {", "#[allow(dead_code)]\npub struct ChallengeInfo {")
content = content.replace("pub enum ACMEChallenge {", "#[allow(dead_code)]\npub enum ACMEChallenge {")
content = content.replace("rcgen::KeyPair::generate().unwrap()", 'rcgen::KeyPair::generate().expect("Failed to generate key pair")')
content = content.replace("auth.challenge(instant_acme::ChallengeType::TlsAlpn01).unwrap()", 'auth.challenge(instant_acme::ChallengeType::TlsAlpn01).expect("TLS ALPN 01 challenge not found")')
content = content.replace("auth.challenge(instant_acme::ChallengeType::Http01).unwrap()", 'auth.challenge(instant_acme::ChallengeType::Http01).expect("HTTP 01 challenge not found")')
with open(acme_path, "w") as f:
    f.write(content)

# Fix error.rs
err_path = "gateway/src/error.rs"
with open(err_path, "r") as f:
    content = f.read()
content = content.replace("RcgenError(#[from] rcgen::RcgenError),", "RcgenError(#[from] rcgen::Error),")
with open(err_path, "w") as f:
    f.write(content)

# Fix ws.rs unwrap()
ws_path = "gateway/src/service/ws.rs"
with open(ws_path, "r") as f:
    content = f.read()
content = content.replace(".unwrap()", '.expect("Expected operation to succeed")')
with open(ws_path, "w") as f:
    f.write(content)

# Fix remaining unused imports and clippy warnings
