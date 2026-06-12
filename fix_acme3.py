with open("gateway/src/service/certificate/acme.rs", "r") as f:
    content = f.read()

content = content.replace("#[derive(Debug)]\npub struct ChallengeInfo {", "#[derive(Debug, Clone)]\npub struct ChallengeInfo {")

# find get_tls_alpn_01_certificate_challenges and replace it entirely
import re
new_get_tls = """    pub fn get_tls_alpn_01_certificate_challenges(
        &self,
    ) -> Result<Vec<ChallengeInfo>, GatewayError> {
        Ok(self.challenges.iter().filter(|c| matches!(c.challenge, ACMEChallenge::TlsAlpn01(_))).cloned().collect())
    }

    pub fn get_http_01_certificate_challenges(&self) -> Result<Vec<ChallengeInfo>, GatewayError> {
        Ok(self.challenges.iter().filter(|c| matches!(c.challenge, ACMEChallenge::Http01(_, _))).cloned().collect())
    }

    pub async fn check_challenge("""

# replace everything from pub fn get_tls_alpn_01_certificate_challenges to pub async fn check_challenge
content = re.sub(
    r'pub fn get_tls_alpn_01_certificate_challenges.*?pub async fn check_challenge\(',
    new_get_tls,
    content,
    flags=re.DOTALL
)

with open("gateway/src/service/certificate/acme.rs", "w") as f:
    f.write(content)
