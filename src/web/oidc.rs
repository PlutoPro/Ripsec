//! OpenID Connect authorization code flow with PKCE. Works with any compliant provider.

use crate::config::Oidc;
use crate::ike::crypto;
use aws_lc_rs::digest;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::Value;
use std::sync::OnceLock;
use std::time::Duration;

#[derive(Deserialize)]
pub struct Provider {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    pub end_session_endpoint: Option<String>,
}

pub struct Identity {
    pub subject: String,
    pub name: String,
    pub roles: Vec<String>,
}

pub struct Client {
    pub config: Oidc,
    redirect_uri: String,
    agent: ureq::Agent,
    provider: OnceLock<Provider>,
}

pub fn token() -> String {
    URL_SAFE_NO_PAD.encode(crypto::random::<32>())
}

fn encode_query(pairs: &[(&str, &str)]) -> String {
    let escape = |s: &str| {
        s.bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                    char::from(b).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect::<String>()
    };
    pairs.iter().map(|(k, v)| format!("{k}={}", escape(v))).collect::<Vec<_>>().join("&")
}

/// Reads a role list from a claim name or a dot separated path such as `realm_access.roles`.
pub fn roles(claims: &Value, path: &str) -> Vec<String> {
    let value = claims.get(path).or_else(|| path.split('.').try_fold(claims, |v, k| v.get(k)));
    match value {
        Some(Value::Array(items)) => items.iter().filter_map(|v| v.as_str().map(String::from)).collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

impl Client {
    pub fn new(config: Oidc, public_url: &str) -> Client {
        let agent =
            ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(10))).build().into();
        Client {
            config,
            redirect_uri: format!("{public_url}/auth/callback"),
            agent,
            provider: OnceLock::new(),
        }
    }

    /// Discovery happens on first use, so the provider may start after we do. Blocking.
    pub fn provider(&self) -> Result<&Provider, String> {
        if let Some(p) = self.provider.get() {
            return Ok(p);
        }
        let base = self.config.discovery_url.clone().unwrap_or_else(|| {
            format!("{}/.well-known/openid-configuration", self.config.issuer.trim_end_matches('/'))
        });
        let provider: Provider = self
            .agent
            .get(&base)
            .call()
            .map_err(|e| format!("discovery: {e}"))?
            .body_mut()
            .read_json()
            .map_err(|e| format!("discovery: {e}"))?;
        if provider.issuer != self.config.issuer {
            return Err(format!("provider reports issuer {:?}", provider.issuer));
        }
        Ok(self.provider.get_or_init(|| provider))
    }

    pub fn authorization_url(&self, state: &str, nonce: &str, verifier: &str) -> Result<String, String> {
        let endpoint = &self.provider()?.authorization_endpoint;
        let challenge = URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, verifier.as_bytes()));
        let query = encode_query(&[
            ("response_type", "code"),
            ("client_id", &self.config.client_id),
            ("redirect_uri", &self.redirect_uri),
            ("scope", &self.config.scopes),
            ("state", state),
            ("nonce", nonce),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ]);
        let separator = if endpoint.contains('?') { '&' } else { '?' };
        Ok(format!("{endpoint}{separator}{query}"))
    }

    /// Exchanges the code and verifies the ID token. Blocking.
    pub fn redeem(&self, code: &str, verifier: &str, nonce: &str) -> Result<Identity, String> {
        let provider = self.provider()?;
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("client_id", self.config.client_id.as_str()),
            ("code_verifier", verifier),
        ];
        if let Some(secret) = &self.config.client_secret {
            form.push(("client_secret", secret));
        }
        let response: Value = self
            .agent
            .post(&provider.token_endpoint)
            .send_form(form)
            .map_err(|e| format!("token endpoint: {e}"))?
            .body_mut()
            .read_json()
            .map_err(|e| format!("token endpoint: {e}"))?;
        let id_token = response["id_token"].as_str().ok_or("no id_token in response")?;
        let keys: JwkSet = self
            .agent
            .get(&provider.jwks_uri)
            .call()
            .map_err(|e| format!("jwks: {e}"))?
            .body_mut()
            .read_json()
            .map_err(|e| format!("jwks: {e}"))?;
        self.verify(id_token, &keys, nonce)
    }

    fn verify(&self, id_token: &str, keys: &JwkSet, nonce: &str) -> Result<Identity, String> {
        let header = jsonwebtoken::decode_header(id_token).map_err(|e| e.to_string())?;
        // Public key algorithms only, so a public key can never be used as an HMAC secret.
        if matches!(header.alg, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512) {
            return Err("ID token uses a symmetric algorithm".into());
        }
        let key = match &header.kid {
            Some(kid) => keys.find(kid),
            None if keys.keys.len() == 1 => keys.keys.first(),
            None => None,
        }
        .ok_or("no matching signing key")?;
        let key = DecodingKey::from_jwk(key).map_err(|e| e.to_string())?;
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.client_id]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        let claims = jsonwebtoken::decode::<Value>(id_token, &key, &validation)
            .map_err(|e| format!("ID token: {e}"))?
            .claims;
        if claims["nonce"].as_str() != Some(nonce) {
            return Err("ID token nonce mismatch".into());
        }
        if claims["azp"].as_str().is_some_and(|azp| azp != self.config.client_id) {
            return Err("ID token was issued to another client".into());
        }
        let subject = claims["sub"].as_str().filter(|s| !s.is_empty()).ok_or("no subject")?;
        let name = ["preferred_username", "email", "name"]
            .iter()
            .find_map(|k| claims[*k].as_str())
            .unwrap_or(subject);
        Ok(Identity {
            subject: subject.to_string(),
            name: name.to_string(),
            roles: roles(&claims, &self.config.roles_claim),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn finds_roles_in_common_claim_shapes() {
        let c = json!({"realm_access": {"roles": ["a"]}, "groups": ["b"], "https://x.example/roles": ["c"]});
        assert_eq!(roles(&c, "realm_access.roles"), ["a"]);
        assert_eq!(roles(&c, "groups"), ["b"]);
        assert_eq!(roles(&c, "https://x.example/roles"), ["c"]);
        assert!(roles(&c, "missing.path").is_empty());
    }

    #[test]
    fn escapes_query_values() {
        assert_eq!(encode_query(&[("a", "x y&z"), ("b", "1")]), "a=x%20y%26z&b=1");
    }
}
