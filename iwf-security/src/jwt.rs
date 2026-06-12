//! JWT validation for the admin API and (optionally) inbound SBA
//! notifications: signature, expiry, audience and scope are all enforced;
//! any failure rejects the token.

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use thiserror::Error;

/// Validation failures. Deliberately coarse — detail goes to logs, not to
/// the caller, to avoid oracle behaviour.
#[derive(Debug, Error)]
pub enum JwtError {
    /// Signature, structure, expiry or audience failed.
    #[error("token rejected")]
    Rejected,
    /// Token verified but lacks a required scope.
    #[error("insufficient scope")]
    InsufficientScope,
}

/// Claims the IWF cares about.
#[derive(Debug, Clone, Deserialize)]
pub struct ValidatedClaims {
    /// Subject (client id of the caller).
    pub sub: String,
    /// Space-separated OAuth scopes.
    #[serde(default)]
    pub scope: String,
    /// Expiry (validated by the library; kept for diagnostics).
    pub exp: u64,
}

impl ValidatedClaims {
    /// Whether `wanted` appears in the space-separated scope list.
    pub fn has_scope(&self, wanted: &str) -> bool {
        self.scope.split(' ').any(|s| s == wanted)
    }
}

/// Reusable validator bound to a key, algorithm and expected audience.
pub struct JwtValidator {
    key: DecodingKey,
    validation: Validation,
}

impl std::fmt::Debug for JwtValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtValidator").finish()
    }
}

impl JwtValidator {
    /// Validator for RS256 tokens (production: NRF / authorization server
    /// public key in PEM).
    pub fn rs256(public_key_pem: &[u8], audience: &str) -> Result<Self, JwtError> {
        let key = DecodingKey::from_rsa_pem(public_key_pem).map_err(|_| JwtError::Rejected)?;
        Ok(Self::with_key(key, Algorithm::RS256, audience))
    }

    /// Validator for HS256 tokens (tests and lab deployments).
    pub fn hs256(secret: &[u8], audience: &str) -> Self {
        Self::with_key(DecodingKey::from_secret(secret), Algorithm::HS256, audience)
    }

    fn with_key(key: DecodingKey, alg: Algorithm, audience: &str) -> Self {
        let mut validation = Validation::new(alg);
        validation.set_audience(&[audience]);
        validation.validate_exp = true;
        validation.leeway = 5;
        JwtValidator { key, validation }
    }

    /// Validate signature/exp/aud and require `required_scope`.
    pub fn validate(&self, token: &str, required_scope: &str) -> Result<ValidatedClaims, JwtError> {
        let data = jsonwebtoken::decode::<ValidatedClaims>(token, &self.key, &self.validation)
            .map_err(|e| {
                tracing::debug!(error = %e, "jwt rejected");
                JwtError::Rejected
            })?;
        if !data.claims.has_scope(required_scope) {
            return Err(JwtError::InsufficientScope);
        }
        Ok(data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde::Serialize;

    #[derive(Serialize)]
    struct TestClaims<'a> {
        sub: &'a str,
        aud: &'a str,
        scope: &'a str,
        exp: u64,
    }

    fn token(aud: &str, scope: &str, exp_offset: i64) -> String {
        let exp = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs() as i64
            + exp_offset) as u64;
        encode(
            &Header::new(Algorithm::HS256),
            &TestClaims {
                sub: "admin-cli",
                aud,
                scope,
                exp,
            },
            &EncodingKey::from_secret(b"unit-test-secret"),
        )
        .expect("encode")
    }

    fn validator() -> JwtValidator {
        JwtValidator::hs256(b"unit-test-secret", "iwf-admin")
    }

    #[test]
    fn valid_token_with_scope_passes() {
        let claims = validator()
            .validate(
                &token("iwf-admin", "iwf:operator iwf:read", 600),
                "iwf:operator",
            )
            .expect("valid");
        assert_eq!(claims.sub, "admin-cli");
    }

    #[test]
    fn expired_token_rejected() {
        assert!(matches!(
            validator().validate(&token("iwf-admin", "iwf:operator", -600), "iwf:operator"),
            Err(JwtError::Rejected)
        ));
    }

    #[test]
    fn wrong_audience_rejected() {
        assert!(matches!(
            validator().validate(&token("other-api", "iwf:operator", 600), "iwf:operator"),
            Err(JwtError::Rejected)
        ));
    }

    #[test]
    fn missing_scope_rejected() {
        assert!(matches!(
            validator().validate(&token("iwf-admin", "iwf:read", 600), "iwf:operator"),
            Err(JwtError::InsufficientScope)
        ));
    }

    #[test]
    fn garbage_rejected() {
        assert!(validator().validate("not.a.jwt", "iwf:operator").is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let other = JwtValidator::hs256(b"different-secret", "iwf-admin");
        assert!(other
            .validate(&token("iwf-admin", "iwf:operator", 600), "iwf:operator")
            .is_err());
    }
}
