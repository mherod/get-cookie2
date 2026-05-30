use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtInfo {
    pub header: Value,
    pub claims: Value,
    pub is_valid: bool,
}

/// Detect if a string is a JWT token
pub fn is_jwt(value: &str) -> bool {
    // JWT has 3 parts separated by dots
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 3 {
        return false;
    }

    // Try to decode the header
    decode_header(value).is_ok()
}

/// Decode a JWT token without signature verification
pub fn decode_jwt(token: &str) -> Option<JwtInfo> {
    if !is_jwt(token) {
        return None;
    }

    // Decode header
    let header = match decode_header(token) {
        Ok(h) => serde_json::to_value(h).ok()?,
        Err(_) => return None,
    };

    // Decode claims without any signature/expiry validation
    let token_data = jsonwebtoken::dangerous::insecure_decode::<Value>(token).ok()?;

    Some(JwtInfo {
        header,
        claims: token_data.claims,
        is_valid: false, // We didn't verify signature
    })
}

/// Validate JWT signature with a secret
pub fn validate_jwt(token: &str, secret: &str) -> Option<JwtInfo> {
    let header = decode_header(token).ok()?;

    let validation = Validation::new(header.alg);

    let token_data = decode::<Value>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .ok()?;

    Some(JwtInfo {
        header: serde_json::to_value(header).ok()?,
        claims: token_data.claims,
        is_valid: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;

    /// Build an HS256 token signed with `secret`. A far-future `exp` claim is
    /// included so the default `validate_jwt` expiry check passes.
    fn make_token(secret: &str) -> String {
        let claims = json!({ "sub": "user-123", "name": "Test User", "exp": 9_999_999_999i64 });
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    #[test]
    fn is_jwt_accepts_real_token() {
        assert!(is_jwt(&make_token("secret")));
    }

    #[test]
    fn is_jwt_rejects_non_tokens() {
        assert!(!is_jwt("not-a-jwt"));
        assert!(!is_jwt("only.two")); // wrong segment count
        assert!(!is_jwt("plain.text.value")); // 3 parts but header is not valid JWT
    }

    #[test]
    fn decode_jwt_returns_claims_without_verification() {
        // decode_jwt must succeed regardless of the signing secret because it
        // performs no signature or expiry validation.
        let token = make_token("whatever-secret");
        let info = decode_jwt(&token).expect("valid JWT should decode");
        assert_eq!(info.claims["sub"], "user-123");
        assert_eq!(info.claims["name"], "Test User");
        assert!(!info.is_valid); // unverified
    }

    #[test]
    fn decode_jwt_rejects_non_token() {
        assert!(decode_jwt("not-a-jwt").is_none());
    }

    #[test]
    fn validate_jwt_accepts_correct_secret() {
        let token = make_token("correct-secret");
        let info = validate_jwt(&token, "correct-secret").expect("signature should validate");
        assert_eq!(info.claims["sub"], "user-123");
        assert!(info.is_valid);
    }

    #[test]
    fn validate_jwt_rejects_wrong_secret() {
        let token = make_token("correct-secret");
        assert!(validate_jwt(&token, "wrong-secret").is_none());
    }
}
