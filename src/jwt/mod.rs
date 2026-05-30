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
