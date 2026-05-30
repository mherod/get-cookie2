use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cookie {
    pub domain: String,
    pub name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry: Option<DateTime<Utc>>,
    pub meta: CookieMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieMeta {
    pub file: String,
    pub browser: String,
    pub decrypted: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum Browser {
    Chrome,
    Safari,
    Firefox,
    Arc,
    Edge,
    Opera,
}

impl Browser {
    pub fn as_str(&self) -> &str {
        match self {
            Browser::Chrome => "Chrome",
            Browser::Safari => "Safari",
            Browser::Firefox => "Firefox",
            Browser::Arc => "Arc",
            Browser::Edge => "Edge",
            Browser::Opera => "Opera",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CookieQuery {
    pub name_pattern: String,
    pub domain_pattern: Option<String>,
    pub include_expired: bool,
}
