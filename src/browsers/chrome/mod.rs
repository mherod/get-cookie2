use crate::browsers::BrowserCookieReader;
use crate::crypto;
use crate::types::{Browser, Cookie, CookieMeta, CookieQuery};
use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};
use rusqlite::Connection;
use std::path::PathBuf;

fn get_meta_version(conn: &Connection) -> Result<i64> {
    let version_str: String = conn
        .query_row("SELECT value FROM meta WHERE key = 'version'", [], |row| {
            row.get(0)
        })
        .unwrap_or_default();

    Ok(version_str.parse::<i64>().unwrap_or(0))
}

pub struct ChromeCookieReader {
    browser: Browser,
}

impl ChromeCookieReader {
    pub fn new(browser: Browser) -> Self {
        Self { browser }
    }

    fn get_base_path(&self) -> PathBuf {
        let home = dirs::home_dir().expect("Failed to get home directory");
        match self.browser {
            Browser::Chrome => home.join("Library/Application Support/Google/Chrome"),
            Browser::Arc => home.join("Library/Application Support/Arc"),
            Browser::Edge => home.join("Library/Application Support/Microsoft Edge"),
            _ => home.join("Library/Application Support/Google/Chrome"),
        }
    }

    fn chrome_timestamp_to_utc(timestamp: i64) -> Option<DateTime<Utc>> {
        // Chrome uses microseconds since 1601-01-01
        const EPOCH_DELTA: i64 = 11644473600; // Seconds between 1601 and 1970

        if timestamp == 0 {
            return None;
        }

        let seconds = (timestamp / 1_000_000) - EPOCH_DELTA;
        Utc.timestamp_opt(seconds, 0).single()
    }
}

impl BrowserCookieReader for ChromeCookieReader {
    fn find_cookie_stores(&self) -> Result<Vec<String>> {
        let base_path = self.get_base_path();
        let mut stores = Vec::new();

        // Default profile
        let default_cookies = base_path.join("Default/Cookies");
        if default_cookies.exists() {
            stores.push(default_cookies.to_string_lossy().to_string());
        }

        // Additional profiles (Profile 1, Profile 2, etc.)
        for entry in std::fs::read_dir(&base_path).context("Failed to read Chrome directory")? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                let profile_name = path.file_name().unwrap().to_string_lossy();
                if profile_name.starts_with("Profile ") {
                    let cookies_path = path.join("Cookies");
                    if cookies_path.exists() {
                        stores.push(cookies_path.to_string_lossy().to_string());
                    }
                }
            }
        }

        Ok(stores)
    }

    fn read_cookies(&self, store_path: &str, query: &CookieQuery) -> Result<Vec<Cookie>> {
        // Copy database to temp location to avoid locks
        let temp_path = format!("/tmp/cookies_{}.db", std::process::id());
        std::fs::copy(store_path, &temp_path).context("Failed to copy cookie database")?;

        let conn = Connection::open(&temp_path).context("Failed to open cookie database")?;

        let meta_version = get_meta_version(&conn).unwrap_or(0);

        // Pre-fetch the Chrome decryption key once for all cookies in this store.
        // This prevents multiple Keychain permission dialogs - the key is cached
        // globally so even multiple profile reads will only prompt once.
        let chrome_key =
            crypto::get_chrome_key_cached().context("Failed to get Chrome encryption key")?;

        let mut sql = String::from(
            "SELECT host_key, name, encrypted_value, expires_utc FROM cookies WHERE 1=1",
        );

        let use_name_filter = query.name_pattern != "%";
        let use_domain_filter = query
            .domain_pattern
            .as_ref()
            .map(|d| d != "%")
            .unwrap_or(false);

        // Add name pattern filter
        if use_name_filter {
            sql.push_str(" AND name LIKE ?1");
        }

        // Add domain filter
        if use_domain_filter {
            if use_name_filter {
                sql.push_str(" AND host_key LIKE ?2");
            } else {
                sql.push_str(" AND host_key LIKE ?1");
            }
        }

        let mut stmt = conn.prepare(&sql)?;

        type CookieRow = (String, String, Vec<u8>, i64);

        let rows: Vec<CookieRow> = if use_name_filter && use_domain_filter {
            let domain = query.domain_pattern.as_ref().unwrap();
            stmt.query_map([&query.name_pattern, domain], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
        } else if use_name_filter {
            stmt.query_map([&query.name_pattern], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
        } else if use_domain_filter {
            let domain = query.domain_pattern.as_ref().unwrap();
            stmt.query_map([domain], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
        } else {
            stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
        };

        let mut cookies = Vec::new();

        for (host_key, name, encrypted_value, expires_utc) in rows {
            // Decrypt value using pre-fetched key
            let value = crypto::decrypt_value_with_key(&encrypted_value, &chrome_key, meta_version)
                .unwrap_or_else(|_e| String::from_utf8_lossy(&encrypted_value).to_string());

            let expiry = Self::chrome_timestamp_to_utc(expires_utc);

            // Filter expired if needed
            if !query.include_expired {
                if let Some(expiry_time) = expiry {
                    if expiry_time < Utc::now() {
                        continue;
                    }
                }
            }

            cookies.push(Cookie {
                domain: host_key,
                name,
                value,
                expiry,
                meta: CookieMeta {
                    file: store_path.to_string(),
                    browser: self.browser.as_str().to_string(),
                    decrypted: true,
                },
            });
        }

        // Clean up temp file
        let _ = std::fs::remove_file(&temp_path);

        Ok(cookies)
    }
}
