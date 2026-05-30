use crate::browsers::BrowserCookieReader;
use crate::types::{Cookie, CookieMeta, CookieQuery};
use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};
use rusqlite::Connection;
use std::path::PathBuf;

pub struct SafariCookieReader;

impl SafariCookieReader {
    pub fn new() -> Self {
        Self
    }

    fn get_cookies_path() -> PathBuf {
        let home = dirs::home_dir().expect("Failed to get home directory");
        home.join("Library/Cookies/Cookies.binarycookies")
    }

    fn safari_timestamp_to_utc(timestamp: f64) -> Option<DateTime<Utc>> {
        // Safari uses seconds since 2001-01-01 (Cocoa/Core Foundation time)
        const COCOA_EPOCH_DELTA: i64 = 978307200; // Seconds between 1970 and 2001

        if timestamp == 0.0 {
            return None;
        }

        let unix_timestamp = timestamp as i64 + COCOA_EPOCH_DELTA;
        Utc.timestamp_opt(unix_timestamp, 0).single()
    }
}

impl BrowserCookieReader for SafariCookieReader {
    fn find_cookie_stores(&self) -> Result<Vec<String>> {
        let cookies_path = Self::get_cookies_path();

        if cookies_path.exists() {
            Ok(vec![cookies_path.to_string_lossy().to_string()])
        } else {
            Ok(vec![])
        }
    }

    fn read_cookies(&self, store_path: &str, query: &CookieQuery) -> Result<Vec<Cookie>> {
        // Safari uses a binary format (.binarycookies), but newer versions also use SQLite
        // Check if it's the SQLite database
        if store_path.contains(".binarycookies") {
            // For now, return empty - binary cookie parsing is complex
            // Would need to implement binary cookie file format parser
            return Ok(vec![]);
        }

        // Try reading as SQLite (Safari 14+)
        let conn = Connection::open(store_path).context("Failed to open Safari cookie database")?;

        let mut sql = String::from("SELECT domain, name, value, expires FROM cookies WHERE 1=1");

        if query.name_pattern != "%" {
            sql.push_str(" AND name LIKE ?1");
        }

        if let Some(ref domain) = query.domain_pattern {
            if domain != "%" {
                sql.push_str(" AND domain LIKE ?2");
            }
        }

        let mut stmt = conn.prepare(&sql)?;

        type CookieRow = (String, String, String, f64);

        let rows: Vec<CookieRow> = if query.name_pattern != "%" && query.domain_pattern.is_some() {
            let domain = query.domain_pattern.as_ref().unwrap();
            stmt.query_map([&query.name_pattern, domain], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, f64>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
        } else if query.name_pattern != "%" {
            stmt.query_map([&query.name_pattern], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, f64>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
        } else {
            stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, f64>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
        };

        let mut cookies = Vec::new();

        for (domain, name, value, expires) in rows {
            let expiry = Self::safari_timestamp_to_utc(expires);

            // Filter expired if needed
            if !query.include_expired {
                if let Some(expiry_time) = expiry {
                    if expiry_time < Utc::now() {
                        continue;
                    }
                }
            }

            cookies.push(Cookie {
                domain,
                name,
                value,
                expiry,
                meta: CookieMeta {
                    file: store_path.to_string(),
                    browser: "Safari".to_string(),
                    decrypted: false,
                },
            });
        }

        Ok(cookies)
    }
}
