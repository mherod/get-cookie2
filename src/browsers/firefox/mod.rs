use crate::browsers::BrowserCookieReader;
use crate::types::{Cookie, CookieMeta, CookieQuery};
use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};
use rusqlite::Connection;
use std::path::PathBuf;

pub struct FirefoxCookieReader;

impl FirefoxCookieReader {
    pub fn new() -> Self {
        Self
    }

    fn get_firefox_profiles_path() -> PathBuf {
        let home = dirs::home_dir().expect("Failed to get home directory");
        home.join("Library/Application Support/Firefox/Profiles")
    }

    fn unix_timestamp_to_utc(timestamp: i64) -> Option<DateTime<Utc>> {
        if timestamp == 0 {
            return None;
        }

        Utc.timestamp_opt(timestamp, 0).single()
    }
}

impl BrowserCookieReader for FirefoxCookieReader {
    fn find_cookie_stores(&self) -> Result<Vec<String>> {
        let profiles_path = Self::get_firefox_profiles_path();

        if !profiles_path.exists() {
            return Ok(vec![]);
        }

        let mut stores = Vec::new();

        for entry in std::fs::read_dir(&profiles_path)
            .context("Failed to read Firefox profiles directory")?
        {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                let cookies_path = path.join("cookies.sqlite");
                if cookies_path.exists() {
                    stores.push(cookies_path.to_string_lossy().to_string());
                }
            }
        }

        Ok(stores)
    }

    fn read_cookies(&self, store_path: &str, query: &CookieQuery) -> Result<Vec<Cookie>> {
        // Copy database to temp location to avoid locks
        let temp_path = format!("/tmp/firefox_cookies_{}.db", std::process::id());
        std::fs::copy(store_path, &temp_path).context("Failed to copy Firefox cookie database")?;

        let conn =
            Connection::open(&temp_path).context("Failed to open Firefox cookie database")?;

        let mut sql = String::from("SELECT host, name, value, expiry FROM moz_cookies WHERE 1=1");

        let use_name_filter = query.name_pattern != "%";
        let use_domain_filter = query
            .domain_pattern
            .as_ref()
            .map(|d| d != "%")
            .unwrap_or(false);

        if use_name_filter {
            sql.push_str(" AND name LIKE ?1");
        }

        if use_domain_filter {
            if use_name_filter {
                sql.push_str(" AND host LIKE ?2");
            } else {
                sql.push_str(" AND host LIKE ?1");
            }
        }

        let mut stmt = conn.prepare(&sql)?;

        type CookieRow = (String, String, String, i64);

        let rows: Vec<CookieRow> = if use_name_filter && use_domain_filter {
            let domain = query.domain_pattern.as_ref().unwrap();
            stmt.query_map([&query.name_pattern, domain], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
        } else if use_name_filter {
            stmt.query_map([&query.name_pattern], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
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
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
        } else {
            stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
        };

        let mut cookies = Vec::new();

        for (host, name, value, expiry) in rows {
            let expiry_time = Self::unix_timestamp_to_utc(expiry);

            // Filter expired if needed
            if !query.include_expired {
                if let Some(exp) = expiry_time {
                    if exp < Utc::now() {
                        continue;
                    }
                }
            }

            cookies.push(Cookie {
                domain: host,
                name,
                value,
                expiry: expiry_time,
                meta: CookieMeta {
                    file: store_path.to_string(),
                    browser: "Firefox".to_string(),
                    decrypted: false,
                },
            });
        }

        // Clean up temp file
        let _ = std::fs::remove_file(&temp_path);

        Ok(cookies)
    }
}
