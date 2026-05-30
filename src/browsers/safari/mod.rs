use crate::browsers::BrowserCookieReader;
use crate::types::{Cookie, CookieMeta, CookieQuery};
use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};
use std::path::PathBuf;

#[derive(Default)]
pub struct SafariCookieReader;

impl SafariCookieReader {
    pub fn new() -> Self {
        Self
    }

    /// Locations Safari may store its binary cookie file, newest first.
    fn candidate_paths() -> Vec<PathBuf> {
        let home = match dirs::home_dir() {
            Some(h) => h,
            None => return vec![],
        };
        vec![
            // Sandboxed Safari (modern macOS).
            home.join(
                "Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies",
            ),
            // Legacy, pre-sandbox location.
            home.join("Library/Cookies/Cookies.binarycookies"),
        ]
    }

    /// Convert a Safari (Cocoa/Core Foundation) timestamp to UTC.
    /// Cocoa time is seconds since 2001-01-01.
    fn safari_timestamp_to_utc(timestamp: f64) -> Option<DateTime<Utc>> {
        const COCOA_EPOCH_DELTA: i64 = 978_307_200; // seconds between 1970 and 2001
        if timestamp == 0.0 {
            return None;
        }
        Utc.timestamp_opt(timestamp as i64 + COCOA_EPOCH_DELTA, 0)
            .single()
    }
}

/// A cookie record decoded straight from the binary file, before pattern
/// filtering and timestamp conversion.
struct RawCookie {
    domain: String,
    name: String,
    value: String,
    /// Expiry as a raw Cocoa timestamp (seconds since 2001-01-01).
    expiry: f64,
}

fn read_u32_be(data: &[u8], offset: usize) -> Result<u32> {
    data.get(offset..offset + 4)
        .map(|b| u32::from_be_bytes(b.try_into().unwrap()))
        .context("unexpected end of data reading big-endian u32")
}

fn read_u32_le(data: &[u8], offset: usize) -> Result<u32> {
    data.get(offset..offset + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .context("unexpected end of data reading little-endian u32")
}

fn read_f64_le(data: &[u8], offset: usize) -> Result<f64> {
    data.get(offset..offset + 8)
        .map(|b| f64::from_le_bytes(b.try_into().unwrap()))
        .context("unexpected end of data reading little-endian f64")
}

/// Read a NUL-terminated string starting at `start`. Returns an empty string if
/// the offset is out of bounds.
fn read_cstr(data: &[u8], start: usize) -> String {
    if start >= data.len() {
        return String::new();
    }
    let bytes = &data[start..];
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// SQL `LIKE`-style matching using only `%` as a wildcard, case-insensitive.
/// `%` alone matches everything; a pattern with no `%` matches exactly.
fn like_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.to_lowercase();
    let value = value.to_lowercase();

    if pattern == "%" {
        return true;
    }
    if !pattern.contains('%') {
        return value == pattern;
    }

    let segments: Vec<&str> = pattern.split('%').collect();
    let last = segments.len() - 1;
    let mut idx = 0usize;
    for (i, seg) in segments.iter().enumerate() {
        if seg.is_empty() {
            continue;
        }
        if i == 0 {
            // Anchored at the start.
            if !value[idx..].starts_with(seg) {
                return false;
            }
            idx += seg.len();
        } else if i == last {
            // Anchored at the end.
            if !value[idx..].ends_with(seg) {
                return false;
            }
        } else {
            // Free-floating: must appear somewhere after the current position.
            match value[idx..].find(seg) {
                Some(p) => idx += p + seg.len(),
                None => return false,
            }
        }
    }
    true
}

/// Parse a `Cookies.binarycookies` file into raw cookie records.
///
/// File layout: magic `cook`, big-endian page count, big-endian page-size
/// table, then the pages. Page and cookie internals are little-endian.
/// Reference: the well-documented Safari binary cookie format.
fn parse_binarycookies(data: &[u8]) -> Result<Vec<RawCookie>> {
    if data.len() < 8 || &data[0..4] != b"cook" {
        anyhow::bail!("not a valid Cookies.binarycookies file (bad magic)");
    }

    let num_pages = read_u32_be(data, 4)? as usize;
    let mut page_sizes = Vec::with_capacity(num_pages);
    let mut offset = 8;
    for _ in 0..num_pages {
        page_sizes.push(read_u32_be(data, offset)? as usize);
        offset += 4;
    }

    let mut cookies = Vec::new();
    let mut page_start = offset;
    for size in page_sizes {
        let page_end = page_start
            .checked_add(size)
            .filter(|&e| e <= data.len())
            .context("truncated page in Safari cookie file")?;
        parse_page(&data[page_start..page_end], &mut cookies)?;
        page_start = page_end;
    }

    Ok(cookies)
}

/// Parse a single page: a 4-byte header, a little-endian cookie count, a table
/// of per-cookie offsets, then the cookie records.
fn parse_page(page: &[u8], out: &mut Vec<RawCookie>) -> Result<()> {
    if page.len() < 8 {
        anyhow::bail!("Safari cookie page too small");
    }
    let num_cookies = read_u32_le(page, 4)? as usize;

    let mut p = 8;
    let mut offsets = Vec::with_capacity(num_cookies);
    for _ in 0..num_cookies {
        offsets.push(read_u32_le(page, p)? as usize);
        p += 4;
    }

    for base in offsets {
        if let Some(cookie) = parse_cookie(page, base)? {
            out.push(cookie);
        }
    }
    Ok(())
}

/// Parse a single cookie record located at `base` within the page. String
/// offsets are relative to `base`.
fn parse_cookie(page: &[u8], base: usize) -> Result<Option<RawCookie>> {
    // The fixed cookie header is 56 bytes; skip records that don't fit.
    if base + 56 > page.len() {
        return Ok(None);
    }

    let domain_off = read_u32_le(page, base + 16)? as usize;
    let name_off = read_u32_le(page, base + 20)? as usize;
    let value_off = read_u32_le(page, base + 28)? as usize;
    let expiry = read_f64_le(page, base + 40)?;

    let domain = read_cstr(page, base + domain_off);
    let name = read_cstr(page, base + name_off);
    let value = read_cstr(page, base + value_off);

    Ok(Some(RawCookie {
        domain,
        name,
        value,
        expiry,
    }))
}

impl BrowserCookieReader for SafariCookieReader {
    fn find_cookie_stores(&self) -> Result<Vec<String>> {
        Ok(Self::candidate_paths()
            .into_iter()
            .filter(|p| p.exists())
            .map(|p| p.to_string_lossy().into_owned())
            .collect())
    }

    fn read_cookies(&self, store_path: &str, query: &CookieQuery) -> Result<Vec<Cookie>> {
        let data = std::fs::read(store_path)
            .with_context(|| format!("Failed to read Safari cookie file: {store_path}"))?;
        let raw = parse_binarycookies(&data)?;

        let mut cookies = Vec::new();
        for rc in raw {
            if !like_match(&query.name_pattern, &rc.name) {
                continue;
            }
            if let Some(ref domain_pattern) = query.domain_pattern {
                if !like_match(domain_pattern, &rc.domain) {
                    continue;
                }
            }

            let expiry = Self::safari_timestamp_to_utc(rc.expiry);
            if !query.include_expired {
                if let Some(expiry_time) = expiry {
                    if expiry_time < Utc::now() {
                        continue;
                    }
                }
            }

            cookies.push(Cookie {
                domain: rc.domain,
                name: rc.name,
                value: rc.value,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid `Cookies.binarycookies` blob: one page, one cookie
    /// (`session=abc123` for `example.com`).
    fn build_fixture() -> Vec<u8> {
        let domain = b"example.com\0";
        let name = b"session\0";
        let path = b"/\0";
        let value = b"abc123\0";

        // String offsets are relative to the start of the cookie record, after
        // the 56-byte fixed header.
        let domain_off = 56u32;
        let name_off = domain_off + domain.len() as u32;
        let path_off = name_off + name.len() as u32;
        let value_off = path_off + path.len() as u32;
        let total = value_off + value.len() as u32;

        let mut rec = Vec::new();
        rec.extend_from_slice(&total.to_le_bytes()); // 0: cookie size
        rec.extend_from_slice(&0u32.to_le_bytes()); // 4: version
        rec.extend_from_slice(&0u32.to_le_bytes()); // 8: flags
        rec.extend_from_slice(&0u32.to_le_bytes()); // 12: unknown
        rec.extend_from_slice(&domain_off.to_le_bytes()); // 16
        rec.extend_from_slice(&name_off.to_le_bytes()); // 20
        rec.extend_from_slice(&path_off.to_le_bytes()); // 24
        rec.extend_from_slice(&value_off.to_le_bytes()); // 28
        rec.extend_from_slice(&[0u8; 8]); // 32: end-of-header marker
        rec.extend_from_slice(&2_000_000_000f64.to_le_bytes()); // 40: expiry (Cocoa)
        rec.extend_from_slice(&1_000_000_000f64.to_le_bytes()); // 48: creation
        rec.extend_from_slice(domain); // 56: strings
        rec.extend_from_slice(name);
        rec.extend_from_slice(path);
        rec.extend_from_slice(value);

        // Page: header, cookie count, offset table, footer, then the record.
        let cookie_offset = 16u32; // 4 header + 4 count + 4 offset + 4 footer
        let mut page = Vec::new();
        page.extend_from_slice(&[0x00, 0x00, 0x01, 0x00]); // page header
        page.extend_from_slice(&1u32.to_le_bytes()); // cookie count
        page.extend_from_slice(&cookie_offset.to_le_bytes()); // offset of cookie 0
        page.extend_from_slice(&[0, 0, 0, 0]); // footer
        page.extend_from_slice(&rec);

        let mut file = Vec::new();
        file.extend_from_slice(b"cook");
        file.extend_from_slice(&1u32.to_be_bytes()); // page count (big-endian)
        file.extend_from_slice(&(page.len() as u32).to_be_bytes()); // page size (big-endian)
        file.extend_from_slice(&page);
        file
    }

    #[test]
    fn parses_single_cookie() {
        let cookies = parse_binarycookies(&build_fixture()).unwrap();
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].domain, "example.com");
        assert_eq!(cookies[0].name, "session");
        assert_eq!(cookies[0].value, "abc123");
        assert_eq!(cookies[0].expiry, 2_000_000_000f64);
    }

    #[test]
    fn rejects_bad_magic() {
        assert!(parse_binarycookies(b"nope1234").is_err());
        assert!(parse_binarycookies(b"too").is_err());
    }

    #[test]
    fn empty_page_table_yields_no_cookies() {
        // Valid magic, zero pages.
        let mut data = Vec::new();
        data.extend_from_slice(b"cook");
        data.extend_from_slice(&0u32.to_be_bytes());
        assert!(parse_binarycookies(&data).unwrap().is_empty());
    }

    #[test]
    fn truncated_page_is_an_error() {
        let mut data = Vec::new();
        data.extend_from_slice(b"cook");
        data.extend_from_slice(&1u32.to_be_bytes()); // 1 page
        data.extend_from_slice(&999u32.to_be_bytes()); // claims 999 bytes
        data.extend_from_slice(&[0u8; 4]); // but only 4 follow
        assert!(parse_binarycookies(&data).is_err());
    }

    #[test]
    fn like_match_semantics() {
        assert!(like_match("%", "anything"));
        assert!(like_match("%github.com%", "www.github.com"));
        assert!(like_match("%example%", "sub.example.com"));
        assert!(like_match("session", "session"));
        assert!(like_match("SESSION", "session")); // case-insensitive
        assert!(!like_match("session", "other"));
        assert!(like_match("auth%", "auth_token"));
        assert!(like_match("%token", "auth_token"));
        assert!(!like_match("%token", "token_auth"));
    }

    #[test]
    fn timestamp_conversion_handles_zero_and_values() {
        assert!(SafariCookieReader::safari_timestamp_to_utc(0.0).is_none());
        assert!(SafariCookieReader::safari_timestamp_to_utc(2_000_000_000.0).is_some());
    }
}
