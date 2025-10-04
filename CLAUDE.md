# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Rust rewrite of the `get-cookie` Node.js tool for extracting and decrypting browser cookies from SQLite databases. Currently focused on macOS support.

## Build & Run Commands

```bash
# Build release binary
cargo build --release

# Run the tool
./target/release/get-cookie2 [OPTIONS]

# Build and test quickly
cargo build

# Common usage examples
./target/release/get-cookie2 auth example.com              # Get specific cookie
./target/release/get-cookie2 --url https://example.com -r  # Render as HTTP header
./target/release/get-cookie2 % github.com --output json    # All cookies as JSON
./target/release/get-cookie2 --list-profiles --browser chrome
```

## Architecture

### Module Structure

- **`src/main.rs`**: CLI entry point, argument parsing, cookie collection orchestration, deduplication
- **`src/types/`**: Core data structures (`Cookie`, `Browser`, `CookieQuery`, `CookieMeta`)
- **`src/browsers/`**: Browser-specific cookie readers implementing `BrowserCookieReader` trait
  - `chrome/`: Handles Chrome, Arc, Edge (Chromium-based browsers)
  - `firefox/`: Firefox-specific cookie extraction
  - `safari/`: Safari cookie support (partial implementation)
- **`src/crypto/`**: Encryption/decryption with macOS Keychain integration
- **`src/jwt/`**: JWT detection, decoding, and validation
- **`src/output/`**: Output formatting (Plain, JSON, Render)

### Key Design Patterns

**BrowserCookieReader Trait**: All browser implementations must implement:
```rust
trait BrowserCookieReader {
    fn find_cookie_stores(&self) -> Result<Vec<String>>;
    fn read_cookies(&self, store_path: &str, query: &CookieQuery) -> Result<Vec<Cookie>>;
}
```

**Global Keychain Caching**: The Chrome decryption key is fetched once and cached globally using `Mutex<Option<Vec<u8>>>` in `src/crypto/mod.rs`. This prevents multiple macOS Keychain permission dialogs. The key is pre-fetched before processing any cookies in a store.

**Two-Level Deduplication**:
1. Main deduplication in `main.rs` by `(name, domain, value)` tuple to avoid showing identical cookies from multiple profiles
2. Render format deduplication by `name` only to show single value per cookie name in HTTP headers

### Chrome Cookie Decryption Flow

1. **Copy database**: SQLite database copied to `/tmp/cookies_{pid}.db` to avoid locks
2. **Get meta version**: Query `meta` table for schema version (stored as TEXT, not INTEGER)
3. **Fetch key once**: Call `crypto::get_chrome_key_cached()` before processing cookies
4. **Decrypt cookies**: Use `decrypt_value_with_key()` with pre-fetched key
5. **Handle v24+ schema**: If `meta_version >= 24`, skip first 32 bytes (hash prefix) after AES-128-CBC decryption
6. **Cleanup**: Remove temp database file

### Chrome Encryption Details

- **Key derivation**: PBKDF2-HMAC-SHA1 with salt "saltysalt", 1003 iterations, 16-byte key
- **Encryption**: AES-128-CBC with IV of 16 spaces
- **Value prefix**: Encrypted values start with "v10" or "v11" marker
- **Schema v24+**: Prepends 32-byte hash to decrypted data that must be stripped

Reference: [Chromium source](https://chromium.googlesource.com/chromium/src/+/b02dcebd7cafab92770734dc2bc317bd07f1d891/net/extras/sqlite/sqlite_persistent_cookie_store.cc#223)

### SQL Query Building

The Chrome reader builds dynamic SQL queries with conditional parameter binding based on query filters. Use boolean flags (`use_name_filter`, `use_domain_filter`) to match parameter counts to query placeholders, avoiding "wrong number of parameters" errors.

## Platform-Specific Code

macOS-only modules are conditionally compiled:
```rust
#[cfg(target_os = "macos")]
pub mod macos;
```

Keychain access uses `security-framework` crate (macOS only dependency in Cargo.toml).

## Output Formats

- **Plain**: Cookie values only, one per line
- **JSON**: Full cookie objects with metadata
- **Render**: HTTP Cookie header format (`name=value; name=value`) with automatic deduplication by name
