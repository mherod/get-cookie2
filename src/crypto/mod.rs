use anyhow::Result;
use std::sync::Mutex;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "macos")]
pub use macos::{decrypt_chrome_cookie_with_key, get_chrome_key as get_chrome_key_impl};

static CHROME_KEY_CACHE: Mutex<Option<Vec<u8>>> = Mutex::new(None);

/// Get Chrome decryption key from Keychain (cached)
///
/// This prevents multiple Keychain access prompts when decrypting many cookies.
/// The key is fetched once from the macOS Keychain and cached for the lifetime
/// of the process. This is important because each Keychain access triggers a
/// permission dialog that the user must approve.
#[cfg(target_os = "macos")]
pub fn get_chrome_key_cached() -> Result<Vec<u8>> {
    let mut cache = CHROME_KEY_CACHE.lock().unwrap();

    if let Some(ref key) = *cache {
        return Ok(key.clone());
    }

    let key = get_chrome_key_impl()?;
    *cache = Some(key.clone());
    Ok(key)
}

#[cfg(not(target_os = "macos"))]
pub fn get_chrome_key_cached() -> Result<Vec<u8>> {
    anyhow::bail!("Keychain access not supported on this platform")
}

/// Decrypt cookie value with a pre-fetched key
pub fn decrypt_value_with_key(
    encrypted_value: &[u8],
    key: &[u8],
    meta_version: i64,
) -> Result<String> {
    #[cfg(target_os = "macos")]
    {
        decrypt_chrome_cookie_with_key(encrypted_value, key, meta_version)
    }

    #[cfg(not(target_os = "macos"))]
    {
        anyhow::bail!("Decryption not supported on this platform")
    }
}

/// Legacy function - prefer get_chrome_key_cached + decrypt_value_with_key
pub fn decrypt_value(encrypted_value: &[u8], _browser: &str, meta_version: i64) -> Result<String> {
    let key = get_chrome_key_cached()?;
    decrypt_value_with_key(encrypted_value, &key, meta_version)
}
