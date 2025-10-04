use anyhow::{Context, Result};
use security_framework::passwords::get_generic_password;
use aes::Aes128;
use cbc::{Decryptor, cipher::{BlockDecryptMut, KeyIvInit}};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;

type Aes128CbcDec = Decryptor<Aes128>;

const CHROME_SALT: &[u8] = b"saltysalt";
const CHROME_IV: &[u8] = b"                "; // 16 spaces
const CHROME_ITERATIONS: u32 = 1003;
const CHROME_KEY_LENGTH: usize = 16;

/// Get Chrome's encryption key from macOS Keychain
pub fn get_chrome_key() -> Result<Vec<u8>> {
    let password_bytes = get_generic_password("Chrome Safe Storage", "Chrome")
        .context("Failed to get Chrome Safe Storage password from Keychain")?;

    let mut key = vec![0u8; CHROME_KEY_LENGTH];
    pbkdf2_hmac::<Sha1>(
        &password_bytes,
        CHROME_SALT,
        CHROME_ITERATIONS,
        &mut key,
    );

    Ok(key)
}

/// Decrypt Chrome cookie value on macOS with a provided key
pub fn decrypt_chrome_cookie_with_key(encrypted_value: &[u8], key: &[u8], meta_version: i64) -> Result<String> {
    // Chrome on macOS prepends "v10" or "v11" to encrypted values
    if encrypted_value.len() < 3 {
        // Not encrypted, return as-is
        return String::from_utf8(encrypted_value.to_vec())
            .context("Failed to decode unencrypted value");
    }

    // Check for v10/v11 prefix
    if &encrypted_value[0..3] == b"v10" || &encrypted_value[0..3] == b"v11" {
        let encrypted_data = &encrypted_value[3..];

        // Decrypt using AES-128-CBC
        let cipher = Aes128CbcDec::new(key.into(), CHROME_IV.into());

        let mut buffer = encrypted_data.to_vec();
        let decrypted_bytes = cipher
            .decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buffer)
            .map_err(|e| anyhow::anyhow!("Failed to decrypt cookie value: {:?}", e))?;

        // Skip the first 32 bytes (hash prefix) if meta version >= 24
        // Ref: https://chromium.googlesource.com/chromium/src/+/b02dcebd7cafab92770734dc2bc317bd07f1d891/net/extras/sqlite/sqlite_persistent_cookie_store.cc#223
        let final_decrypted = if meta_version >= 24 && decrypted_bytes.len() > 32 {
            &decrypted_bytes[32..]
        } else {
            decrypted_bytes
        };

        String::from_utf8(final_decrypted.to_vec())
            .context("Failed to decode decrypted value")
    } else {
        // Not encrypted with v10/v11, return as-is
        String::from_utf8(encrypted_value.to_vec())
            .context("Failed to decode unencrypted value")
    }
}
