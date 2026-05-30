use anyhow::Result;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "macos")]
pub use macos::{decrypt_chrome_cookie_with_key, get_chrome_key as get_chrome_key_impl};

// The key cache is only exercised on macOS, where the Keychain lookup happens.
#[cfg(target_os = "macos")]
use std::sync::Mutex;

#[cfg(target_os = "macos")]
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
#[cfg_attr(not(target_os = "macos"), allow(unused_variables))]
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

#[cfg(test)]
mod tests {
    use pbkdf2::pbkdf2_hmac;
    use sha1::Sha1;

    // Chrome's fixed key-derivation parameters (see macos.rs).
    const SALT: &[u8] = b"saltysalt";
    const ITERATIONS: u32 = 1003;
    const KEY_LEN: usize = 16;

    fn derive_key(password: &[u8]) -> Vec<u8> {
        let mut key = vec![0u8; KEY_LEN];
        pbkdf2_hmac::<Sha1>(password, SALT, ITERATIONS, &mut key);
        key
    }

    #[test]
    fn pbkdf2_key_is_deterministic_and_16_bytes() {
        let k1 = derive_key(b"peanuts");
        let k2 = derive_key(b"peanuts");
        assert_eq!(k1.len(), KEY_LEN);
        assert_eq!(k1, k2, "same password must derive the same key");
        assert_ne!(
            derive_key(b"peanuts"),
            derive_key(b"different"),
            "different passwords must derive different keys"
        );
    }

    // The decryption path is macOS-only (decrypt_value_with_key bails on other
    // platforms), so the round-trip vectors are gated to keep CI portable.
    #[cfg(target_os = "macos")]
    mod decrypt {
        use super::derive_key;
        use crate::crypto::decrypt_value_with_key;
        use aes::Aes128;
        use cbc::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};

        type Aes128CbcEnc = cbc::Encryptor<Aes128>;
        const IV: &[u8] = b"                "; // 16 spaces, matches the decryptor

        /// Encrypt `plaintext` the way Chrome does: AES-128-CBC with a 16-space
        /// IV and a "v10" version prefix.
        fn encrypt_v10(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
            let cipher = Aes128CbcEnc::new(key.into(), IV.into());
            // Pad the buffer up to the next 16-byte block boundary for PKCS7.
            let mut buf = vec![0u8; (plaintext.len() / 16 + 1) * 16];
            buf[..plaintext.len()].copy_from_slice(plaintext);
            let ciphertext = cipher
                .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
                .unwrap();
            let mut blob = b"v10".to_vec();
            blob.extend_from_slice(ciphertext);
            blob
        }

        #[test]
        fn round_trip_v10_decrypts_to_plaintext() {
            let key = derive_key(b"peanuts");
            let blob = encrypt_v10(b"secret-cookie-value", &key);
            let decrypted = decrypt_value_with_key(&blob, &key, 0).unwrap();
            assert_eq!(decrypted, "secret-cookie-value");
        }

        #[test]
        fn meta_v24_strips_32_byte_hash_prefix() {
            let key = derive_key(b"peanuts");
            let mut payload = vec![0u8; 32]; // 32-byte SHA-256 domain hash prefix
            payload.extend_from_slice(b"value-after-hash");
            let blob = encrypt_v10(&payload, &key);
            let decrypted = decrypt_value_with_key(&blob, &key, 24).unwrap();
            assert_eq!(decrypted, "value-after-hash");
        }

        #[test]
        fn pre_v24_keeps_full_payload() {
            let key = derive_key(b"peanuts");
            let blob = encrypt_v10(b"no-prefix-stripping", &key);
            let decrypted = decrypt_value_with_key(&blob, &key, 23).unwrap();
            assert_eq!(decrypted, "no-prefix-stripping");
        }

        #[test]
        fn unencrypted_value_without_prefix_passes_through() {
            let key = derive_key(b"peanuts");
            let decrypted = decrypt_value_with_key(b"plaintext-value", &key, 0).unwrap();
            assert_eq!(decrypted, "plaintext-value");
        }
    }
}
