//! C2: AEAD-конверт для приватного iroh-ключа. argon2id(пароль,salt)→ключ,
//! ChaCha20Poly1305 над каноническим плейнтекстом ключа. AAD = "v:kdf".

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};

const FORMAT_V: u8 = 1;
const KDF_ID: &str = "argon2id";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub(crate) struct EncryptedKey {
    pub v: u8,
    pub kdf: String,
    pub salt: String,
    pub nonce: String,
    pub ct: String,
}

/// argon2id(passphrase, salt) → 32-байтный ключ ChaCha. Параметры — дефолт крейта.
fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let argon = argon2::Argon2::default();
    let mut out = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| anyhow!("argon2: {e}"))?;
    Ok(out)
}

/// AAD аутентифицирует заголовок (версию+KDF), чтобы их подмена ловилась tag-ом.
fn aad() -> String {
    format!("{FORMAT_V}:{KDF_ID}")
}

pub(crate) fn encrypt(key_bytes: &[u8], passphrase: &str) -> Result<EncryptedKey> {
    let mut salt = [0u8; 16];
    use chacha20poly1305::aead::rand_core::RngCore;
    OsRng.fill_bytes(&mut salt);
    let dk = derive_key(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&dk));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let aad = aad();
    let ct = cipher
        .encrypt(&nonce, Payload { msg: key_bytes, aad: aad.as_bytes() })
        .map_err(|e| anyhow!("aead encrypt: {e}"))?;
    Ok(EncryptedKey {
        v: FORMAT_V,
        kdf: KDF_ID.to_string(),
        salt: STANDARD.encode(salt),
        nonce: STANDARD.encode(nonce),
        ct: STANDARD.encode(ct),
    })
}

pub(crate) fn decrypt(env: &EncryptedKey, passphrase: &str) -> Result<Vec<u8>> {
    let salt = STANDARD.decode(&env.salt).context("base64 salt")?;
    let nonce_bytes = STANDARD.decode(&env.nonce).context("base64 nonce")?;
    let ct = STANDARD.decode(&env.ct).context("base64 ct")?;
    // Длина nonce проверяется явно: Nonce::from_slice паникует на ≠12 байт.
    // Битый-но-валидный-JSON конверт должен давать Err, а не крах процесса.
    if nonce_bytes.len() != 12 {
        bail!("повреждён конверт: длина nonce {} (ожидалось 12)", nonce_bytes.len());
    }
    let dk = derive_key(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&dk));
    let nonce = Nonce::from_slice(&nonce_bytes);
    // AAD должен совпасть с заголовком ИМЕННО этого конверта (а не дефолтным),
    // чтобы подмена v/kdf ловилась как tag fail.
    let aad = format!("{}:{}", env.v, env.kdf);
    cipher
        .decrypt(nonce, Payload { msg: &ct, aad: aad.as_bytes() })
        .map_err(|e| anyhow!("aead decrypt (неверный пароль или подмена заголовка): {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt_roundtrips() {
        let secret = b"canonical-key-bytes-0123456789ab";
        let env = encrypt(secret, "correct horse").unwrap();
        let back = decrypt(&env, "correct horse").unwrap();
        assert_eq!(back, secret);
    }

    #[test]
    fn decrypt_wrong_passphrase_errors() {
        let env = encrypt(b"secret-bytes", "right").unwrap();
        assert!(decrypt(&env, "wrong").is_err(), "неверный пароль → Err");
    }

    #[test]
    fn two_encrypts_differ_in_salt_nonce_ct() {
        let a = encrypt(b"same-bytes", "pw").unwrap();
        let b = encrypt(b"same-bytes", "pw").unwrap();
        assert_ne!(a.salt, b.salt, "salt рандомизирован");
        assert_ne!(a.nonce, b.nonce, "nonce рандомизирован");
        assert_ne!(a.ct, b.ct, "ct отличается");
    }

    #[test]
    fn envelope_serde_roundtrips() {
        let env = encrypt(b"x", "pw").unwrap();
        let json = serde_json::to_string(&env).unwrap();
        let back: EncryptedKey = serde_json::from_str(&json).unwrap();
        assert_eq!(env, back);
    }

    #[test]
    fn tampered_kdf_header_fails_decrypt() {
        let mut env = encrypt(b"secret", "pw").unwrap();
        env.kdf = "scrypt".to_string(); // подмена заголовка, ct прежний
        assert!(decrypt(&env, "pw").is_err(), "AAD не сходится → Err");
    }

    #[test]
    fn malformed_nonce_errors_not_panics() {
        let mut env = encrypt(b"secret", "pw").unwrap();
        env.nonce = STANDARD.encode([0u8; 4]); // 4 байта вместо 12
        assert!(decrypt(&env, "pw").is_err(), "короткий nonce → Err, не паника");
    }
}
