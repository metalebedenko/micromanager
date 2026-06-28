//! Постоянная iroh-личность (опт-ин персист pairing): стабильный `EndpointId`
//! между рестартами. Файл `identity.json` (приватный ключ, права 0600).
//! C2: при заданном `MM_KEY_PASSPHRASE` ключ хранится зашифрованным (см. keyfile).

use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use iroh::SecretKey;

use serde::Deserialize;

use super::keyfile::{self, EncryptedKey};
use super::store::{ensure_0600, write_private};

/// Лёгкий зонд: JSON-объект-конверт несёт поле `v`. Плейнтекст-ключ — JSON-строка,
/// сюда не парсится. Позволяет version-gate ДО требования полной схемы EncryptedKey.
#[derive(Deserialize)]
struct VersionProbe {
    v: u8,
}

/// `MM_KEY_PASSPHRASE` из окружения; пустая строка → None (как `MM_STATE_DIR`).
fn key_passphrase() -> Option<String> {
    std::env::var("MM_KEY_PASSPHRASE").ok().filter(|s| !s.is_empty())
}

/// Записать ключ в плейнтексте (текущий дефолт): serde-строка SecretKey, 0600, атомарно.
fn save_plain(path: &Path, key: &SecretKey) -> std::io::Result<()> {
    let json = serde_json::to_string(key)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    write_private(path, json.as_bytes())
}

/// Зашифровать ключ паролем и записать конверт: 0600, атомарно.
fn save_encrypted(path: &Path, key: &SecretKey, passphrase: &str) -> Result<()> {
    let key_bytes = serde_json::to_vec(key).context("сериализация ключа")?; // канон. плейнтекст
    let env = keyfile::encrypt(&key_bytes, passphrase)?;
    let json = serde_json::to_string(&env).context("сериализация конверта")?;
    write_private(path, json.as_bytes()).context("запись конверта")?;
    Ok(())
}

/// Загрузить постоянный ключ или создать новый. Публичный вход: читает env и делегирует.
pub fn load_or_create(path: &Path) -> Result<SecretKey> {
    let pass = key_passphrase();
    load_or_create_with(path, pass.as_deref())
}

/// Ядро с явным паролем (тест-шов: тесты не трогают глобальный env).
/// Safety: «зашифровано, но не открыть» → Err, НИКОГДА не регенерим (иначе ротация EndpointId).
fn load_or_create_with(path: &Path, passphrase: Option<&str>) -> Result<SecretKey> {
    if path.exists() {
        ensure_0600(path);
        let raw = std::fs::read_to_string(path).context("чтение файла идентичности")?;

        // 1. зашифрованный конверт? Сначала пробуем только поле `v` — так JSON-объект-конверт
        // опознаётся ДО требования полной схемы. Иначе будущий формат (v=2 с другими полями)
        // не распарсился бы как EncryptedKey, провалился в «мусор» и СГЕНЕРИЛ бы новый ключ —
        // ровно та тихая ротация EndpointId, которую инвариант запрещает.
        if let Ok(probe) = serde_json::from_str::<VersionProbe>(&raw) {
            if probe.v != 1 {
                bail!("неподдерживаемая версия формата ключа (v={}) — обнови micromanager", probe.v);
            }
            // v==1 → требуем полную схему; нехватка полей = повреждён конверт, НЕ регенерим
            let env: EncryptedKey = serde_json::from_str(&raw)
                .context("конверт v=1 повреждён (не хватает полей)")?;
            if env.kdf != "argon2id" {
                bail!("неподдерживаемый KDF '{}' — обнови micromanager", env.kdf);
            }
            let pass = passphrase
                .ok_or_else(|| anyhow!("ключ зашифрован, задайте MM_KEY_PASSPHRASE"))?;
            let bytes = keyfile::decrypt(&env, pass)
                .context("неверный MM_KEY_PASSPHRASE или повреждён конверт")?;
            let key: SecretKey = serde_json::from_slice(&bytes).context("разбор расшифрованного ключа")?;
            return Ok(key);
        }

        // 2. плейнтекст SecretKey?
        if let Ok(key) = serde_json::from_str::<SecretKey>(&raw) {
            if let Some(pass) = passphrase {
                // миграция плейнтекст → шифр тем же ключом (EndpointId не меняется); best-effort
                if let Err(e) = save_encrypted(path, &key, pass) {
                    eprintln!("[micromanager] миграция ключа в шифр не удалась: {e}");
                }
            }
            return Ok(key);
        }

        // 3. ни то, ни другое → битый файл: WARN + новый (как C1)
        eprintln!(
            "[micromanager] {path:?}: файл идентичности повреждён — создаю новый ключ; \
             ПРЕЖНИЕ ДОВЕРИЯ АННУЛИРОВАНЫ (EndpointId сменился)"
        );
    }

    // нет файла или битый → генерируем и сохраняем в нужном формате
    let key = SecretKey::generate();
    let saved = match passphrase {
        Some(pass) => save_encrypted(path, &key, pass),
        None => save_plain(path, &key).map_err(Into::into),
    };
    if let Err(e) = saved {
        eprintln!("[micromanager] не удалось сохранить идентичность {path:?}: {e}");
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_then_load_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id.json");
        let a = load_or_create_with(&path, None).unwrap();
        let b = load_or_create_with(&path, None).unwrap();
        assert_eq!(a.public(), b.public(), "повторный load — тот же EndpointId");
    }

    #[cfg(unix)]
    #[test]
    fn created_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id.json");
        let _ = load_or_create_with(&path, None).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn wide_perms_forced_to_0600_on_load() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id.json");
        let _ = load_or_create_with(&path, None).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let _ = load_or_create_with(&path, None).unwrap(); // должен ужесточить
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "широкие права ужесточены до 0600");
    }

    #[test]
    fn corrupt_file_recreates_without_panic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id.json");
        std::fs::write(&path, "не json мусор").unwrap();
        let key = load_or_create_with(&path, None).unwrap(); // не паника
        // после пересоздания файл валиден → следующий load стабилен
        let key2 = load_or_create_with(&path, None).unwrap();
        assert_eq!(key.public(), key2.public());
    }

    #[test]
    fn write_leaves_no_tmp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id.json");
        let _ = load_or_create_with(&path, None).unwrap();
        assert!(!path.with_extension("tmp").exists(), "temp-файл не остаётся");
    }

    #[test]
    fn default_no_pass_file_is_plaintext_secretkey() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id.json");
        let _ = load_or_create_with(&path, None).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        // без пароля файл — JSON-строка SecretKey, НЕ объект-конверт
        assert!(serde_json::from_str::<SecretKey>(&raw).is_ok());
        assert!(serde_json::from_str::<EncryptedKey>(&raw).is_err());
    }

    #[test]
    fn with_pass_file_is_encrypted_envelope_and_stable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id.json");
        let a = load_or_create_with(&path, Some("pw")).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        // файл — конверт, НЕ парсится как SecretKey
        assert!(serde_json::from_str::<EncryptedKey>(&raw).is_ok());
        assert!(serde_json::from_str::<SecretKey>(&raw).is_err());
        // повторный load тем же паролем — тот же ключ
        let b = load_or_create_with(&path, Some("pw")).unwrap();
        assert_eq!(a.public(), b.public());
    }

    #[test]
    fn migration_plaintext_to_encrypted_keeps_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id.json");
        // создаём плейнтекст-файл
        let plain = load_or_create_with(&path, None).unwrap();
        // теперь с паролем → миграция в конверт, тот же EndpointId
        let migrated = load_or_create_with(&path, Some("pw")).unwrap();
        assert_eq!(plain.public(), migrated.public(), "ключ не сменился при миграции");
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(serde_json::from_str::<EncryptedKey>(&raw).is_ok(), "файл стал конвертом");
    }

    #[test]
    fn encrypted_without_pass_errors_no_regen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id.json");
        let _ = load_or_create_with(&path, Some("pw")).unwrap(); // создаём конверт
        let before = std::fs::read_to_string(&path).unwrap();
        let res = load_or_create_with(&path, None); // нет пароля
        assert!(res.is_err(), "конверт без пароля → Err");
        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(before, after, "файл НЕ перезаписан (нет регенерации)");
    }

    #[test]
    fn encrypted_wrong_pass_errors_no_regen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id.json");
        let _ = load_or_create_with(&path, Some("right")).unwrap();
        let before = std::fs::read_to_string(&path).unwrap();
        let res = load_or_create_with(&path, Some("wrong"));
        assert!(res.is_err(), "неверный пароль → Err");
        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(before, after, "файл НЕ перезаписан");
    }

    #[test]
    fn unknown_version_envelope_errors_no_regen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id.json");
        // валидный конверт из будущего: v=99
        let env = EncryptedKey { v: 99, kdf: "argon2id".into(), salt: "AAAA".into(), nonce: "AAAA".into(), ct: "AAAA".into() };
        std::fs::write(&path, serde_json::to_string(&env).unwrap()).unwrap();
        let before = std::fs::read_to_string(&path).unwrap();
        let res = load_or_create_with(&path, Some("pw"));
        assert!(res.is_err(), "неизвестная версия → Err");
        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(before, after, "файл НЕ перезаписан");
    }

    #[test]
    fn envelope_v1_missing_fields_errors_no_regen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id.json");
        // JSON-объект с v=1, но без salt/nonce/ct (будущий/битый формат под текущей версией)
        std::fs::write(&path, r#"{"v":1,"kdf":"argon2id"}"#).unwrap();
        let before = std::fs::read_to_string(&path).unwrap();
        let res = load_or_create_with(&path, Some("pw"));
        assert!(res.is_err(), "конверт v=1 без полей → Err, не мусор-регенерация");
        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(before, after, "файл НЕ перезаписан");
    }

    #[cfg(unix)]
    #[test]
    fn encrypted_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id.json");
        let _ = load_or_create_with(&path, Some("pw")).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
