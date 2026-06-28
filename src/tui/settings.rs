//! Модель настроек TUI (минимальный экран взаимодействия): мозг + политика безопасности.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::safety::Policy;

/// Настройки сессии TUI. `#[serde(default)]` на контейнере: отсутствующие поля
/// в конфиге берутся из `Default` (совместимость со старым/частичным конфигом).
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub model: String,
    pub host: String,
    pub api_key: Option<String>,
    pub provider: crate::brain::Provider,
    pub allowed_path: Option<PathBuf>,
    pub allow_shell: bool,
    pub allow_dangerous: bool,
    /// Роутер мозга: primary (плоские поля выше) → fallback при неудаче.
    /// Тумблер; по умолчанию выкл (поведение с одним мозгом не меняется).
    pub routing: bool,
    /// Резервный профиль для роутера (cloud). Пустой → роутер не активируется.
    pub fallback: crate::brain::BrainProfile,
    /// Таймаут запроса локального мозга (сек) — зависший демон → Err → fallback.
    pub local_timeout_secs: u64,
    /// TTL гранта при «поделиться своим ПК» (сек); 0 = без лимита.
    pub ttl_secs: u64,
    /// «Запомнить друга» при шеринге (опт-ин персист pairing: стабильная личность + allowlist).
    pub remember: bool,
}

// Ручной Debug: НЕ печатать api_key (иначе `{:?}`/`dbg!` слил бы LLM-ключ в логи).
// fallback.api_key маскируется собственным Debug у BrainProfile.
impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settings")
            .field("model", &self.model)
            .field("host", &self.host)
            .field("api_key", &self.api_key.as_ref().map(|_| "***"))
            .field("provider", &self.provider)
            .field("allowed_path", &self.allowed_path)
            .field("allow_shell", &self.allow_shell)
            .field("allow_dangerous", &self.allow_dangerous)
            .field("routing", &self.routing)
            .field("fallback", &self.fallback)
            .field("local_timeout_secs", &self.local_timeout_secs)
            .field("ttl_secs", &self.ttl_secs)
            .field("remember", &self.remember)
            .finish()
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            model: crate::brain::default_model(),
            host: std::env::var("OLLAMA_HOST")
                .ok()
                .filter(|h| !h.is_empty())
                .unwrap_or_else(|| "http://localhost:11434".to_string()),
            api_key: std::env::var("OLLAMA_API_KEY").ok().filter(|k| !k.is_empty()),
            provider: crate::brain::Provider::default(),
            allowed_path: None,
            allow_shell: true,
            allow_dangerous: false,
            routing: false,
            fallback: crate::brain::BrainProfile::default(),
            local_timeout_secs: 30,
            ttl_secs: 0,
            remember: false,
        }
    }
}

impl Settings {
    /// Собрать политику безопасности из настроек. Struct-литерал (не `default()`+reassign):
    /// и компилируется против 4-полевого `Policy`, и не ловит clippy `field_reassign_with_default`.
    pub fn to_policy(&self) -> Policy {
        Policy {
            allowed_paths: self.allowed_path.clone().into_iter().collect(),
            blocked_patterns: Vec::new(),
            allow_shell: self.allow_shell,
            allow_dangerous: self.allow_dangerous,
        }
    }

    /// Грант для «поделиться своим ПК»: политика из настроек + TTL (0 = без лимита).
    /// `remember` читается отдельно при bind (это про идентичность, не про политику).
    pub fn to_grant(&self) -> crate::net::Grant {
        crate::net::Grant {
            policy: self.to_policy(),
            ttl: (self.ttl_secs > 0).then(|| std::time::Duration::from_secs(self.ttl_secs)),
        }
    }

    /// Профиль primary-мозга из плоских полей настроек.
    fn primary_profile(&self) -> crate::brain::BrainProfile {
        crate::brain::BrainProfile {
            provider: self.provider,
            host: self.host.clone(),
            model: self.model.clone(),
            api_key: self.api_key.clone(),
        }
    }

    /// Роутер активен = тумблер включён И fallback-профиль полный.
    /// Включённый routing с пустым fallback → роутер НЕ активируется (один мозг).
    pub fn routing_active(&self) -> bool {
        self.routing && self.fallback.is_complete()
    }

    /// Построить мозг из настроек. `routing` выкл / неполный fallback → один мозг
    /// (как прежде). `routing` вкл + полный fallback → `RoutingBrain` (local primary
    /// с таймаутом → cloud fallback).
    pub fn build_brain(&self) -> Box<dyn crate::brain::Brain> {
        if self.routing_active() {
            return Box::new(crate::brain::RoutingBrain::new(
                self.primary_profile().build_with_timeout(self.local_timeout_secs),
                self.fallback.build(),
            ));
        }
        if self.routing && !self.fallback.is_complete() {
            eprintln!(
                "[micromanager] routing включён, но fallback-профиль неполный (нет host/model) — \
                 работаю на одном мозге"
            );
        }
        self.primary_profile().build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_safe() {
        let s = Settings::default();
        assert!(s.allow_shell);
        assert!(!s.allow_dangerous);
        assert!(s.allowed_path.is_none());
        assert!(!s.model.is_empty());
    }

    #[test]
    fn ttl_remember_roundtrip_and_to_grant() {
        let s = Settings {
            ttl_secs: 300,
            remember: true,
            ..Default::default()
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: Settings = serde_json::from_str(&json).unwrap();
        assert_eq!(back.ttl_secs, 300);
        assert!(back.remember);
        assert_eq!(s.to_grant().ttl, Some(std::time::Duration::from_secs(300)));
        // ttl_secs=0 → без лимита
        let s0 = Settings {
            ttl_secs: 0,
            ..Default::default()
        };
        assert_eq!(s0.to_grant().ttl, None);
    }

    #[test]
    fn to_policy_maps_fields() {
        let s = Settings {
            allow_shell: false,
            allow_dangerous: true,
            allowed_path: Some(std::path::PathBuf::from("/tmp/work")),
            ..Default::default()
        };
        let p = s.to_policy();
        assert!(!p.allow_shell);
        assert!(p.allow_dangerous);
        assert_eq!(p.allowed_paths, vec![std::path::PathBuf::from("/tmp/work")]);
    }

    #[test]
    fn to_policy_empty_path_means_unrestricted() {
        let p = Settings::default().to_policy();
        assert!(p.allowed_paths.is_empty()); // пусто = без ограничения пути (как Policy::default)
    }

    #[test]
    fn default_has_host() {
        let s = Settings::default();
        assert!(!s.host.is_empty());
    }

    #[test]
    fn default_provider_is_ollama() {
        assert_eq!(Settings::default().provider, crate::brain::Provider::Ollama);
    }

    #[test]
    fn build_brain_returns_boxed_brain() {
        // build_brain теперь отдаёт Box<dyn Brain>; просто строим оба провайдера без паники.
        let mut s = Settings { model: "m".into(), host: "http://localhost:11434".into(), ..Default::default() };
        let _ = s.build_brain();
        s.provider = crate::brain::Provider::OpenAi;
        s.host = "https://openrouter.ai/api/v1".into();
        s.api_key = Some("k".into());
        let _ = s.build_brain();
    }

    #[test]
    fn routing_active_requires_toggle_and_complete_fallback() {
        use crate::brain::{BrainProfile, Provider};
        // выкл → не активен
        assert!(!Settings::default().routing_active());
        // вкл + полный fallback → активен
        let complete = BrainProfile {
            provider: Provider::OpenAi,
            host: "https://openrouter.ai/api/v1".into(),
            model: "z-ai/glm-4.6".into(),
            api_key: Some("k".into()),
        };
        let s = Settings {
            routing: true,
            fallback: complete,
            ..Default::default()
        };
        assert!(s.routing_active());
        // вкл, но fallback пустой → НЕ активен (не уводим на нерабочий fallback)
        let s2 = Settings {
            routing: true,
            fallback: BrainProfile::default(),
            ..Default::default()
        };
        assert!(!s2.routing_active(), "пустой fallback при routing=on → не активен");
    }

    #[test]
    fn build_brain_combos_do_not_panic() {
        use crate::brain::{BrainProfile, Provider};
        // routing off → один мозг
        let _ = Settings::default().build_brain();
        // routing on + полный fallback → RoutingBrain
        let s = Settings {
            routing: true,
            fallback: BrainProfile {
                provider: Provider::OpenAi,
                host: "https://openrouter.ai/api/v1".into(),
                model: "m".into(),
                api_key: Some("k".into()),
            },
            ..Default::default()
        };
        let _ = s.build_brain();
        // routing on + пустой fallback → один мозг + warning, не паника
        let s2 = Settings {
            routing: true,
            ..Default::default()
        };
        let _ = s2.build_brain();
    }

    #[test]
    fn old_config_without_routing_fields_defaults_off() {
        // Старый конфиг без routing/fallback/local_timeout_secs → дефолты, не падаем.
        let json = r#"{"model":"x","provider":"ollama"}"#;
        let s: Settings = serde_json::from_str(json).unwrap();
        assert!(!s.routing, "routing по умолчанию off");
        assert!(s.local_timeout_secs > 0, "таймаут имеет дефолт");
        assert!(!s.fallback.is_complete(), "fallback по умолчанию пуст");
    }

    #[test]
    fn provider_serde_default_for_old_config() {
        // Старый конфиг без provider → Ollama (serde default на контейнере).
        let json = r#"{"model":"x"}"#;
        let s: Settings = serde_json::from_str(json).unwrap();
        assert_eq!(s.provider, crate::brain::Provider::Ollama);
    }

    #[test]
    fn serde_roundtrip_with_missing_fields_uses_defaults() {
        // старый конфиг без host/api_key → дефолты, не падаем
        let json = r#"{"model":"x","allow_shell":false}"#;
        let s: Settings = serde_json::from_str(json).unwrap();
        assert_eq!(s.model, "x");
        assert!(!s.allow_shell);
        assert!(!s.host.is_empty()); // host подставлен из Default
    }
}
