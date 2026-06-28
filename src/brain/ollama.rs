//! Мозг на локальной Ollama (`/api/chat` с tool-calling). Блокирующий HTTP —
//! агент-цикл синхронный; в async-контексте вызывать через spawn_blocking.

use serde::Deserialize;
use serde_json::json;

use super::{Brain, Message, ToolSpec};

pub struct OllamaBrain {
    host: String,
    model: String,
    api_key: Option<String>,
    client: reqwest::blocking::Client,
}

impl OllamaBrain {
    pub fn new(host: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            model: model.into(),
            api_key: None,
            client: reqwest::blocking::Client::new(),
        }
    }

    /// Прицепить Bearer API-ключ (для прямого Ollama-cloud). None/пустой — без авторизации.
    pub fn with_api_key(mut self, key: Option<String>) -> Self {
        self.api_key = key.filter(|k| !k.is_empty());
        self
    }

    pub fn api_key(&self) -> Option<&str> {
        self.api_key.as_deref()
    }

    /// Настроить таймаут HTTP-клиента для `chat` (роутер: зависший локальный демон
    /// → `Err` по таймауту → авто-fallback). Probe `health()` использует свой таймаут.
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(secs))
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new());
        self
    }

    /// Хост из `OLLAMA_HOST` (по умолч. localhost:11434), модель — из аргумента,
    /// иначе `MM_MODEL`, иначе gemma4:12b (умеет tools, проверено). Ключ — `OLLAMA_API_KEY`.
    pub fn from_env(model: Option<String>) -> Self {
        let host =
            std::env::var("OLLAMA_HOST").unwrap_or_else(|_| "http://localhost:11434".to_string());
        let model = model
            .or_else(|| std::env::var("MM_MODEL").ok())
            .unwrap_or_else(|| "gemma4:12b".to_string());
        Self::new(host, model).with_api_key(std::env::var("OLLAMA_API_KEY").ok())
    }

    pub fn model(&self) -> &str {
        &self.model
    }
}

#[derive(Deserialize)]
struct ChatResponse {
    message: Message,
}

impl Brain for OllamaBrain {
    fn chat(&self, messages: &[Message], tools: &[ToolSpec]) -> anyhow::Result<Message> {
        let body = json!({
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "stream": false,
        });
        let mut req = self.client.post(format!("{}/api/chat", self.host)).json(&body);
        if let Some(key) = &self.api_key {
            // Не отправляем API-ключ по cleartext: только HTTPS или локальный хост.
            if !super::host_allows_key(&self.host) {
                anyhow::bail!(
                    "отказ: API-ключ нельзя слать на не-HTTPS хост ({}). Используй https:// \
                     или локальный демон Ollama без ключа.",
                    self.host
                );
            }
            req = req.bearer_auth(key);
        }
        let resp = req.send()?;
        let status = resp.status();
        if !status.is_success() {
            // Тело часто содержит причину (напр. «requires subscription, upgrade…») —
            // вытащим её, иначе мутный «403 Forbidden» теряет смысл.
            let body = resp.text().unwrap_or_default();
            let detail = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from))
                .unwrap_or(body);
            let detail: String = detail.trim().chars().take(300).collect();
            anyhow::bail!("Ollama {status}: {detail}");
        }
        let parsed: ChatResponse = resp.json()?;
        Ok(parsed.message)
    }

    /// Probe доступности демона: GET `{host}/api/tags` с коротким таймаутом.
    /// 2xx → доступен; ошибка/таймаут/не-2xx → недоступен (роутер уйдёт на fallback).
    /// Таймаут probe независим от таймаута `chat` — зависший пинг не вешает старт.
    fn health(&self) -> bool {
        self.client
            .get(format!("{}/api/tags", self.host))
            .timeout(std::time::Duration::from_secs(2))
            .send()
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_stored_via_builder() {
        let b = OllamaBrain::new("http://h", "m").with_api_key(Some("secret".into()));
        assert_eq!(b.api_key(), Some("secret"));
        assert_eq!(b.model(), "m");
    }

    #[test]
    fn no_api_key_by_default() {
        let b = OllamaBrain::new("http://h", "m");
        assert_eq!(b.api_key(), None);
    }

    #[test]
    fn host_allows_key_https_and_localhost_only() {
        use crate::brain::host_allows_key;
        assert!(host_allows_key("https://ollama.com"));
        assert!(host_allows_key("http://localhost:11434"));
        assert!(host_allows_key("http://127.0.0.1:11434"));
        assert!(!host_allows_key("http://evil.example.com")); // cleartext + не локалхост
        assert!(!host_allows_key("ftp://x")); // схема не распознана → отказ
    }

    #[test]
    fn with_timeout_preserves_config() {
        // Настраиваемый таймаут chat-клиента (зависший демон → Err по таймауту → fallback).
        // Билдер не теряет model/api_key; саму сетевую отсечку не симулируем.
        let b = OllamaBrain::new("http://h", "m")
            .with_api_key(Some("k".into()))
            .with_timeout(5);
        assert_eq!(b.model(), "m");
        assert_eq!(b.api_key(), Some("k"));
    }

    #[test]
    fn health_false_on_dead_host() {
        // Демон недоступен (порт 1, connection refused — мгновенно) → health()==false,
        // без зависания теста (короткий таймаут probe).
        let b = OllamaBrain::new("http://127.0.0.1:1", "m");
        assert!(!b.health(), "мёртвый Ollama-хост → health false");
    }

    #[test]
    fn chat_refuses_key_over_cleartext() {
        // ключ + http не-локалхост → отказ ещё ДО сети (без реального запроса)
        let b = OllamaBrain::new("http://evil.example.com", "m").with_api_key(Some("k".into()));
        let err = b.chat(&[], &[]).unwrap_err();
        assert!(err.to_string().contains("API-ключ"));
    }
}
