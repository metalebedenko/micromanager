//! Мозг на OpenAI-совместимом API (`/chat/completions` с tool-calling): OpenRouter
//! и любой совместимый endpoint. Блокирующий HTTP — звать из spawn_blocking.
//! Перевод внутреннего (Ollama-образного) формата ⇄ провод OpenAI живёт здесь.

use serde::Deserialize;
use serde_json::{json, Value};

use super::{host_allows_key, Brain, FunctionCall, Message, ToolCall, ToolSpec};

pub struct OpenAiBrain {
    base_url: String,
    model: String,
    api_key: String,
    client: reqwest::blocking::Client,
}

impl OpenAiBrain {
    pub fn new(base_url: impl Into<String>, model: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            model: model.into(),
            api_key: api_key.into(),
            client: reqwest::blocking::Client::new(),
        }
    }
    pub fn model(&self) -> &str {
        &self.model
    }
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}
#[derive(Deserialize)]
struct Choice {
    message: WireMessage,
}
#[derive(Deserialize)]
struct WireMessage {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Option<Vec<WireToolCall>>,
}
#[derive(Deserialize)]
struct WireToolCall {
    #[serde(default)]
    id: Option<String>,
    function: WireFunction,
}
#[derive(Deserialize)]
struct WireFunction {
    name: String,
    /// OpenAI отдаёт arguments СТРОКОЙ с JSON внутри.
    #[serde(default)]
    arguments: String,
}

impl OpenAiBrain {
    /// Внутренняя история → тело запроса OpenAI (одно место перевода форматов).
    fn build_request(&self, messages: &[Message], tools: &[ToolSpec]) -> Value {
        let msgs: Vec<Value> = messages.iter().map(wire_message).collect();
        let mut body = json!({
            "model": self.model,
            "messages": msgs,
            "stream": false,
        });
        if !tools.is_empty() {
            body["tools"] = serde_json::to_value(tools).unwrap_or(Value::Null);
        }
        body
    }
}

/// Перевод одного внутреннего сообщения в OpenAI-форму.
fn wire_message(m: &Message) -> Value {
    // Ассистент с tool_calls и без текста: content должен отсутствовать (не ""),
    // иначе строгие OpenAI-совместимые эндпоинты отклоняют запрос.
    let omit_content = m.role == "assistant" && m.content.is_empty() && m.tool_calls.is_some();
    let mut v = if omit_content {
        json!({ "role": m.role })
    } else {
        json!({ "role": m.role, "content": m.content })
    };
    if m.role == "tool" {
        if let Some(id) = &m.tool_call_id {
            v["tool_call_id"] = json!(id);
        }
    }
    if let Some(calls) = &m.tool_calls {
        let wired: Vec<Value> = calls
            .iter()
            .enumerate()
            .map(|(i, c)| {
                // id обязателен для OpenAI; если мозг почему-то не дал — синтезируем стабильный.
                let id = c.id.clone().unwrap_or_else(|| format!("call_{i}"));
                json!({
                    "id": id,
                    "type": "function",
                    "function": {
                        "name": c.function.name,
                        "arguments": serde_json::to_string(&c.function.arguments).unwrap_or_else(|_| "{}".into()),
                    }
                })
            })
            .collect();
        v["tool_calls"] = json!(wired);
    }
    v
}

/// OpenAI-ответ → внутреннее assistant-сообщение (arguments-строка → Value).
fn parse_response(raw: Value) -> anyhow::Result<Message> {
    let parsed: ChatResponse = serde_json::from_value(raw)?;
    let wm = parsed
        .choices
        .into_iter()
        .next()
        .map(|c| c.message)
        .ok_or_else(|| anyhow::anyhow!("OpenAI: пустой choices"))?;
    let tool_calls = wm.tool_calls.map(|calls| {
        calls
            .into_iter()
            .map(|c| {
                let arguments = if c.function.arguments.trim().is_empty() {
                    json!({})
                } else {
                    serde_json::from_str(&c.function.arguments).unwrap_or_else(|_| json!({}))
                };
                ToolCall {
                    id: c.id,
                    function: FunctionCall { name: c.function.name, arguments },
                }
            })
            .collect::<Vec<_>>()
    });
    Ok(Message {
        role: "assistant".to_string(),
        content: wm.content.unwrap_or_default(),
        tool_name: None,
        tool_call_id: None,
        tool_calls,
    })
}

// `health()` намеренно НЕ переопределён: cloud-провайдер наследует дефолт трейта
// `true`. Реальная проверка доступности — первый `chat` (его ошибка всплывает телом);
// лишний пинг `/models` дал бы false-negative/задержку.
impl Brain for OpenAiBrain {
    fn chat(&self, messages: &[Message], tools: &[ToolSpec]) -> anyhow::Result<Message> {
        // Bearer-ключ только по HTTPS/localhost (как в OllamaBrain).
        if !host_allows_key(&self.base_url) {
            anyhow::bail!(
                "отказ: API-ключ нельзя слать на не-HTTPS хост ({}). Используй https://.",
                self.base_url
            );
        }
        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        let resp = self
            .client
            .post(url)
            .bearer_auth(&self.api_key)
            .json(&self.build_request(messages, tools))
            .send()?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            let detail = serde_json::from_str::<Value>(&body)
                .ok()
                .and_then(|v| {
                    v.get("error")
                        .and_then(|e| e.get("message").and_then(|m| m.as_str()).map(String::from))
                        .or_else(|| v.get("error").and_then(|e| e.as_str()).map(String::from))
                })
                .unwrap_or(body);
            let detail: String = detail.trim().chars().take(300).collect();
            anyhow::bail!("OpenAI {status}: {detail}");
        }
        parse_response(resp.json()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn brain() -> OpenAiBrain {
        OpenAiBrain::new("https://openrouter.ai/api/v1", "z-ai/glm-4.6", "k")
    }

    #[test]
    fn health_is_true_for_cloud() {
        // OpenAI-совместимый (cloud) наследует дефолт трейта `true`: реальная
        // проверка доступности — первый `chat` (его ошибка всплывает телом),
        // лишний пинг /models дал бы false-negative/задержку.
        assert!(brain().health());
    }

    #[test]
    fn request_body_maps_messages_and_tools() {
        let msgs = vec![Message::system("s"), Message::user("привет")];
        let body = brain().build_request(&msgs, &[]);
        assert_eq!(body["model"], "z-ai/glm-4.6");
        assert_eq!(body["stream"], false);
        assert_eq!(body["messages"][1]["role"], "user");
        assert_eq!(body["messages"][1]["content"], "привет");
    }

    #[test]
    fn request_serializes_assistant_tool_calls_with_string_arguments() {
        // assistant с tool_call: arguments в OpenAI — СТРОКА, не объект.
        let mut assistant = Message { role: "assistant".into(), content: String::new(), tool_name: None, tool_call_id: None,
            tool_calls: Some(vec![ToolCall { id: Some("c1".into()),
                function: FunctionCall { name: "list_dir".into(), arguments: json!({"path":"."}) } }]) };
        assistant.content = String::new();
        let tool_msg = Message::tool_with_id("list_dir", Some("c1".into()), "[]");
        let body = brain().build_request(&[assistant, tool_msg], &[]);
        let tc = &body["messages"][0]["tool_calls"][0];
        assert_eq!(tc["id"], "c1");
        assert_eq!(tc["type"], "function");
        assert_eq!(tc["function"]["name"], "list_dir");
        // arguments — строка с JSON внутри
        let args = tc["function"]["arguments"].as_str().expect("arguments должна быть строкой");
        assert_eq!(serde_json::from_str::<Value>(args).unwrap()["path"], ".");
        // tool-сообщение несёт tool_call_id и role=tool
        assert_eq!(body["messages"][1]["role"], "tool");
        assert_eq!(body["messages"][1]["tool_call_id"], "c1");
        assert_eq!(body["messages"][1]["content"], "[]");
    }

    #[test]
    fn parse_response_extracts_content_and_tool_calls() {
        let raw = json!({"choices":[{"message":{"role":"assistant","content":"",
            "tool_calls":[{"id":"call_9","type":"function",
                "function":{"name":"read_file","arguments":"{\"path\":\"todo.txt\"}"}}]}}]});
        let m = parse_response(raw).unwrap();
        assert_eq!(m.role, "assistant");
        let calls = m.tool_calls.unwrap();
        assert_eq!(calls[0].id.as_deref(), Some("call_9"));
        assert_eq!(calls[0].function.name, "read_file");
        // arguments-строка распарсена обратно в Value
        assert_eq!(calls[0].function.arguments["path"], "todo.txt");
    }

    #[test]
    fn parse_response_plain_text_has_no_tool_calls() {
        let raw = json!({"choices":[{"message":{"role":"assistant","content":"готово"}}]});
        let m = parse_response(raw).unwrap();
        assert_eq!(m.content, "готово");
        assert!(m.tool_calls.is_none());
    }

    #[test]
    fn parse_response_empty_choices_errors() {
        let raw = json!({"choices":[]});
        assert!(parse_response(raw).is_err());
    }

    #[test]
    fn parse_response_multiple_tool_calls_preserved() {
        let raw = json!({"choices":[{"message":{"role":"assistant","content":"",
            "tool_calls":[
                {"id":"a","type":"function","function":{"name":"list_dir","arguments":"{\"path\":\".\"}"}},
                {"id":"b","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"x\"}"}}
            ]}}]});
        let calls = parse_response(raw).unwrap().tool_calls.unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].id.as_deref(), Some("a"));
        assert_eq!(calls[1].function.name, "read_file");
    }

    #[test]
    fn parse_response_empty_arguments_string_becomes_empty_object() {
        let raw = json!({"choices":[{"message":{"role":"assistant","content":"",
            "tool_calls":[{"id":"c","type":"function","function":{"name":"list_dir","arguments":""}}]}}]});
        let calls = parse_response(raw).unwrap().tool_calls.unwrap();
        assert_eq!(calls[0].function.arguments, json!({}));
    }

    #[test]
    fn parse_response_malformed_arguments_falls_back_to_empty_object() {
        // Битая (не-JSON) строка arguments не должна валить весь ответ — fallback {}.
        let raw = json!({"choices":[{"message":{"role":"assistant","content":"",
            "tool_calls":[{"id":"c","type":"function","function":{"name":"list_dir","arguments":"{not json"}}]}}]});
        let calls = parse_response(raw).unwrap().tool_calls.unwrap();
        assert_eq!(calls[0].function.arguments, json!({}));
    }

    #[test]
    fn chat_refuses_key_over_cleartext() {
        let b = OpenAiBrain::new("http://evil.example.com/v1", "m", "k");
        let err = b.chat(&[], &[]).unwrap_err();
        assert!(err.to_string().contains("API-ключ"));
    }

    #[test]
    fn assistant_with_only_tool_calls_omits_empty_content() {
        let assistant = Message { role: "assistant".into(), content: String::new(), tool_name: None, tool_call_id: None,
            tool_calls: Some(vec![ToolCall { id: Some("c1".into()),
                function: FunctionCall { name: "list_dir".into(), arguments: serde_json::json!({"path":"."}) } }]) };
        let body = OpenAiBrain::new("https://openrouter.ai/api/v1", "m", "k").build_request(&[assistant], &[]);
        let msg = &body["messages"][0];
        assert!(msg.get("content").is_none() || msg["content"].is_null(),
            "assistant с только tool_calls не должен слать пустой content: {msg}");
        assert!(msg["tool_calls"][0]["id"] == "c1");
    }
}
