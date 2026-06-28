//! Telegram-фронт: приём команд владельца → safety+audit → ответ.
//! Bot API за трейтом `TelegramApi` (мок в тестах, reqwest-клиент в проде). Long-polling.

use std::sync::Arc;

use anyhow::Result;
use serde::Deserialize;
use serde_json::json;

use crate::brain::{run_agent, run_agent_with, Brain, ToolRunner};
use crate::command::route_command;
use crate::net::{McpSession, McpToolRunner};

mod confirm;
mod report;
pub use confirm::{
    format_callback, parse_callback, ButtonSender, Decision, PendingConfirms, TelegramConfirmer,
};
pub use report::{redact, ReportSink, ReqwestReportSink, TelegramReportAudit};

/// Минимальные типы Bot API.
#[derive(Deserialize, Clone, Debug)]
pub struct Update {
    pub update_id: i64,
    #[serde(default)]
    pub message: Option<Message>,
    #[serde(default)]
    pub callback_query: Option<CallbackQuery>,
}
#[derive(Deserialize, Clone, Debug)]
pub struct Message {
    pub chat: Chat,
    #[serde(default)]
    pub text: Option<String>,
}
#[derive(Deserialize, Clone, Debug)]
pub struct Chat {
    pub id: i64,
}
#[derive(Deserialize, Clone, Debug)]
pub struct CallbackQuery {
    pub id: String,
    pub from: User,
    #[serde(default)]
    pub data: Option<String>,
}
#[derive(Deserialize, Clone, Debug)]
pub struct User {
    pub id: i64,
}

/// Абстракция Bot API: реальный reqwest-клиент или мок в тестах.
pub trait TelegramApi: Send + Sync {
    /// Long-poll новых апдейтов начиная с offset.
    fn get_updates(
        &self,
        offset: i64,
    ) -> impl std::future::Future<Output = Result<Vec<Update>>> + Send;
    /// Отправить текст в чат.
    fn send_message(
        &self,
        chat_id: i64,
        text: &str,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    /// Отправить текст как MarkdownV2 (для ``` code-block моноширинного вывода).
    fn send_markdown(
        &self,
        chat_id: i64,
        text: &str,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    /// Подтвердить callback (гасит «часики» на inline-кнопке) + короткий тост.
    fn answer_callback(
        &self,
        callback_id: &str,
        text: &str,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

/// Лимит длины сообщения Telegram = 4096 UTF-16 единиц. Режем по 4000 символов
/// (запас под суррогатные пары эмодзи: символ может стоить 2 UTF-16 единицы).
const TG_MAX_CHARS: usize = 4000;

/// Разбить длинный ответ на куски ≤ `max` символов для Telegram (иначе sendMessage
/// отвергает >4096). Режем по границам строк; строку длиннее `max` — жёстко по символам.
/// Пустой текст → пустой вектор (нечего слать). Склейка кусков == оригинал.
fn split_message(text: &str, max: usize) -> Vec<String> {
    if text.is_empty() {
        return Vec::new();
    }
    let mut chunks = Vec::new();
    let mut cur = String::new();
    for line in text.split_inclusive('\n') {
        if line.chars().count() > max {
            // строка сама длиннее лимита → сбросить накопленное и резать жёстко
            if !cur.is_empty() {
                chunks.push(std::mem::take(&mut cur));
            }
            let mut buf = String::new();
            for ch in line.chars() {
                if buf.chars().count() == max {
                    chunks.push(std::mem::take(&mut buf));
                }
                buf.push(ch);
            }
            cur = buf; // остаток несём в следующий кусок
            continue;
        }
        if cur.chars().count() + line.chars().count() > max {
            chunks.push(std::mem::take(&mut cur));
        }
        cur.push_str(line);
    }
    if !cur.is_empty() {
        chunks.push(cur);
    }
    chunks
}

/// Ответ владельцу: текст + надо ли моноширить (вывод явной команды).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub text: String,
    pub mono: bool,
}

impl Reply {
    pub fn plain(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            mono: false,
        }
    }
    pub fn mono(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            mono: true,
        }
    }
}

/// Исходящее сообщение после рендера: обычный текст или MarkdownV2-блок (+ сырой fallback).
#[derive(Debug, PartialEq, Eq)]
pub enum OutMessage {
    Plain(String),
    Markdown { formatted: String, fallback: String },
}

/// Разложить ответ в исходящие сообщения: режем по `max`; mono → самодостаточные ``` блоки.
pub fn render_reply(reply: &Reply, max: usize) -> Vec<OutMessage> {
    split_message(&reply.text, max)
        .into_iter()
        .map(|chunk| {
            if reply.mono {
                OutMessage::Markdown {
                    formatted: code_block(&escape_code_block(&chunk)),
                    fallback: chunk,
                }
            } else {
                OutMessage::Plain(chunk)
            }
        })
        .collect()
}

/// Короткий тост для answerCallbackQuery по решению (≤ 200 символов).
fn toast(d: crate::tg::confirm::Decision) -> &'static str {
    use crate::tg::confirm::Decision;
    match d {
        Decision::Yes => "✅ принято",
        Decision::All => "♾ доверяю до конца сессии",
        Decision::No => "🚫 отклонено",
    }
}

/// Замаскировать Telegram bot-token в строке (reqwest-ошибки включают URL вида
/// `.../bot<TOKEN>/method`; reqwest НЕ редактит path → токен утёк бы в stderr/логи).
/// Заменяет всё между `/bot` и следующим `/` на `***`.
pub(crate) fn scrub_token(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find("/bot") {
        let (head, tail) = rest.split_at(pos + 4); // включая "/bot"
        out.push_str(head);
        out.push_str("***");
        match tail.find('/') {
            Some(slash) => rest = &tail[slash..], // оставшийся путь (с `/method`)
            None => {
                rest = "";
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Разослать исходящие: Plain → send_message; Markdown → send_markdown с fail-safe
/// (ошибка → send_message сырым текстом). UI не должен терять сообщение.
async fn deliver_outs<A: TelegramApi>(api: &A, chat_id: i64, outs: Vec<OutMessage>) {
    for out in outs {
        match out {
            OutMessage::Plain(t) => {
                if let Err(e) = api.send_message(chat_id, &t).await {
                    eprintln!("[tg] send_message ошибка: {}", scrub_token(&e.to_string()));
                }
            }
            OutMessage::Markdown { formatted, fallback } => {
                if let Err(e) = api.send_markdown(chat_id, &formatted).await {
                    eprintln!("[tg] send_markdown ошибка ({}); fallback plain", scrub_token(&e.to_string()));
                    let _ = api.send_message(chat_id, &fallback).await;
                }
            }
        }
    }
}

/// Экранировать содержимое для MarkdownV2 ``` code-block: ТОЛЬКО `\` и backtick
/// (внутри code-block остальные спецсимволы MarkdownV2 литеральны).
fn escape_code_block(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch == '\\' || ch == '`' {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// Обернуть уже-экранированный текст в MarkdownV2 code-block. `\n` сразу после
/// открывающего fence обязателен — иначе Telegram примет первое слово за language-тег.
fn code_block(escaped: &str) -> String {
    format!("```\n{escaped}\n```")
}

/// Обработать текст (sync; зовётся из spawn_blocking). Явная команда → диспатч;
/// иначе при наличии мозга — agent-loop (NL-режим); без мозга — справка (raw).
pub fn process_text(runner: &dyn ToolRunner, brain: Option<&dyn Brain>, text: &str) -> Reply {
    if let Some((tool, args)) = route_command(text) {
        return Reply::mono(runner.dispatch(&tool, &args));
    }
    match brain {
        Some(b) => Reply::plain(
            run_agent(b, runner, text).unwrap_or_else(|e| format!("мозг недоступен: {e}")),
        ),
        None => Reply::plain(HELP),
    }
}

/// Обработать сообщение владельца: /connect, /disconnect, удалённая команда (если
/// подключены к B) или локально (команда/NL). Async — т.к. удалёнка по сети.
async fn dispatch_message(
    text: &str,
    local: &Arc<McpToolRunner>,
    brain: Option<Arc<dyn Brain>>,
    remote: &RemoteSlot,
) -> Reply {
    if let Some(code) = text.strip_prefix("/connect ").map(str::trim) {
        return Reply::plain(match McpSession::connect(code).await {
            Ok(session) => {
                match session.list_tools_full().await {
                    Ok(tools) => {
                        let specs: Vec<_> = tools.iter().map(crate::net::map_tool).collect();
                        let tool_names: Vec<String> = specs.iter().map(|s| s.function.name.clone()).collect();
                        let runner = McpToolRunner::start(session, specs);
                        *remote.lock().await = Some(runner);
                        format!(
                            "✅ Подключился к компу друга. Тулы: {}. Команды теперь идут ТУДА. /disconnect — отключиться.",
                            tool_names.join(", ")
                        )
                    }
                    Err(e) => format!("❌ Не удалось получить список тулов: {e}"),
                }
            }
            Err(e) => format!("❌ Не удалось подключиться: {e}"),
        });
    }
    if text.trim() == "/disconnect" {
        let taken = remote.lock().await.take();
        return Reply::plain(match taken {
            Some(runner) => {
                // shutdown блокирующий (join потока) — выносим из async-контекста
                tokio::task::spawn_blocking(move || runner.shutdown())
                    .await
                    .ok();
                "Отключился от компа друга. Команды снова локальные.".to_string()
            }
            None => "Нет активного подключения.".to_string(),
        });
    }
    // подключены к B → команда исполняется на B (под вето владельца B)
    {
        let h = { let g = remote.lock().await; g.as_ref().map(|r| r.handle()) };
        if let Some(h) = h {
            if let Some((tool, args)) = route_command(text) {
                // dispatch блокирующий (blocking_recv) — выносим из async
                return tokio::task::spawn_blocking(move || h.dispatch(&tool, &args))
                    .await
                    .map(Reply::mono)
                    .unwrap_or_else(|_| Reply::plain("внутренняя ошибка"));
            }
            // NL-ветка: есть мозг → agent-loop через удалённый хэндл
            if let Some(b) = brain.clone() {
                let text = text.to_string();
                return tokio::task::spawn_blocking(move || {
                    let mut msgs = crate::brain::new_conversation();
                    msgs.push(crate::brain::Message::user(&text));
                    run_agent_with(&*b, &h, &mut msgs, &std::sync::atomic::AtomicBool::new(false))
                        .unwrap_or_else(|e| format!("мозг недоступен: {e}"))
                })
                .await
                .map(Reply::plain)
                .unwrap_or_else(|_| Reply::plain("внутренняя ошибка"));
            }
            // нет мозга → подсказка про команды
            return Reply::plain("На компе друга: команды (list_dir/read_file/search/run_shell/write_file); для NL подключите мозг.");
        }
    }
    // локально: возможен блокирующий confirm → отдельный blocking-поток.
    // `handle` (клонируемый) идёт в поток; раннер живёт в TelegramFront.
    let h = local.handle();
    let text = text.to_string();
    tokio::task::spawn_blocking(move || process_text(&h, brain.as_deref(), &text))
        .await
        .unwrap_or_else(|_| Reply::plain("внутренняя ошибка"))
}

/// Telegram-фронт: polling → allowlist(owner) → команда (spawn) / callback (resolve).
/// Слот хранит владельца McpToolRunner; handle() клонируется для dispatch и NL.
type RemoteSlot = Arc<tokio::sync::Mutex<Option<McpToolRunner>>>;

pub struct TelegramFront<T: TelegramApi> {
    api: Arc<T>,
    owner_chat_id: i64,
    local: Arc<McpToolRunner>,
    pending: Arc<PendingConfirms>,
    brain: Option<Arc<dyn Brain>>,
    remote: RemoteSlot,
}

impl<T: TelegramApi + Send + Sync + 'static> TelegramFront<T> {
    pub fn new(
        api: T,
        owner_chat_id: i64,
        local: McpToolRunner,
        pending: Arc<PendingConfirms>,
    ) -> Self {
        Self {
            api: Arc::new(api),
            owner_chat_id,
            local: Arc::new(local),
            pending,
            brain: None,
            remote: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    /// Включить NL-режим: текст-не-команда → agent-loop через этот мозг.
    pub fn with_brain(mut self, brain: Arc<dyn Brain>) -> Self {
        self.brain = Some(brain);
        self
    }

    /// Главный цикл long-polling. Идемпотентность по update_id (offset = last+1).
    /// Сообщения обрабатываются в отдельных задачах (confirm блокируется, не стопоря poll).
    pub async fn run(&self) -> Result<()> {
        eprintln!("[tg] фронт запущен; владелец chat_id={}.", self.owner_chat_id);
        let mut offset = 0i64;
        loop {
            let updates = match self.api.get_updates(offset).await {
                Ok(u) => u,
                Err(e) => {
                    eprintln!("[tg] get_updates ошибка: {}; пауза", scrub_token(&e.to_string()));
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    continue;
                }
            };
            for u in updates {
                offset = u.update_id + 1;
                self.route(u);
            }
        }
    }

    /// Разобрать апдейт: callback от владельца → resolve; сообщение владельца → spawn-обработка.
    fn route(&self, update: Update) {
        if let Some(cb) = update.callback_query {
            if cb.from.id == self.owner_chat_id {
                let api = self.api.clone();
                let id = cb.id.clone();
                if let Some((decision, nonce)) = cb.data.as_deref().and_then(parse_callback) {
                    self.pending.resolve(&nonce, decision);
                    let toast_text = toast(decision); // Decision: Copy
                    tokio::spawn(async move {
                        let _ = api.answer_callback(&id, toast_text).await;
                    });
                } else {
                    // невалидный/протухший callback — всё равно гасим часики
                    tokio::spawn(async move {
                        let _ = api.answer_callback(&id, "").await;
                    });
                }
            }
            return;
        }
        let Some(text) = self.owner_text(&update) else { return };
        let text = text.to_string();
        let local = self.local.clone();
        let api = self.api.clone();
        let brain = self.brain.clone();
        let remote = self.remote.clone();
        let owner = self.owner_chat_id;
        // отдельная задача: dispatch (с возможным блокирующим confirm) не стопорит poll-цикл
        tokio::spawn(async move {
            let reply = dispatch_message(&text, &local, brain.clone(), &remote).await;
            // Вывод команд → моноширинные ``` блоки (MarkdownV2), проза → обычный текст.
            // Режем по лимиту Telegram (4096), fail-safe внутри deliver_outs.
            deliver_outs(&*api, owner, render_reply(&reply, TG_MAX_CHARS)).await;
        });
    }

    /// Текст сообщения, только если оно от владельца (иначе None — игнор).
    fn owner_text<'a>(&self, update: &'a Update) -> Option<&'a str> {
        let msg = update.message.as_ref()?;
        if msg.chat.id != self.owner_chat_id {
            return None;
        }
        msg.text.as_deref()
    }
}

const HELP: &str = "Не понял. Команды: \
list_dir <путь> | read_file <путь> | search <корень> <строка> | run_shell <команда> \
(мутации/команды требуют подтверждения владельца).";

// Парсер команд переехал в crate::command (единый источник для tg и TUI).
// Импортируется как `use crate::command::route_command;` выше.

// ─── Реальный клиент Bot API на reqwest (async) ───

/// Прод-клиент Telegram Bot API. Не используется в тестах (там — мок).
pub struct ReqwestTelegram {
    token: String,
    client: reqwest::Client,
}

impl ReqwestTelegram {
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            client: reqwest::Client::new(),
        }
    }
    fn url(&self, method: &str) -> String {
        format!("https://api.telegram.org/bot{}/{method}", self.token)
    }
}

#[derive(Deserialize)]
struct TgResponse<R> {
    result: R,
}

impl TelegramApi for ReqwestTelegram {
    async fn get_updates(&self, offset: i64) -> Result<Vec<Update>> {
        let resp: TgResponse<Vec<Update>> = self
            .client
            .get(self.url("getUpdates"))
            .query(&[("offset", offset.to_string()), ("timeout", "30".to_string())])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(resp.result)
    }

    async fn send_message(&self, chat_id: i64, text: &str) -> Result<()> {
        self.client
            .post(self.url("sendMessage"))
            .json(&json!({ "chat_id": chat_id, "text": text }))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    async fn send_markdown(&self, chat_id: i64, text: &str) -> Result<()> {
        self.client
            .post(self.url("sendMessage"))
            .json(&json!({ "chat_id": chat_id, "text": text, "parse_mode": "MarkdownV2" }))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    async fn answer_callback(&self, callback_id: &str, text: &str) -> Result<()> {
        self.client
            .post(self.url("answerCallbackQuery"))
            .json(&json!({ "callback_query_id": callback_id, "text": text }))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

/// Прод-отправитель inline-кнопок подтверждения.
/// `send_confirm` зовётся синхронно из confirmer-а, который блокирует driver-поток
/// раннера — а тот выполняется ВНУТРИ tokio-рантайма (`rt.block_on`). `reqwest::blocking`
/// в любом tokio-контексте роняет временный рантайм → паника. Поэтому весь blocking-HTTP
/// выносим на ЧИСТЫЙ std-поток (без ambient-рантайма) и join-им.
pub struct ReqwestButtonSender {
    token: String,
}

impl ReqwestButtonSender {
    pub fn new(token: impl Into<String>) -> Self {
        Self { token: token.into() }
    }
}

impl ButtonSender for ReqwestButtonSender {
    fn send_confirm(&self, chat_id: i64, text: &str, nonce: &str, dangerous: bool) -> Result<()> {
        let keyboard = if dangerous {
            json!([[
                {"text": "‼ Подтвердить ОПАСНОЕ", "callback_data": format_callback(Decision::Yes, nonce)},
                {"text": "Отмена", "callback_data": format_callback(Decision::No, nonce)},
            ]])
        } else {
            json!([[
                {"text": "✅ Да", "callback_data": format_callback(Decision::Yes, nonce)},
                {"text": "♾ На сессию", "callback_data": format_callback(Decision::All, nonce)},
                {"text": "🚫 Нет", "callback_data": format_callback(Decision::No, nonce)},
            ]])
        };
        let prefix = if dangerous { "‼ ОПАСНОЕ — подтвердить?" } else { "Подтвердить действие?" };
        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.token);
        let body = json!({
            "chat_id": chat_id,
            "text": format!("{prefix}\n{text}"),
            "reply_markup": { "inline_keyboard": keyboard },
        });
        // blocking-HTTP — на чистом std-потоке (нет ambient tokio-рантайма → reqwest::blocking ок).
        std::thread::spawn(move || -> Result<()> {
            reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()?
                .post(url)
                .json(&body)
                .send()?
                .error_for_status()?;
            Ok(())
        })
        .join()
        .map_err(|_| anyhow::anyhow!("confirm-поток HTTP паниковал"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::NullAudit;
    use crate::safety::{DenyConfirmer, Policy};

    #[test]
    fn scrub_token_masks_bot_token_in_url() {
        // reqwest-ошибка с URL: токен не должен попасть в stderr.
        let err = "error sending request for url (https://api.telegram.org/bot123456789:AAEhBP-real-secret/getUpdates): timed out";
        let scrubbed = scrub_token(err);
        assert!(!scrubbed.contains("123456789:AAEhBP-real-secret"), "токен утёк: {scrubbed}");
        assert!(scrubbed.contains("/bot***/getUpdates"), "ожидали маску: {scrubbed}");
        // строка без токена не ломается
        assert_eq!(scrub_token("HTTP 401 Unauthorized"), "HTTP 401 Unauthorized");
    }

    /// Мок Bot API (тривиальный — для построения front в синхронных тестах).
    struct MockApi;
    impl TelegramApi for MockApi {
        async fn get_updates(&self, _offset: i64) -> Result<Vec<Update>> {
            Ok(vec![])
        }
        async fn send_message(&self, _chat_id: i64, _text: &str) -> Result<()> {
            Ok(())
        }
        async fn send_markdown(&self, _chat_id: i64, _text: &str) -> Result<()> {
            Ok(())
        }
        async fn answer_callback(&self, _callback_id: &str, _text: &str) -> Result<()> {
            Ok(())
        }
    }

    /// Мок, фиксирующий вызовы (метод, текст) — для проверки deliver_outs/fail-safe.
    #[derive(Default)]
    struct RecordingApi {
        calls: std::sync::Mutex<Vec<(String, String)>>,
        fail_markdown: bool,
    }
    impl TelegramApi for RecordingApi {
        async fn get_updates(&self, _o: i64) -> Result<Vec<Update>> {
            Ok(vec![])
        }
        async fn send_message(&self, _c: i64, text: &str) -> Result<()> {
            self.calls.lock().unwrap().push(("send_message".into(), text.into()));
            Ok(())
        }
        async fn send_markdown(&self, _c: i64, text: &str) -> Result<()> {
            self.calls.lock().unwrap().push(("send_markdown".into(), text.into()));
            if self.fail_markdown {
                anyhow::bail!("400 Bad Request")
            } else {
                Ok(())
            }
        }
        async fn answer_callback(&self, callback_id: &str, text: &str) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(("answer_callback".into(), format!("{callback_id}|{text}")));
            Ok(())
        }
    }

    fn local_runner() -> McpToolRunner {
        McpToolRunner::start_local(
            Policy::default(),
            std::sync::Arc::new(DenyConfirmer),
            std::sync::Arc::new(NullAudit),
        )
    }

    #[test]
    fn split_message_short_text_one_chunk() {
        assert_eq!(split_message("привет", 4000), vec!["привет".to_string()]);
        assert!(split_message("", 4000).is_empty(), "пустой текст → нечего слать");
    }

    #[test]
    fn escape_code_block_escapes_backtick_and_backslash_only() {
        assert_eq!(escape_code_block("a`b"), "a\\`b");
        assert_eq!(escape_code_block("a\\b"), "a\\\\b");
        // точки/дефисы/воскл. знаки внутри блока НЕ спецсимволы — не трогаем
        assert_eq!(escape_code_block("file-1.txt!"), "file-1.txt!");
    }

    #[test]
    fn code_block_wraps_with_leading_newline() {
        let b = code_block("x");
        assert!(b.starts_with("```\n"), "fence + \\n обязателен: {b}");
        assert!(b.ends_with("\n```"), "{b}");
    }

    #[test]
    fn render_reply_plain_splits_to_plain() {
        let r = Reply::plain("короткий");
        assert_eq!(render_reply(&r, 4000), vec![OutMessage::Plain("короткий".into())]);
    }

    #[test]
    fn render_reply_mono_wraps_and_keeps_fallback() {
        let r = Reply::mono("a`b");
        let outs = render_reply(&r, 4000);
        assert_eq!(outs.len(), 1);
        match &outs[0] {
            OutMessage::Markdown { formatted, fallback } => {
                assert!(formatted.starts_with("```\n"), "{formatted}");
                assert!(formatted.contains("a\\`b"), "экранирован бэктик: {formatted}");
                assert_eq!(fallback, "a`b"); // сырой текст для fail-safe
            }
            other => panic!("ожидался Markdown, got {other:?}"),
        }
    }

    #[test]
    fn render_reply_long_mono_makes_multiple_blocks() {
        let big = "строка\n".repeat(2000); // заведомо > 4000 символов
        let outs = render_reply(&Reply::mono(big), 4000);
        assert!(outs.len() >= 2, "длинный вывод режется на блоки: {}", outs.len());
        assert!(outs.iter().all(|o| matches!(o, OutMessage::Markdown { formatted, .. } if formatted.starts_with("```\n"))));
    }

    #[test]
    fn render_reply_empty_is_empty() {
        assert!(render_reply(&Reply::plain(""), 4000).is_empty());
    }

    #[tokio::test]
    async fn deliver_plain_uses_send_message() {
        let api = RecordingApi::default();
        deliver_outs(&api, 1, vec![OutMessage::Plain("привет".into())]).await;
        let calls = api.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "send_message");
        assert_eq!(calls[0].1, "привет");
    }

    #[tokio::test]
    async fn deliver_markdown_uses_send_markdown() {
        let api = RecordingApi::default();
        deliver_outs(
            &api,
            1,
            vec![OutMessage::Markdown { formatted: "```\nx\n```".into(), fallback: "x".into() }],
        )
        .await;
        let calls = api.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "send_markdown");
    }

    #[tokio::test]
    async fn deliver_markdown_failure_falls_back_to_plain() {
        let api = RecordingApi { fail_markdown: true, ..Default::default() };
        deliver_outs(
            &api,
            1,
            vec![OutMessage::Markdown { formatted: "```\nx\n```".into(), fallback: "x".into() }],
        )
        .await;
        let calls = api.calls.lock().unwrap();
        // send_markdown (упал) → затем send_message с fallback
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "send_markdown");
        assert_eq!(calls[1].0, "send_message");
        assert_eq!(calls[1].1, "x");
    }

    #[test]
    fn callback_query_deserializes_id() {
        let j = r#"{"id":"cb42","from":{"id":7},"data":"y:abc"}"#;
        let cb: CallbackQuery = serde_json::from_str(j).unwrap();
        assert_eq!(cb.id, "cb42");
    }

    #[tokio::test]
    async fn button_sender_new_does_not_panic_in_async() {
        // Регресс: раньше reqwest::blocking::Client строился в конструкторе и ронял
        // временный рантайм внутри async (#[tokio::main]) → паника при старте `telegram`.
        // Теперь конструктор только хранит токен — безопасен в async-контексте.
        let _s = ReqwestButtonSender::new("token123");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_confirm_does_not_panic_in_async_runtime() {
        // Регресс: confirmer зовёт send_confirm синхронно из driver-потока, который
        // выполняется ВНУТРИ tokio-рантайма → reqwest::blocking там ронял рантайм (паника).
        // Теперь HTTP уходит на чистый std-поток. Результат — Ok/Err (битый токен/оффлайн),
        // но НЕ паника. Сеть не нужна для проверки именно отсутствия паники.
        let s = ReqwestButtonSender::new("123:invalid-token-for-test");
        let res = s.send_confirm(1, "тест", "nonce", false);
        // Любой исход кроме паники приемлем (обычно Err: 401/404/оффлайн).
        let _ = res;
    }

    #[test]
    fn toast_strings_by_decision() {
        use crate::tg::confirm::Decision;
        assert_eq!(toast(Decision::Yes), "✅ принято");
        assert_eq!(toast(Decision::All), "♾ доверяю до конца сессии");
        assert_eq!(toast(Decision::No), "🚫 отклонено");
        // все ≤ 200 символов (лимит answerCallbackQuery)
        for d in [Decision::Yes, Decision::All, Decision::No] {
            assert!(toast(d).chars().count() <= 200);
        }
    }

    #[test]
    fn split_message_breaks_on_line_boundaries_under_limit() {
        let text = "aaaa\nbbbb\ncccc\n"; // строки по 5 байт с \n
        let chunks = split_message(text, 6); // влезает по ~одной строке
        assert!(chunks.iter().all(|c| c.chars().count() <= 6), "каждый кусок ≤ лимита");
        assert_eq!(chunks.concat(), text, "склейка кусков == оригинал");
    }

    #[test]
    fn split_message_hard_splits_overlong_line() {
        let line = "x".repeat(25); // одна строка длиннее лимита, без \n
        let chunks = split_message(&line, 10);
        assert_eq!(chunks.len(), 3, "25/10 → 3 куска");
        assert!(chunks.iter().all(|c| c.chars().count() <= 10));
        assert_eq!(chunks.concat(), line);
    }

    fn msg(chat: i64, text: &str) -> Update {
        Update {
            update_id: 1,
            message: Some(Message {
                chat: Chat { id: chat },
                text: Some(text.to_string()),
            }),
            callback_query: None,
        }
    }

    #[test]
    fn routes_list_dir_to_real_listing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hi.txt"), "x").unwrap();
        let r = local_runner();
        let out = process_text(&r.handle(), None, &format!("list_dir {}", dir.path().display()));
        assert!(out.text.contains("hi.txt"), "got: {}", out.text);
        assert!(out.mono, "вывод команды моноширинный");
    }

    #[test]
    fn unknown_without_brain_shows_help() {
        let r = local_runner();
        let out = process_text(&r.handle(), None, "привет");
        assert!(out.text.contains("Команды"));
        assert!(!out.mono, "проза/help — не моноширинно");
    }

    #[test]
    fn mutation_denied_without_confirm() {
        // DenyConfirmer: run_shell (Ask) → отказ, команда не исполняется (echo не выполнен)
        let r = local_runner();
        let out = process_text(&r.handle(), None, "run_shell echo mm_marker_42");
        let lo = out.text.to_lowercase();
        assert!(
            !out.text.contains("mm_marker_42") && (lo.contains("отказ") || lo.contains("ошибка") || lo.contains("deny")),
            "должен быть отказ без исполнения: {}", out.text
        );
        assert!(out.mono, "вывод команды моноширинный");
    }

    #[test]
    fn nl_text_goes_to_brain_when_present() {
        use crate::brain::{Brain, Message, ToolSpec};
        // мок-мозг: сразу финальный ответ без tool_calls
        struct MockBrain;
        impl Brain for MockBrain {
            fn chat(&self, _: &[Message], _: &[ToolSpec]) -> anyhow::Result<Message> {
                Ok(Message {
                    role: "assistant".into(),
                    content: "готово, босс".into(),
                    tool_name: None,
                    tool_call_id: None,
                    tool_calls: None,
                })
            }
        }
        let r = local_runner();
        let out = process_text(&r.handle(), Some(&MockBrain), "наведи порядок");
        assert_eq!(out.text, "готово, босс");
        assert!(!out.mono, "ответ мозга — проза, не моноширинно");
    }

    #[test]
    fn allowlist_owner_text_filters_non_owner() {
        let f = TelegramFront::new(
            MockApi,
            7,
            local_runner(),
            std::sync::Arc::new(PendingConfirms::new()),
        );
        assert!(f.owner_text(&msg(999, "list_dir /tmp")).is_none(), "чужой → игнор");
        assert_eq!(f.owner_text(&msg(7, "list_dir /tmp")), Some("list_dir /tmp"));
    }

    /// NL-роутинг через активный remote: мок McpCaller + мок мозг.
    /// Проверяем, что NL-текст (не команда) при активном remote уходит в agent-loop через хэндл.
    #[tokio::test]
    async fn nl_routes_to_remote_agent_loop_when_connected() {
        use crate::brain::{Brain, FunctionCall, Message as BrainMsg, ToolCall, ToolSpec};
        use crate::net::{McpCaller, McpToolRunner};
        use std::sync::atomic::{AtomicUsize, Ordering};

        // Мок McpCaller: эхо-вызов, close — ничего.
        struct EchoCaller;
        impl McpCaller for EchoCaller {
            async fn call(&self, name: String, _a: serde_json::Value) -> anyhow::Result<String> {
                Ok(format!("B:{name}"))
            }
            async fn close(self) {}
        }

        // Один spec list_dir
        let specs = vec![ToolSpec {
            kind: "function".into(),
            function: crate::brain::FunctionSpec {
                name: "list_dir".into(),
                description: "список директории".into(),
                parameters: serde_json::json!({"type": "object"}),
            },
        }];
        let runner = McpToolRunner::start(EchoCaller, specs);
        let slot: RemoteSlot = Arc::new(tokio::sync::Mutex::new(Some(runner)));

        // Мок-мозг: шаг 1 → tool_call list_dir, шаг 2 → финал "готово"
        struct TwoStepBrain {
            step: AtomicUsize,
        }
        impl Brain for TwoStepBrain {
            fn chat(&self, _msgs: &[BrainMsg], _tools: &[ToolSpec]) -> anyhow::Result<BrainMsg> {
                let s = self.step.fetch_add(1, Ordering::SeqCst);
                if s == 0 {
                    Ok(BrainMsg {
                        role: "assistant".into(),
                        content: String::new(),
                        tool_name: None,
                        tool_call_id: None,
                        tool_calls: Some(vec![ToolCall {
                            id: Some("c1".into()),
                            function: FunctionCall {
                                name: "list_dir".into(),
                                arguments: serde_json::json!({"path": "."}),
                            },
                        }]),
                    })
                } else {
                    Ok(BrainMsg {
                        role: "assistant".into(),
                        content: "готово".into(),
                        tool_name: None,
                        tool_call_id: None,
                        tool_calls: None,
                    })
                }
            }
        }

        let brain: Arc<dyn Brain> = Arc::new(TwoStepBrain { step: AtomicUsize::new(0) });
        let local = Arc::new(local_runner());

        // NL-текст (не команда) при активном remote + brain → должен вернуть результат agent-loop
        let reply = dispatch_message("покажи файлы", &local, Some(brain), &slot).await;
        // Мозг вернул "готово", либо в ответе есть B:list_dir (результат хэндла)
        assert!(
            reply.text.contains("готово") || reply.text.contains("B:list_dir"),
            "ожидали результат agent-loop, получили: {}", reply.text
        );
        assert!(!reply.mono, "NL-ответ — проза, не моноширинно");
    }
}
