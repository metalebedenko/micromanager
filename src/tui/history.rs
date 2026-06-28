//! Свёртка истории диалога TUI: ограничение роста персистентной `Vec<Message>`.
//! Чистое ядро (без I/O/сети) + шов `summarize_if_needed` (единственная точка вызова мозга).
//! При превышении лимита (гибрид: число сообщений / суммарный размер) старые ходы
//! ужимаются LLM-саммари; недавние сохраняются дословно; системный промпт — всегда.

use crate::brain::{Brain, Message};
use crate::tui::event::AppEvent;
use std::sync::mpsc::Sender;

/// Потолок числа сообщений в истории.
const MAX_MESSAGES: usize = 40;
/// Потолок суммарного размера `content` (символы, ≈ 4 симв/токен → ~6k токенов).
const MAX_CHARS: usize = 24_000;
/// Целевой максимум сообщений в сохраняемом «хвосте» (≈ половина MAX_MESSAGES).
const KEEP_TAIL_MSGS: usize = 20;
/// Целевой максимум символов в сохраняемом «хвосте» (≈ половина MAX_CHARS).
const KEEP_TAIL_CHARS: usize = 12_000;

/// Суммарный размер `content` всех сообщений (символы, не байты).
fn total_chars(messages: &[Message]) -> usize {
    messages.iter().map(|m| m.content.chars().count()).sum()
}

/// История превысила лимит (гибрид: по числу сообщений ИЛИ по размеру).
pub fn over_limit(messages: &[Message]) -> bool {
    messages.len() > MAX_MESSAGES || total_chars(messages) > MAX_CHARS
}

/// План свёртки: что ужать в саммари и какой «хвост» сохранить дословно.
pub struct TrimPlan {
    pub to_summarize: Vec<Message>,
    pub keep_tail: Vec<Message>,
}

/// Найти границу свёртки. Голова (`messages[0]` — system, и любые более ранние
/// summary-сообщения до первого user) НЕ входит в план: её пере-собирает
/// `apply_summary`/`truncate_fallback`. Хвост — недавние ходы в пределах бюджета
/// (символы И число сообщений), всегда минимум один ход; режется по `role=="user"`.
pub fn plan_trim(messages: &[Message]) -> TrimPlan {
    if messages.len() <= 1 {
        return TrimPlan {
            to_summarize: Vec::new(),
            keep_tail: Vec::new(),
        };
    }
    // body = всё после системного промпта (индекс 0).
    let body = &messages[1..];
    // Старты ходов внутри body — индексы user-сообщений.
    let turn_starts: Vec<usize> = body
        .iter()
        .enumerate()
        .filter(|(_, m)| m.role == "user")
        .map(|(i, _)| i)
        .collect();
    let Some(&last_start) = turn_starts.last() else {
        // Нет user-ходов в body — нечего сохранять дословно, всё в саммари.
        return TrimPlan {
            to_summarize: body.to_vec(),
            keep_tail: Vec::new(),
        };
    };
    // Хвост всегда включает последний ход целиком (даже если он один больше бюджета).
    let mut keep_start = last_start;
    let mut acc_chars: usize = body[keep_start..]
        .iter()
        .map(|m| m.content.chars().count())
        .sum();
    // Расширяем хвост более ранними ходами, пока влезаем в бюджет (символы И число).
    for &ts in turn_starts.iter().rev().skip(1) {
        let seg_chars: usize = body[ts..keep_start]
            .iter()
            .map(|m| m.content.chars().count())
            .sum();
        let tail_msgs = body.len() - ts;
        if acc_chars + seg_chars > KEEP_TAIL_CHARS || tail_msgs > KEEP_TAIL_MSGS {
            break;
        }
        acc_chars += seg_chars;
        keep_start = ts;
    }
    TrimPlan {
        to_summarize: body[..keep_start].to_vec(),
        keep_tail: body[keep_start..].to_vec(),
    }
}

/// Префикс summary-сообщения (по нему детектим и не накапливаем повторные свёртки).
pub const SUMMARY_MARKER: &str = "Краткое содержание предыдущего диалога:";

/// Инструкция мозгу-суммаризатору (вызывается с пустым списком тулов).
pub const SUMMARY_PROMPT: &str = "Ты сжимаешь историю диалога. Сократи приведённый ниже \
фрагмент в краткое резюме из 3-5 предложений на русском. Сохрани важные факты, имена, \
пути к файлам и результаты действий. Ничего не выдумывай и не добавляй от себя. \
Ответь только текстом резюме, без пояснений.";

/// Компактная текстовая сериализация старых ходов для подачи суммаризатору.
pub fn serialize_for_summary(to_summarize: &[Message]) -> String {
    to_summarize
        .iter()
        .map(|m| {
            let who = m.tool_name.as_deref().unwrap_or(&m.role);
            format!("[{who}] {}", m.content)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Собрать свёрнутую историю: системный промпт + одно summary-сообщение + недавний хвост.
/// Идемпотентно по числу summary: голова (старый summary) уходит в `to_summarize` плана и
/// заменяется новым (результат всегда содержит ровно одно summary-сообщение).
pub fn apply_summary(messages: &[Message], summary_text: &str) -> Vec<Message> {
    let plan = plan_trim(messages);
    let mut out = Vec::with_capacity(plan.keep_tail.len() + 2);
    if let Some(sys) = messages.first() {
        out.push(sys.clone());
    }
    out.push(Message::system(&format!(
        "{SUMMARY_MARKER} {}",
        summary_text.trim()
    )));
    out.extend(plan.keep_tail);
    out
}

/// Страховка без саммари: системный промпт + недавний хвост (старое выброшено целиком).
pub fn truncate_fallback(messages: &[Message]) -> Vec<Message> {
    let plan = plan_trim(messages);
    let mut out = Vec::with_capacity(plan.keep_tail.len() + 1);
    if let Some(sys) = messages.first() {
        out.push(sys.clone());
    }
    out.extend(plan.keep_tail);
    out
}

/// Свернуть историю, если она превысила лимит. Единственная точка вызова мозга.
/// Успешное саммари → `apply_summary`; ошибка/пустой ответ → `truncate_fallback`.
/// Возвращает `true`, если свёртка произошла (история изменена). При `over_limit`,
/// но пустом `to_summarize` (один большой недавний ход) — no-op (`false`).
pub fn summarize_if_needed(
    brain: &dyn Brain,
    messages: &mut Vec<Message>,
    tx: &Sender<AppEvent>,
) -> bool {
    if !over_limit(messages) {
        return false;
    }
    let plan = plan_trim(messages);
    if plan.to_summarize.is_empty() {
        return false; // нечего сворачивать (хвост сам больше бюджета)
    }
    let n = plan.to_summarize.len();
    let text = serialize_for_summary(&plan.to_summarize);
    let prompt = [Message::system(SUMMARY_PROMPT), Message::user(&text)];
    match brain.chat(&prompt, &[]) {
        Ok(reply) if !reply.content.trim().is_empty() => {
            *messages = apply_summary(messages, &reply.content);
            let _ = tx.send(AppEvent::Activity(format!(
                "⋯ свёрнуто {n} старых сообщений в саммари"
            )));
        }
        _ => {
            *messages = truncate_fallback(messages);
            let _ = tx.send(AppEvent::Activity(format!(
                "⋯ обрезано {n} старых сообщений (саммари недоступно)"
            )));
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*; // тащит родительские `use` (Message, Brain, AppEvent и пр.)
    use crate::brain::ToolSpec; // Brain/Message уже из super::*
    use std::sync::mpsc;

    // Мозг-суммаризатор: всегда возвращает непустое резюме.
    struct SummBrain;
    impl Brain for SummBrain {
        fn chat(&self, _m: &[Message], _t: &[ToolSpec]) -> anyhow::Result<Message> {
            Ok(Message::system("СЖАТО"))
        }
    }
    // Мозг, падающий на chat (Ollama лёг / таймаут).
    struct DeadBrain;
    impl Brain for DeadBrain {
        fn chat(&self, _m: &[Message], _t: &[ToolSpec]) -> anyhow::Result<Message> {
            anyhow::bail!("brain down")
        }
    }
    // Мозг, вернувший пустой content (трактуем как неудачу).
    struct EmptyBrain;
    impl Brain for EmptyBrain {
        fn chat(&self, _m: &[Message], _t: &[ToolSpec]) -> anyhow::Result<Message> {
            Ok(Message::system("   "))
        }
    }

    #[test]
    fn summarize_applies_and_labels_on_success() {
        let mut v = long_history();
        let before = v.len();
        let (tx, rx) = mpsc::channel::<AppEvent>();
        let did = summarize_if_needed(&SummBrain, &mut v, &tx);
        assert!(did);
        assert!(v.len() < before);
        assert!(v.iter().any(|m| m.content.starts_with(SUMMARY_MARKER)));
        match rx.try_recv().unwrap() {
            AppEvent::Activity(s) => assert!(s.contains("свёрнуто")),
            _ => panic!("ожидалась Activity-метка"),
        }
    }

    #[test]
    fn summarize_falls_back_on_brain_error() {
        let mut v = long_history();
        let before = v.len();
        let (tx, rx) = mpsc::channel::<AppEvent>();
        let did = summarize_if_needed(&DeadBrain, &mut v, &tx);
        assert!(did);
        assert!(v.len() < before);
        assert!(v.iter().all(|m| !m.content.starts_with(SUMMARY_MARKER)));
        match rx.try_recv().unwrap() {
            AppEvent::Activity(s) => assert!(s.contains("обрезано")),
            _ => panic!("ожидалась Activity-метка"),
        }
    }

    #[test]
    fn summarize_empty_reply_falls_back() {
        let mut v = long_history();
        let (tx, _rx) = mpsc::channel::<AppEvent>();
        summarize_if_needed(&EmptyBrain, &mut v, &tx);
        assert!(v.iter().all(|m| !m.content.starts_with(SUMMARY_MARKER)));
    }

    #[test]
    fn summarize_noop_under_limit() {
        let mut v = vec![
            Message::system("sys"),
            Message::user("вопрос"),
            assistant("ответ"),
        ];
        let snapshot = v.clone();
        let (tx, rx) = mpsc::channel::<AppEvent>();
        let did = summarize_if_needed(&SummBrain, &mut v, &tx);
        assert!(!did);
        assert_eq!(v.len(), snapshot.len());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn summarize_noop_when_nothing_older_than_tail() {
        // Один гигантский недавний ход больше бюджета → over_limit true, но to_summarize пуст.
        let mut v = vec![Message::system("sys")];
        v.push(Message::user(&"x".repeat(MAX_CHARS + 1)));
        v.push(assistant("ок"));
        let (tx, rx) = mpsc::channel::<AppEvent>();
        let did = summarize_if_needed(&SummBrain, &mut v, &tx);
        assert!(!did, "нечего сворачивать — no-op");
        assert!(rx.try_recv().is_err());
    }

    // Хелпер: история из system + n чередующихся user/assistant коротких сообщений.
    fn history(n: usize) -> Vec<Message> {
        let mut v = vec![Message::system("sys")];
        for i in 0..n {
            if i % 2 == 0 {
                v.push(Message::user(&format!("u{i}")));
            } else {
                v.push(assistant(&format!("a{i}")));
            }
        }
        v
    }

    fn assistant(text: &str) -> Message {
        Message {
            role: "assistant".into(),
            content: text.into(),
            tool_name: None,
            tool_call_id: None,
            tool_calls: None,
        }
    }

    fn tool_msg(name: &str, content: &str) -> Message {
        Message::tool(name, content)
    }

    #[test]
    fn plan_keeps_system_out_of_turns_and_tail_starts_with_user() {
        // system + 30 коротких сообщений (user/assistant) → по счёту вместит не все
        let mut v = vec![Message::system("sys")];
        for i in 0..30 {
            if i % 2 == 0 {
                v.push(Message::user(&format!("u{i}")));
            } else {
                v.push(assistant(&format!("a{i}")));
            }
        }
        let plan = plan_trim(&v);
        // хвост начинается с user-сообщения (инвариант: нет сиротских tool/assistant)
        assert_eq!(plan.keep_tail.first().map(|m| m.role.as_str()), Some("user"));
        // что-то ушло в саммари (история длинная)
        assert!(!plan.to_summarize.is_empty());
        // system НЕ попал ни в to_summarize, ни в keep_tail (он — отдельная голова)
        assert!(plan.to_summarize.iter().all(|m| m.content != "sys"));
        assert!(plan.keep_tail.iter().all(|m| m.content != "sys"));
    }

    #[test]
    fn plan_does_not_orphan_tool_message() {
        // ход: user -> assistant -> tool. Граница не должна оставить tool без user-хода.
        let mut v = vec![Message::system("sys")];
        for i in 0..15 {
            v.push(Message::user(&format!("u{i}")));
            v.push(assistant(&format!("a{i}")));
            v.push(tool_msg("list_dir", &format!("r{i}")));
        }
        let plan = plan_trim(&v);
        assert_eq!(plan.keep_tail.first().map(|m| m.role.as_str()), Some("user"));
        assert_ne!(plan.keep_tail.first().map(|m| m.role.as_str()), Some("tool"));
    }

    #[test]
    fn plan_single_huge_turn_kept_whole_summarize_empty() {
        // system + один большой ход (user длиннее бюджета)
        let mut v = vec![Message::system("sys")];
        v.push(Message::user(&"x".repeat(KEEP_TAIL_CHARS + 5_000)));
        v.push(assistant("ответ"));
        let plan = plan_trim(&v);
        // нечего сворачивать (один ход), хвост = этот ход целиком
        assert!(plan.to_summarize.is_empty());
        assert_eq!(plan.keep_tail.len(), 2);
    }

    #[test]
    fn plan_caps_tail_by_message_count() {
        // много коротких user-ходов (размер мал, но число велико) → хвост ограничен по числу
        let mut v = vec![Message::system("sys")];
        for i in 0..60 {
            v.push(Message::user(&format!("u{i}")));
        }
        let plan = plan_trim(&v);
        assert!(
            plan.keep_tail.len() <= KEEP_TAIL_MSGS,
            "хвост {} > {KEEP_TAIL_MSGS}",
            plan.keep_tail.len()
        );
        assert!(!plan.to_summarize.is_empty());
    }

    fn long_history() -> Vec<Message> {
        let mut v = vec![Message::system("sys")];
        for i in 0..40 {
            v.push(Message::user(&format!("u{i} {}", "x".repeat(400))));
            v.push(assistant(&format!("a{i}")));
        }
        v
    }

    #[test]
    fn apply_summary_structure_and_role() {
        let v = long_history();
        let out = apply_summary(&v, "  резюме диалога  ");
        // [system, system(summary), ...keep_tail]
        assert_eq!(out[0].role, "system");
        assert_eq!(out[0].content, "sys");
        assert_eq!(out[1].role, "system");
        assert!(out[1].content.starts_with(SUMMARY_MARKER));
        assert!(out[1].content.contains("резюме диалога"));
        // хвост начинается с user (третий элемент)
        assert_eq!(out[2].role, "user");
        // результат короче исходника
        assert!(out.len() < v.len());
    }

    #[test]
    fn apply_summary_idempotent_no_accumulation() {
        let v = long_history();
        let once = apply_summary(&v, "резюме-1");
        let twice = apply_summary(&once, "резюме-2");
        // ровно одно summary-сообщение (по маркеру), не два
        let summaries = twice
            .iter()
            .filter(|m| m.content.starts_with(SUMMARY_MARKER))
            .count();
        assert_eq!(summaries, 1, "summary не должен накапливаться");
        assert_eq!(twice[0].content, "sys");
    }

    #[test]
    fn truncate_fallback_structure_no_summary() {
        let v = long_history();
        let out = truncate_fallback(&v);
        assert_eq!(out[0].content, "sys");
        // нет summary-сообщения
        assert!(out.iter().all(|m| !m.content.starts_with(SUMMARY_MARKER)));
        // первый после system — user
        assert_eq!(out[1].role, "user");
        assert!(out.len() < v.len());
    }

    #[test]
    fn serialize_contains_roles_and_content() {
        let msgs = vec![Message::user("привет мир"), assistant("здравствуй")];
        let s = serialize_for_summary(&msgs);
        assert!(s.contains("привет мир"));
        assert!(s.contains("здравствуй"));
        assert!(s.contains("user"));
        assert!(!s.is_empty());
    }

    #[test]
    fn summary_prompt_nonempty() {
        assert!(!SUMMARY_PROMPT.trim().is_empty());
    }

    #[test]
    fn under_limit_is_false() {
        assert!(!over_limit(&history(4)));
    }

    #[test]
    fn over_message_count_is_true() {
        // 1 system + 50 сообщений = 51 > MAX_MESSAGES(40)
        assert!(over_limit(&history(50)));
    }

    #[test]
    fn over_chars_is_true() {
        // мало сообщений, но огромный content одного из них
        let mut v = vec![Message::system("sys")];
        v.push(Message::user(&"x".repeat(MAX_CHARS + 1)));
        assert!(over_limit(&v));
    }
}
