//! Роутер мозга: надёжность. `primary` (обычно local-Ollama) основной,
//! `fallback` (cloud) — автоматический резерв. Посессионный sticky: один раз ушли
//! на fallback — остаёмся до `reset()` (новый разговор).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use super::{Brain, Message, ToolSpec};

#[derive(Clone, Copy, PartialEq, Debug)]
enum Active {
    Primary,
    Fallback,
}

/// Обёртка-`Brain`: маршрутизирует ход на primary, при его недоступности/ошибке —
/// на fallback (sticky на сессию). Прозрачна для агент-цикла и всех фронтов.
pub struct RoutingBrain {
    primary: Box<dyn Brain>,
    fallback: Box<dyn Brain>,
    active: Mutex<Active>,
    /// Сделан ли ленивый health-check primary (один раз перед первым ходом).
    checked: AtomicBool,
}

impl RoutingBrain {
    pub fn new(primary: Box<dyn Brain>, fallback: Box<dyn Brain>) -> Self {
        Self {
            primary,
            fallback,
            active: Mutex::new(Active::Primary),
            checked: AtomicBool::new(false),
        }
    }

    /// Сбросить sticky-состояние к primary (TUI `Ctrl-L` = новый разговор → снова
    /// пере-проверяем local). Идемпотентно.
    pub fn reset(&self) {
        *self.active.lock().unwrap() = Active::Primary;
        self.checked.store(false, Ordering::SeqCst);
    }
}

impl Brain for RoutingBrain {
    fn chat(&self, messages: &[Message], tools: &[ToolSpec]) -> anyhow::Result<Message> {
        // Инвариант: `chat` зовётся последовательно (агент-цикл — один ход за раз;
        // TUI к тому же строит RoutingBrain заново на каждое сообщение и не шарит его
        // между потоками). `active`/`checked` — раздельные lock/atomic; при гипотетическом
        // параллельном вызове это не нарушает безопасность (худшее — лишняя проба primary).
        // sticky: уже ушли на fallback — идём прямо туда, primary не трогаем.
        if *self.active.lock().unwrap() == Active::Fallback {
            return self.fallback.chat(messages, tools);
        }
        // Ленивый health-check primary перед первым ходом (ровно один раз).
        // swap гарантирует однократность; health() вычисляется только если ещё не проверяли.
        if !self.checked.swap(true, Ordering::SeqCst) && !self.primary.health() {
            *self.active.lock().unwrap() = Active::Fallback;
            return self.fallback.chat(messages, tools);
        }
        // primary прошёл health — пробуем ход. Ошибка → sticky-fallback + повтор на нём.
        match self.primary.chat(messages, tools) {
            Ok(reply) => Ok(reply),
            Err(_) => {
                *self.active.lock().unwrap() = Active::Fallback;
                self.fallback.chat(messages, tools)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    struct MockBrain {
        name: &'static str,
        healthy: bool,
        fail_chat: bool,
        chat_calls: Arc<AtomicUsize>,
        health_calls: Arc<AtomicUsize>,
    }
    impl Brain for MockBrain {
        fn chat(&self, _m: &[Message], _t: &[ToolSpec]) -> anyhow::Result<Message> {
            self.chat_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_chat {
                anyhow::bail!("{} chat fail", self.name);
            }
            Ok(Message::system(self.name))
        }
        fn health(&self) -> bool {
            self.health_calls.fetch_add(1, Ordering::SeqCst);
            self.healthy
        }
    }

    /// Возвращает (мозг, счётчик chat, счётчик health).
    fn mock(
        name: &'static str,
        healthy: bool,
        fail_chat: bool,
    ) -> (Box<dyn Brain>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let chat = Arc::new(AtomicUsize::new(0));
        let health = Arc::new(AtomicUsize::new(0));
        let b = Box::new(MockBrain {
            name,
            healthy,
            fail_chat,
            chat_calls: chat.clone(),
            health_calls: health.clone(),
        });
        (b, chat, health)
    }

    fn load(a: &Arc<AtomicUsize>) -> usize {
        a.load(Ordering::SeqCst)
    }

    // (a) primary жив → ход идёт на primary, fallback не трогается.
    #[test]
    fn primary_alive_routes_to_primary() {
        let (p, pc, _ph) = mock("P", true, false);
        let (f, fc, _fh) = mock("F", true, false);
        let r = RoutingBrain::new(p, f);
        let reply = r.chat(&[], &[]).unwrap();
        assert_eq!(reply.content, "P");
        assert_eq!(load(&pc), 1);
        assert_eq!(load(&fc), 0, "fallback не должен вызываться");
    }

    // (b) primary недоступен на старте (health=false) → сразу fallback, primary.chat не зван.
    #[test]
    fn primary_unhealthy_routes_straight_to_fallback() {
        let (p, pc, ph) = mock("P", false, false);
        let (f, fc, _fh) = mock("F", true, false);
        let r = RoutingBrain::new(p, f);
        let reply = r.chat(&[], &[]).unwrap();
        assert_eq!(reply.content, "F");
        assert_eq!(load(&ph), 1, "health primary проверен");
        assert_eq!(load(&pc), 0, "primary.chat НЕ зван при health=false");
        assert_eq!(load(&fc), 1);
    }

    // (c) primary прошёл health, но chat упал → повтор на fallback + sticky на сессию.
    #[test]
    fn primary_chat_error_falls_back_and_sticks() {
        let (p, pc, _ph) = mock("P", true, true); // health ok, chat fail
        let (f, fc, _fh) = mock("F", true, false);
        let r = RoutingBrain::new(p, f);

        let r1 = r.chat(&[], &[]).unwrap();
        assert_eq!(r1.content, "F");
        assert_eq!(load(&pc), 1, "primary.chat пробован один раз");
        assert_eq!(load(&fc), 1);

        // второй ход — sticky: сразу fallback, primary больше не трогаем.
        let r2 = r.chat(&[], &[]).unwrap();
        assert_eq!(r2.content, "F");
        assert_eq!(load(&pc), 1, "primary.chat НЕ зван повторно (sticky)");
        assert_eq!(load(&fc), 2);
    }

    // (d) оба упали → Err наверх, без паники.
    #[test]
    fn both_fail_returns_error() {
        let (p, _pc, _ph) = mock("P", true, true);
        let (f, _fc, _fh) = mock("F", true, true);
        let r = RoutingBrain::new(p, f);
        assert!(r.chat(&[], &[]).is_err());
    }

    // (e) reset() → следующий ход снова делает health-check primary.
    #[test]
    fn reset_rechecks_primary_health() {
        let (p, _pc, ph) = mock("P", false, false); // недоступен → уйдём на fallback
        let (f, _fc, _fh) = mock("F", true, false);
        let r = RoutingBrain::new(p, f);

        r.chat(&[], &[]).unwrap(); // health #1 → fallback
        assert_eq!(load(&ph), 1);

        r.reset();
        r.chat(&[], &[]).unwrap(); // active=Primary, checked=false → health #2
        assert_eq!(load(&ph), 2, "после reset primary пере-проверяется");
    }
}
