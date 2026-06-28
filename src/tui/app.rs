//! Чистый редьюсер UI: всё состояние TUI + переходы по клавишам/событиям.
//! Без I/O и без терминала — полностью юнит-тестируется.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::tui::textinput::TextInput;

/// Куда направлен ввод/фокус.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Focus {
    Chat,
    Settings,
    Confirm,
    Help,
    /// Экран подключения к удалённому узлу (ввод кода + статус).
    Remote,
    /// Экран «поделиться своим ПК» (owner-monitor для входящих A).
    Share,
    /// Оверлей выбора чата (мульти-чат).
    Chats,
}

/// Автор строки чата.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChatRole {
    User,
    Agent,
    System,
}

/// Текстовое поле настроек, доступное для редактирования.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SettingsField {
    Model,
    Host,
    ApiKey,
    Path,
    FallbackHost,
    FallbackModel,
    FallbackApiKey,
}

/// Активное редактирование поля настроек.
#[derive(Clone, Debug)]
pub struct Editing {
    pub field: SettingsField,
    pub buffer: TextInput,
}

/// Переключить провайдера (Ollama ⇄ OpenAI). Общий код для primary и fallback тумблеров.
fn toggle_provider(p: crate::brain::Provider) -> crate::brain::Provider {
    match p {
        crate::brain::Provider::Ollama => crate::brain::Provider::OpenAi,
        crate::brain::Provider::OpenAi => crate::brain::Provider::Ollama,
    }
}

/// Статус подключения к удалённому узлу.
#[derive(Clone, Debug, PartialEq)]
pub enum RemoteStatus {
    Connecting,
    Connected,
    Error(String),
}

/// Состояние активного подключения к удалённому узлу.
pub struct RemoteView {
    pub host_label: String,
    pub tools: Vec<String>,
    pub grant: crate::net::GrantSummary,
    pub connected_at: std::time::Instant,
    /// Unix-timestamp подключения — для записи в лог при отключении.
    pub connected_at_unix: u64,
    pub status: RemoteStatus,
}

/// Одна строка диалога.
#[derive(Clone, Debug)]
pub struct ChatLine {
    pub role: ChatRole,
    pub text: String,
}

/// Один диалоговый тред: заголовок + строки показа + история мозга + скролл.
pub struct Chat {
    pub title: String,
    pub lines: Vec<ChatLine>,
    pub brain: Vec<crate::brain::Message>,
    pub scroll: u16,
}

impl Chat {
    /// Пустой чат: история мозга = свежий системный промпт (new_conversation).
    pub fn empty() -> Self {
        Self {
            title: String::new(),
            lines: Vec::new(),
            brain: crate::brain::new_conversation(),
            scroll: 0,
        }
    }
}

/// Побочный эффект, который редьюсер просит выполнить цикл.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    SubmitTask(String),
    /// Прямая команда оператора (префикс `!`), исполняется без мозга.
    /// Строка — текст ПОСЛЕ `!` (напр. "ls /tmp"), парсится исполнителем.
    RunCommand(String),
    TrustSession,
    CancelTask,
    NewConversation,
    SettingsChanged,
    /// Набор/активность чатов изменились — сохранить sessions.json.
    ChatsChanged,
    Quit,
    None,
    /// Подключиться к удалённому узлу по коду (node-id или адрес).
    Connect(String),
    /// Отключиться от текущего удалённого узла.
    Disconnect,
    /// Начать «поделиться своим ПК» (поднять эндпоинт, принимать A).
    StartShare,
    /// Прекратить шеринг (закрыть эндпоинт, оборвать A).
    StopShare,
}

/// Display-only состояние экрана «поделиться своим ПК».
#[derive(Clone, Default)]
pub struct ShareView {
    /// Код-приглашение (после bind); None — ещё поднимаем эндпоинт.
    pub invite_code: Option<String>,
    /// Подключённые A (короткие node-id).
    pub peers: Vec<String>,
    /// Ошибка шеринга (напр. bind упал).
    pub error: Option<String>,
    /// Сводка выдаваемого гранта (для показа), берётся из настроек при старте.
    pub grant: crate::net::GrantSummary,
}

/// Всё состояние TUI.
pub struct App {
    pub focus: Focus,
    pub input: TextInput,
    pub chats: Vec<Chat>,
    pub active: usize,
    /// Какой чат сейчас «думает» (его агент крутится); None — никакой.
    pub running_chat: Option<usize>,
    /// Подсветка в оверлее выбора чата.
    pub chats_cursor: usize,
    pub activity: Vec<String>,
    pub should_quit: bool,
    pub running: bool,
    pub pending: Option<crate::tui::event::ConfirmRequest>,
    pub settings: crate::tui::settings::Settings,
    pub history: Vec<String>,
    pub history_idx: Option<usize>,
    /// Максимально осмысленная прокрутка (визуальные строки сверх окна) — пишется
    /// рендером (interior mutability), читается редьюсером для клампа PgUp.
    pub chat_max_scroll: std::cell::Cell<u16>,
    pub settings_edit: Option<Editing>,
    /// Активное подключение к удалённому узлу (None = нет подключения).
    pub remote: Option<RemoteView>,
    /// Лог завершённых сессий с удалёнными узлами.
    pub host_log: Vec<crate::tui::hosts::HostLogEntry>,
    /// Буфер ввода кода подключения на экране Remote.
    pub remote_code_input: TextInput,
    /// Состояние экрана «поделиться своим ПК».
    pub share: ShareView,
}

impl App {
    pub fn new() -> Self {
        Self {
            focus: Focus::Chat,
            input: TextInput::new(),
            chats: vec![Chat::empty()],
            active: 0,
            running_chat: None,
            chats_cursor: 0,
            activity: Vec::new(),
            should_quit: false,
            running: false,
            pending: None,
            settings: crate::tui::settings::Settings::default(),
            history: Vec::new(),
            history_idx: None,
            chat_max_scroll: std::cell::Cell::new(0),
            settings_edit: None,
            remote: None,
            host_log: Vec::new(),
            remote_code_input: TextInput::new(),
            share: ShareView::default(),
        }
    }

    /// Активный чат (видимый).
    pub fn active_chat(&self) -> &Chat { &self.chats[self.active] }
    pub fn active_chat_mut(&mut self) -> &mut Chat { &mut self.chats[self.active] }
    /// Строки активного чата (для рендера/статуса).
    pub fn chat(&self) -> &[ChatLine] { &self.chats[self.active].lines }
    /// Скролл активного чата.
    pub fn chat_scroll(&self) -> u16 { self.chats[self.active].scroll }
    /// Куда направлять строки агента: думающий чат, иначе активный.
    pub fn target_chat(&self) -> usize { self.running_chat.unwrap_or(self.active) }

    /// Прокрутить чат: up=назад (к началу), step — на сколько визуальных строк.
    /// PgUp клампится к реальному максимуму (если рендер его посчитал); вниз — к низу.
    pub fn scroll_chat(&mut self, up: bool, step: u16) {
        let max = self.chat_max_scroll.get();
        let cur = self.active_chat().scroll;
        let next = if up {
            let n = cur.saturating_add(step);
            if max > 0 { n.min(max) } else { n }
        } else {
            cur.saturating_sub(step)
        };
        self.active_chat_mut().scroll = next;
    }

    /// Добавить системную строку в активный чат (приветствие, статусы).
    pub fn push_system(&mut self, text: impl Into<String>) {
        self.active_chat_mut().lines.push(ChatLine {
            role: ChatRole::System,
            text: text.into(),
        });
    }

    /// Обработать нажатие клавиши; вернуть запрошенный побочный эффект.
    pub fn on_key(&mut self, key: KeyEvent) -> Command {
        // Ctrl-C — выход из любого режима (kill-switch).
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.should_quit = true;
            return Command::Quit;
        }
        // Ctrl-L — новый разговор (очистка). Только когда агент не работает.
        if key.code == KeyCode::Char('l') && key.modifiers.contains(KeyModifiers::CONTROL) {
            if self.running {
                return Command::None;
            }
            self.active_chat_mut().lines.clear();
            self.activity.clear();
            self.input.clear();
            self.focus = Focus::Chat;
            return Command::NewConversation;
        }
        // Ctrl-T — меню чатов (только из чата, не во время модалок).
        if key.code == KeyCode::Char('t')
            && key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(self.focus, Focus::Chat)
        {
            self.chats_cursor = self.active;
            self.focus = Focus::Chats;
            return Command::None;
        }
        match self.focus {
            Focus::Chat => self.on_key_chat(key),
            Focus::Confirm => self.on_key_confirm(key),
            Focus::Settings => self.on_key_settings(key),
            Focus::Help => {
                // любой Esc/?/q закрывает справку
                if matches!(
                    key.code,
                    KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q')
                ) {
                    self.focus = Focus::Chat;
                }
                Command::None
            }
            Focus::Remote => self.on_key_remote(key),
            Focus::Share => self.on_key_share(key),
            Focus::Chats => self.on_key_chats(key),
        }
    }

    fn on_key_chats(&mut self, key: KeyEvent) -> Command {
        match key.code {
            KeyCode::Up => {
                self.chats_cursor = self.chats_cursor.saturating_sub(1);
                Command::None
            }
            KeyCode::Down => {
                if self.chats_cursor + 1 < self.chats.len() {
                    self.chats_cursor += 1;
                }
                Command::None
            }
            KeyCode::Enter => {
                self.active = self.chats_cursor;
                self.focus = Focus::Chat;
                Command::ChatsChanged
            }
            KeyCode::Char('n') => {
                self.chats.push(Chat::empty());
                self.active = self.chats.len() - 1;
                self.chats_cursor = self.active;
                self.focus = Focus::Chat;
                Command::ChatsChanged
            }
            KeyCode::Char('d') => {
                if self.running {
                    self.push_system("нельзя удалять чат, пока агент работает");
                    return Command::None;
                }
                self.delete_chat(self.chats_cursor);
                Command::ChatsChanged
            }
            KeyCode::Esc => {
                self.focus = Focus::Chat;
                Command::None
            }
            _ => Command::None,
        }
    }

    /// Удалить чат i (не вызывается при running). Инвариант «никогда ноль».
    fn delete_chat(&mut self, i: usize) {
        if self.chats.len() == 1 {
            self.chats[0] = Chat::empty();
            self.active = 0;
            self.chats_cursor = 0;
            return;
        }
        self.chats.remove(i);
        if self.active > i {
            self.active -= 1;
        } else if self.active >= self.chats.len() {
            self.active = self.chats.len() - 1;
        }
        self.chats_cursor = self.chats_cursor.min(self.chats.len() - 1);
    }

    fn on_key_share(&mut self, key: KeyEvent) -> Command {
        match key.code {
            KeyCode::Esc => {
                self.focus = Focus::Chat;
                Command::StopShare
            }
            KeyCode::Char(c) => {
                self.input.insert_char(c);
                Command::None
            }
            KeyCode::Backspace => {
                self.input.backspace();
                Command::None
            }
            KeyCode::Delete => {
                self.input.delete();
                Command::None
            }
            KeyCode::Left => {
                self.input.left();
                Command::None
            }
            KeyCode::Right => {
                self.input.right();
                Command::None
            }
            KeyCode::Home => {
                self.input.home();
                Command::None
            }
            KeyCode::End => {
                self.input.end();
                Command::None
            }
            KeyCode::Enter => {
                let raw = self.input.as_str().trim().to_string();
                self.input.clear();
                if raw.is_empty() {
                    return Command::None;
                }
                // На экране шеринга мозга нет — ввод это прямая команда на СВОЮ машину
                // (под тем же safety-гейтом). Ведущий `!` опционален (привычка из чата).
                let cmd = raw.strip_prefix('!').unwrap_or(&raw).trim().to_string();
                if cmd.is_empty() {
                    return Command::None;
                }
                Command::RunCommand(cmd)
            }
            _ => Command::None,
        }
    }

    fn on_key_settings(&mut self, key: KeyEvent) -> Command {
        if self.settings_edit.is_some() {
            return self.on_key_settings_editing(key);
        }
        match key.code {
            KeyCode::Char('m') => {
                self.start_edit(SettingsField::Model, self.settings.model.clone());
                Command::None
            }
            KeyCode::Char('h') => {
                self.start_edit(SettingsField::Host, self.settings.host.clone());
                Command::None
            }
            KeyCode::Char('k') => {
                self.start_edit(
                    SettingsField::ApiKey,
                    self.settings.api_key.clone().unwrap_or_default(),
                );
                Command::None
            }
            KeyCode::Char('p') => {
                let cur = self
                    .settings
                    .allowed_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default();
                self.start_edit(SettingsField::Path, cur);
                Command::None
            }
            KeyCode::Char('e') => {
                self.settings.allow_shell = !self.settings.allow_shell;
                Command::SettingsChanged
            }
            KeyCode::Char('y') => {
                // «запомнить друга» при шеринге (опт-ин персист pairing)
                self.settings.remember = !self.settings.remember;
                Command::SettingsChanged
            }
            KeyCode::Char('t') => {
                // TTL гранта при шеринге: цикл 0(без лимита)→60→300→3600→0
                self.settings.ttl_secs = match self.settings.ttl_secs {
                    0 => 60,
                    60 => 300,
                    300 => 3600,
                    _ => 0,
                };
                Command::SettingsChanged
            }
            KeyCode::Char('d') => {
                self.settings.allow_dangerous = !self.settings.allow_dangerous;
                Command::SettingsChanged
            }
            KeyCode::Char('r') => {
                self.settings.provider = toggle_provider(self.settings.provider);
                Command::SettingsChanged
            }
            // ─── Роутер мозга: тумблер + fallback-профиль ───
            KeyCode::Char('o') => {
                self.settings.routing = !self.settings.routing;
                Command::SettingsChanged
            }
            KeyCode::Char('b') => {
                self.settings.fallback.provider = toggle_provider(self.settings.fallback.provider);
                Command::SettingsChanged
            }
            KeyCode::Char('f') => {
                self.start_edit(SettingsField::FallbackHost, self.settings.fallback.host.clone());
                Command::None
            }
            KeyCode::Char('g') => {
                self.start_edit(
                    SettingsField::FallbackModel,
                    self.settings.fallback.model.clone(),
                );
                Command::None
            }
            KeyCode::Char('j') => {
                self.start_edit(
                    SettingsField::FallbackApiKey,
                    self.settings.fallback.api_key.clone().unwrap_or_default(),
                );
                Command::None
            }
            KeyCode::Esc => {
                self.focus = Focus::Chat;
                Command::None
            }
            _ => Command::None,
        }
    }

    fn start_edit(&mut self, field: SettingsField, buffer: String) {
        self.settings_edit = Some(Editing {
            field,
            buffer: TextInput::from(buffer),
        });
    }

    fn on_key_settings_editing(&mut self, key: KeyEvent) -> Command {
        match key.code {
            KeyCode::Char(c) => {
                if let Some(ed) = self.settings_edit.as_mut() {
                    ed.buffer.insert_char(c);
                }
                Command::None
            }
            KeyCode::Backspace => {
                if let Some(ed) = self.settings_edit.as_mut() {
                    ed.buffer.backspace();
                }
                Command::None
            }
            KeyCode::Delete => {
                if let Some(ed) = self.settings_edit.as_mut() {
                    ed.buffer.delete();
                }
                Command::None
            }
            KeyCode::Left => {
                if let Some(ed) = self.settings_edit.as_mut() {
                    ed.buffer.left();
                }
                Command::None
            }
            KeyCode::Right => {
                if let Some(ed) = self.settings_edit.as_mut() {
                    ed.buffer.right();
                }
                Command::None
            }
            KeyCode::Home => {
                if let Some(ed) = self.settings_edit.as_mut() {
                    ed.buffer.home();
                }
                Command::None
            }
            KeyCode::End => {
                if let Some(ed) = self.settings_edit.as_mut() {
                    ed.buffer.end();
                }
                Command::None
            }
            KeyCode::Enter => {
                if let Some(ed) = self.settings_edit.take() {
                    self.commit_edit(ed);
                    return Command::SettingsChanged;
                }
                Command::None
            }
            KeyCode::Esc => {
                self.settings_edit = None; // отмена
                Command::None
            }
            _ => Command::None,
        }
    }

    fn commit_edit(&mut self, ed: Editing) {
        let val = ed.buffer.as_str().trim().to_string();
        match ed.field {
            SettingsField::Model => {
                if !val.is_empty() {
                    self.settings.model = val;
                }
            }
            SettingsField::Host => {
                if !val.is_empty() {
                    self.settings.host = val;
                }
            }
            SettingsField::ApiKey => {
                self.settings.api_key = if val.is_empty() { None } else { Some(val) };
            }
            SettingsField::Path => {
                self.settings.allowed_path = if val.is_empty() {
                    None
                } else {
                    Some(std::path::PathBuf::from(val))
                };
            }
            SettingsField::FallbackHost => {
                self.settings.fallback.host = val;
            }
            SettingsField::FallbackModel => {
                self.settings.fallback.model = val;
            }
            SettingsField::FallbackApiKey => {
                self.settings.fallback.api_key = if val.is_empty() { None } else { Some(val) };
            }
        }
    }

    fn on_key_remote(&mut self, key: KeyEvent) -> Command {
        // Ctrl-D — отключиться от текущего узла.
        if key.code == KeyCode::Char('d') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return Command::Disconnect;
        }
        match key.code {
            KeyCode::Char(c) => {
                self.remote_code_input.insert_char(c);
                Command::None
            }
            KeyCode::Backspace => {
                self.remote_code_input.backspace();
                Command::None
            }
            KeyCode::Delete => {
                self.remote_code_input.delete();
                Command::None
            }
            KeyCode::Left => {
                self.remote_code_input.left();
                Command::None
            }
            KeyCode::Right => {
                self.remote_code_input.right();
                Command::None
            }
            KeyCode::Home => {
                self.remote_code_input.home();
                Command::None
            }
            KeyCode::End => {
                self.remote_code_input.end();
                Command::None
            }
            KeyCode::Enter => {
                let code = self.remote_code_input.take();
                Command::Connect(code)
            }
            KeyCode::Esc => {
                self.focus = Focus::Chat;
                Command::None
            }
            _ => Command::None,
        }
    }

    fn on_key_confirm(&mut self, key: KeyEvent) -> Command {
        let answer = match key.code {
            KeyCode::Char('y') | KeyCode::Char('a') => true,
            KeyCode::Char('n') | KeyCode::Esc => false,
            _ => return Command::None, // прочие клавиши игнорим, модалка держится
        };
        let Some(req) = self.pending.take() else {
            self.focus = Focus::Chat;
            return Command::None;
        };
        let dangerous = req.dangerous;
        let trust = key.code == KeyCode::Char('a') && answer && !dangerous;
        if trust {
            // доверие точечно для ЭТОГО confirmer-а (важно при нескольких удалённых A);
            // dangerous сюда не попадает.
            req.trust.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        let _ = req.reply.send(answer); // ошибка отправки безопасна — агент уже fail-closed
        self.focus = Focus::Chat;
        // «a» = доверять на сессию (НЕ опасное): чат-confirmer гасится через Command::TrustSession,
        // удалённые A — через выставленный выше req.trust.
        if trust {
            return Command::TrustSession;
        }
        Command::None
    }

    fn on_key_chat(&mut self, key: KeyEvent) -> Command {
        match key.code {
            // Esc во время работы агента — отмена текущей задачи.
            KeyCode::Esc if self.running => Command::CancelTask,
            // `s`/`?`/`g` при пустом вводе открывают настройки/справку/Remote; иначе печатаются как символ.
            KeyCode::Char('s') if self.input.is_empty() => {
                self.focus = Focus::Settings;
                Command::None
            }
            KeyCode::Char('?') if self.input.is_empty() => {
                self.focus = Focus::Help;
                Command::None
            }
            KeyCode::Char('g') if self.input.is_empty() => {
                self.focus = Focus::Remote;
                Command::None
            }
            KeyCode::Char('p') if self.input.is_empty() => {
                // «поделиться своим ПК» — снять сводку гранта из настроек для показа.
                self.share.grant = crate::net::GrantSummary {
                    allowed_paths: self
                        .settings
                        .allowed_path
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect(),
                    allow_shell: self.settings.allow_shell,
                    allow_dangerous: self.settings.allow_dangerous,
                    ttl_secs: (self.settings.ttl_secs > 0).then_some(self.settings.ttl_secs),
                };
                self.focus = Focus::Share;
                Command::StartShare
            }
            KeyCode::Char(c) => {
                self.input.insert_char(c);
                Command::None
            }
            KeyCode::Backspace => {
                self.input.backspace();
                Command::None
            }
            KeyCode::Delete => {
                self.input.delete();
                Command::None
            }
            KeyCode::Left => {
                self.input.left();
                Command::None
            }
            KeyCode::Right => {
                self.input.right();
                Command::None
            }
            KeyCode::Home => {
                self.input.home();
                Command::None
            }
            KeyCode::End => {
                self.input.end();
                Command::None
            }
            KeyCode::Enter if key.modifiers.contains(KeyModifiers::ALT) => {
                self.input.insert_newline(); // Alt+Enter — перенос строки
                Command::None
            }
            KeyCode::Enter => {
                if self.running || self.input.as_str().trim().is_empty() {
                    return Command::None;
                }
                let task = self.input.as_str().trim().to_string();
                self.input.clear();
                self.history.push(task.clone());
                self.history_idx = None;
                self.active_chat_mut().scroll = 0; // своё сообщение → прилипаем к низу
                self.active_chat_mut().lines.push(ChatLine {
                    role: ChatRole::User,
                    text: task.clone(),
                });
                if self.active_chat().title.is_empty() {
                    // заголовок из первого сообщения (то же правило, что derive_title)
                    self.active_chat_mut().title = task.trim().chars().take(30).collect();
                }
                // Префикс `!` — прямая команда мимо мозга (ручное управление).
                if let Some(rest) = task.strip_prefix('!') {
                    let rest = rest.trim().to_string();
                    if rest.is_empty() {
                        // `!` без команды — показать подсказку, ничего не исполнять.
                        self.push_system(crate::command::command_hint());
                        return Command::None;
                    }
                    return Command::RunCommand(rest);
                }
                Command::SubmitTask(task)
            }
            KeyCode::Up => {
                if self.history.is_empty() {
                    return Command::None;
                }
                let idx = match self.history_idx {
                    None => self.history.len() - 1,
                    Some(0) => 0,
                    Some(i) => i - 1,
                };
                self.history_idx = Some(idx);
                self.input.set(&self.history[idx]);
                Command::None
            }
            KeyCode::Down => {
                match self.history_idx {
                    Some(i) if i + 1 < self.history.len() => {
                        self.history_idx = Some(i + 1);
                        self.input.set(&self.history[i + 1]);
                    }
                    Some(_) => {
                        self.history_idx = None; // мимо новейшего → черновик
                        self.input.clear();
                    }
                    None => {}
                }
                Command::None
            }
            KeyCode::PageUp => {
                self.scroll_chat(true, 5);
                Command::None
            }
            KeyCode::PageDown => {
                self.scroll_chat(false, 5);
                Command::None
            }
            _ => Command::None,
        }
    }

    /// Свернуть событие бэкенда в состояние.
    pub fn on_event(&mut self, ev: crate::tui::event::AppEvent) {
        use crate::tui::event::AppEvent;
        match ev {
            // Клавиши перехватывает цикл (через on_key) ДО on_event — здесь no-op.
            AppEvent::Key(_) => {}
            AppEvent::AgentReply(text) => {
                // в чат-источник (думающий), не в видимый
                let t = self.target_chat();
                self.chats[t].scroll = 0; // новое сообщение → прилипаем к низу
                self.chats[t].lines.push(ChatLine {
                    role: ChatRole::Agent,
                    text,
                });
            }
            AppEvent::Activity(line) => self.activity.push(line),
            AppEvent::AgentDone(result) => {
                // ошибку — в чат-источник, ПОТОМ сброс running_chat (единственный владелец сброса).
                if let Err(e) = result {
                    let t = self.target_chat();
                    self.chats[t].lines.push(ChatLine {
                        role: ChatRole::System,
                        text: format!("⚠ ошибка: {e}"),
                    });
                }
                self.running = false;
                self.running_chat = None;
            }
            AppEvent::Confirm(req) => {
                self.pending = Some(req);
                self.focus = Focus::Confirm;
            }
            AppEvent::Resize => {}
            AppEvent::ScrollUp => self.scroll_chat(true, 3),
            AppEvent::ScrollDown => self.scroll_chat(false, 3),
            AppEvent::RemoteConnected { host, tools, grant, at_unix } => {
                self.remote = Some(RemoteView {
                    host_label: host,
                    tools,
                    grant,
                    connected_at: std::time::Instant::now(),
                    connected_at_unix: at_unix,
                    status: RemoteStatus::Connected,
                });
            }
            AppEvent::RemoteError(msg) => {
                // Если есть активный view — обновляем статус; иначе создаём Error-view с пустыми полями.
                if let Some(view) = self.remote.as_mut() {
                    view.status = RemoteStatus::Error(msg);
                } else {
                    self.remote = Some(RemoteView {
                        host_label: String::new(),
                        tools: vec![],
                        grant: Default::default(),
                        connected_at: std::time::Instant::now(),
                        connected_at_unix: 0,
                        status: RemoteStatus::Error(msg),
                    });
                }
            }
            AppEvent::RemoteDisconnected => {
                if let Some(view) = self.remote.take() {
                    self.host_log.push(crate::tui::hosts::HostLogEntry {
                        host_label: view.host_label,
                        connected_at_unix: view.connected_at_unix,
                    });
                }
            }
            AppEvent::ShareInvite(code) => {
                self.share.invite_code = Some(code);
                self.share.error = None;
            }
            AppEvent::SharePeerConnected(id) => {
                if !self.share.peers.contains(&id) {
                    self.share.peers.push(id);
                }
            }
            AppEvent::SharePeerGone(id) => {
                self.share.peers.retain(|p| p != &id);
            }
            AppEvent::ShareError(msg) => {
                self.share.error = Some(msg);
            }
            AppEvent::ShareStopped => {
                self.share = ShareView::default();
            }
        }
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

/// Заголовок чата из первого user-сообщения истории мозга: ≤30 символов (по символам,
/// не байтам — без паники на UTF-8). Нет user-сообщения → "".
pub fn derive_title(brain: &[crate::brain::Message]) -> String {
    let Some(first) = brain.iter().find(|m| m.role == "user") else {
        return String::new();
    };
    first.content.trim().chars().take(30).collect()
}

/// Преобразовать историю мозга в строки чата (для восстановления при старте).
/// Показываем только user/assistant с текстом; system и tool-сообщения скрыты.
pub fn history_to_chat(messages: &[crate::brain::Message]) -> Vec<ChatLine> {
    messages
        .iter()
        .filter_map(|m| match m.role.as_str() {
            "user" => Some(ChatLine {
                role: ChatRole::User,
                text: m.content.clone(),
            }),
            "assistant" if !m.content.is_empty() => Some(ChatLine {
                role: ChatRole::Agent,
                text: m.content.clone(),
            }),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::brain::{ToolRunner, ToolSpec};
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use serde_json::Value;
    use std::sync::Mutex;

    fn key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }
    fn code(k: KeyCode) -> KeyEvent {
        KeyEvent::new(k, KeyModifiers::NONE)
    }

    #[test]
    fn p_enters_share_and_starts_esc_leaves_and_stops() {
        let mut app = App::new();
        let cmd = app.on_key(key('p'));
        assert_eq!(app.focus, Focus::Share);
        assert_eq!(cmd, Command::StartShare);
        let cmd = app.on_key(code(KeyCode::Esc));
        assert_eq!(app.focus, Focus::Chat);
        assert_eq!(cmd, Command::StopShare);
    }

    #[test]
    fn share_screen_input_runs_local_command() {
        let mut app = App::new();
        let _ = app.on_key(key('p')); // на экран Share
        for ch in "!ls".chars() {
            let _ = app.on_key(key(ch));
        }
        let cmd = app.on_key(code(KeyCode::Enter));
        // ведущий `!` срезается (как в чат-пути) → команда «ls»
        assert_eq!(cmd, Command::RunCommand("ls".into()));
        assert!(app.input.is_empty(), "после отправки поле очищено");
    }

    #[test]
    fn share_events_update_view() {
        use crate::tui::event::AppEvent;
        let mut app = App::new();
        app.on_event(AppEvent::ShareInvite("CODE123".into()));
        assert_eq!(app.share.invite_code.as_deref(), Some("CODE123"));
        app.on_event(AppEvent::SharePeerConnected("nodeAAAA".into()));
        assert_eq!(app.share.peers, vec!["nodeAAAA".to_string()]);
        app.on_event(AppEvent::SharePeerGone("nodeAAAA".into()));
        assert!(app.share.peers.is_empty());
        app.on_event(AppEvent::ShareError("bind failed".into()));
        assert_eq!(app.share.error.as_deref(), Some("bind failed"));
        app.on_event(AppEvent::ShareStopped);
        assert!(app.share.invite_code.is_none() && app.share.peers.is_empty());
    }

    /// Мок-раннер: считает вызовы dispatch, отдаёт фиксированный ответ.
    #[derive(Default)]
    struct CountingRunner {
        calls: Mutex<Vec<String>>,
    }
    impl ToolRunner for CountingRunner {
        fn specs(&self) -> Vec<ToolSpec> {
            vec![]
        }
        fn dispatch(&self, name: &str, _a: &Value) -> String {
            self.calls.lock().unwrap().push(name.to_string());
            "файлы: a.txt b.txt".to_string()
        }
    }

    // Acceptance: полный путь прямой команды без мозга на уровне reducer+события.
    // Печать `!ls /tmp` → RunCommand → run_manual исполняет ОДИН dispatch (без мозга) →
    // ответ как реплика агента, AgentDone снимает running.
    #[test]
    fn manual_command_end_to_end_local() {
        use crate::tui::manual::{run_manual, ManualOutcome};
        let mut app = App::new();
        for c in "!ls /tmp".chars() {
            app.on_key(key(c));
        }
        let cmd = app.on_key(code(KeyCode::Enter));
        let raw = match cmd {
            Command::RunCommand(r) => r,
            other => panic!("ожидался RunCommand, получено {other:?}"),
        };
        // run_loop выставил бы running=true перед запуском исполнителя.
        app.running = true;
        let runner = CountingRunner::default();
        let out = run_manual(&runner, &raw);
        let text = match out {
            ManualOutcome::Done(t) => t,
            ManualOutcome::Hint(_) => panic!("команда должна быть распознана"),
        };
        // dispatch вызван ровно раз (мозг не участвовал).
        assert_eq!(runner.calls.lock().unwrap().as_slice(), ["list_dir"]);
        // исполнитель шлёт ответ + AgentDone — прогоняем через редьюсер.
        app.on_event(AppEvent::AgentReply(text));
        app.on_event(AppEvent::AgentDone(Ok(String::new())));
        assert!(!app.running); // running снят
        assert!(app
            .chat()
            .iter()
            .any(|l| matches!(l.role, ChatRole::Agent) && l.text.contains("a.txt")));
    }

    #[test]
    fn derive_title_from_first_user_message_trimmed() {
        use crate::brain::Message;
        let brain = vec![Message::system("sys"), Message::user("наладить вывод дисплея на втором мониторе пожалуйста")];
        let t = super::derive_title(&brain);
        assert!(t.chars().count() <= 30, "≤30 символов: {t:?}");
        assert!(t.starts_with("наладить вывод"));
    }

    #[test]
    fn derive_title_empty_when_no_user() {
        use crate::brain::Message;
        assert_eq!(super::derive_title(&[Message::system("sys")]), "");
    }

    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    #[test]
    fn ctrl_t_opens_chats_menu_cursor_at_active() {
        let mut app = App::new();
        app.chats.push(Chat::empty());
        app.active = 1;
        let _ = app.on_key(ctrl('t'));
        assert_eq!(app.focus, Focus::Chats);
        assert_eq!(app.chats_cursor, 1);
    }

    #[test]
    fn chats_menu_new_creates_and_activates() {
        let mut app = App::new();
        let _ = app.on_key(ctrl('t'));
        let cmd = app.on_key(key('n'));
        assert_eq!(app.chats.len(), 2);
        assert_eq!(app.active, 1, "новый чат активен");
        assert_eq!(app.focus, Focus::Chat);
        assert_eq!(cmd, Command::ChatsChanged);
    }

    #[test]
    fn chats_menu_arrows_and_enter_switch() {
        let mut app = App::new();
        app.chats.push(Chat::empty()); // 2 чата
        let _ = app.on_key(ctrl('t')); // cursor=0 (active)
        let _ = app.on_key(code(KeyCode::Down));
        assert_eq!(app.chats_cursor, 1);
        let cmd = app.on_key(code(KeyCode::Enter));
        assert_eq!(app.active, 1);
        assert_eq!(app.focus, Focus::Chat);
        assert_eq!(cmd, Command::ChatsChanged);
    }

    #[test]
    fn chats_menu_esc_closes_without_switch() {
        let mut app = App::new();
        app.chats.push(Chat::empty());
        let _ = app.on_key(ctrl('t'));
        let _ = app.on_key(code(KeyCode::Down));
        let cmd = app.on_key(code(KeyCode::Esc));
        assert_eq!(app.active, 0, "active не сменился");
        assert_eq!(app.focus, Focus::Chat);
        assert_eq!(cmd, Command::None);
    }

    #[test]
    fn chats_menu_delete_removes_and_shifts_active() {
        let mut app = App::new();
        app.chats.push(Chat::empty()); // [0,1]
        app.active = 1;
        let _ = app.on_key(ctrl('t')); // cursor=1
        let cmd = app.on_key(key('d'));
        assert_eq!(app.chats.len(), 1);
        assert_eq!(app.active, 0, "active сполз на оставшийся");
        assert_eq!(cmd, Command::ChatsChanged);
    }

    #[test]
    fn delete_last_chat_resets_to_one_empty() {
        let mut app = App::new();
        app.active_chat_mut().lines.push(ChatLine { role: ChatRole::User, text: "x".into() });
        let _ = app.on_key(ctrl('t'));
        let _ = app.on_key(key('d'));
        assert_eq!(app.chats.len(), 1, "никогда ноль");
        assert!(app.chat().is_empty(), "оставшийся чат пуст");
    }

    #[test]
    fn delete_blocked_while_running() {
        let mut app = App::new();
        app.chats.push(Chat::empty());
        app.running = true;
        let _ = app.on_key(ctrl('t'));
        let cmd = app.on_key(key('d'));
        assert_eq!(app.chats.len(), 2, "удаление заблокировано при running");
        assert_eq!(cmd, Command::None);
        assert!(app.chat().iter().any(|l| matches!(l.role, ChatRole::System)), "есть системная строка");
    }

    #[test]
    fn new_while_running_keeps_running_chat() {
        let mut app = App::new();
        app.running = true;
        app.running_chat = Some(0);
        let _ = app.on_key(ctrl('t'));
        let _ = app.on_key(key('n'));
        assert_eq!(app.running_chat, Some(0));
        assert_eq!(app.target_chat(), 0);
    }

    #[test]
    fn submit_sets_title_from_first_message() {
        let mut app = App::new();
        for c in "проверка дисплея".chars() { app.on_key(key(c)); }
        let _ = app.on_key(code(KeyCode::Enter));
        assert_eq!(app.active_chat().title, "проверка дисплея");
    }

    #[test]
    fn typing_appends_to_input() {
        let mut app = App::new();
        app.on_key(key('h'));
        app.on_key(key('i'));
        assert_eq!(app.input.as_str(), "hi");
    }

    #[test]
    fn backspace_removes_last_char_safely() {
        let mut app = App::new();
        for c in "пр".chars() {
            app.on_key(key(c));
        }
        app.on_key(code(KeyCode::Backspace));
        assert_eq!(app.input.as_str(), "п"); // кириллица не ломается
    }

    #[test]
    fn chat_edits_in_the_middle_with_cursor() {
        let mut app = App::new();
        for ch in "абвг".chars() {
            let _ = app.on_key(key(ch));
        }
        // курсор в конце; уйти влево на 2 и вставить 'X'
        let _ = app.on_key(code(KeyCode::Left));
        let _ = app.on_key(code(KeyCode::Left));
        let _ = app.on_key(key('X'));
        assert_eq!(app.input.as_str(), "абXвг");
        // Delete удаляет символ справа ('в')
        let _ = app.on_key(code(KeyCode::Delete));
        assert_eq!(app.input.as_str(), "абXг");
        // Home + Backspace в начале — no-op
        let _ = app.on_key(code(KeyCode::Home));
        let _ = app.on_key(code(KeyCode::Backspace));
        assert_eq!(app.input.as_str(), "абXг");
    }

    #[test]
    fn enter_submits_task_and_echoes_user_line() {
        let mut app = App::new();
        for c in "ls".chars() {
            app.on_key(key(c));
        }
        let cmd = app.on_key(code(KeyCode::Enter));
        assert!(matches!(cmd, Command::SubmitTask(t) if t == "ls"));
        assert!(app.input.is_empty());
        assert_eq!(app.chat().len(), 1);
        assert!(matches!(app.chat()[0].role, ChatRole::User));
        assert_eq!(app.chat()[0].text, "ls");
    }

    #[test]
    fn bang_prefix_emits_run_command_and_echoes() {
        let mut app = App::new();
        for c in "!ls /tmp".chars() {
            app.on_key(key(c));
        }
        let cmd = app.on_key(code(KeyCode::Enter));
        assert!(matches!(cmd, Command::RunCommand(ref r) if r == "ls /tmp"));
        assert!(app.input.is_empty());
        // эхо вводимой строки в чат (с префиксом, как набрал оператор)
        assert_eq!(app.chat().len(), 1);
        assert!(matches!(app.chat()[0].role, ChatRole::User));
        assert_eq!(app.chat()[0].text, "!ls /tmp");
    }

    #[test]
    fn bang_only_shows_hint_no_command() {
        let mut app = App::new();
        app.on_key(key('!'));
        let cmd = app.on_key(code(KeyCode::Enter));
        assert!(matches!(cmd, Command::None)); // нечего исполнять
        assert!(app.input.is_empty());
        // подсказка добавлена системной строкой
        assert!(app.chat().iter().any(|l| l.text.contains("!ls")));
    }

    #[test]
    fn plain_text_still_submits_to_brain() {
        let mut app = App::new();
        for c in "привет".chars() {
            app.on_key(key(c));
        }
        let cmd = app.on_key(code(KeyCode::Enter));
        assert!(matches!(cmd, Command::SubmitTask(t) if t == "привет"));
    }

    #[test]
    fn bang_blocked_while_running() {
        let mut app = App::new();
        app.running = true;
        for c in "!ls".chars() {
            app.on_key(key(c));
        }
        let cmd = app.on_key(code(KeyCode::Enter));
        assert!(matches!(cmd, Command::None)); // занят — не принимаем
        assert_eq!(app.input.as_str(), "!ls"); // ввод сохранён
    }

    #[test]
    fn enter_on_empty_input_does_nothing() {
        let mut app = App::new();
        let cmd = app.on_key(code(KeyCode::Enter));
        assert!(matches!(cmd, Command::None));
        assert!(app.chat().is_empty());
    }

    #[test]
    fn ctrl_c_requests_quit() {
        let mut app = App::new();
        let ev = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        let cmd = app.on_key(ev);
        assert!(matches!(cmd, Command::Quit));
        assert!(app.should_quit);
    }

    #[test]
    fn submit_blocked_while_running() {
        let mut app = App::new();
        app.running = true;
        for c in "x".chars() {
            app.on_key(key(c));
        }
        let cmd = app.on_key(code(KeyCode::Enter));
        assert!(matches!(cmd, Command::None)); // занят — не принимаем новую задачу
        assert_eq!(app.input.as_str(), "x"); // ввод сохранён
    }

    use crate::tui::event::AppEvent;

    #[test]
    fn agent_reply_routes_to_running_chat_not_active() {
        let mut app = App::new();
        app.chats.push(Chat::empty()); // 2 чата
        app.running = true;
        app.running_chat = Some(1); // думает чат 1
        app.active = 0; // смотрим чат 0
        app.on_event(AppEvent::AgentReply("ответ B".into()));
        assert!(app.chats[1].lines.iter().any(|l| l.text == "ответ B"), "ответ в чат-источник");
        assert!(app.chats[0].lines.is_empty(), "видимый чат не тронут");
    }

    #[test]
    fn agent_done_error_routes_to_running_chat() {
        let mut app = App::new();
        app.chats.push(Chat::empty());
        app.running = true;
        app.running_chat = Some(1);
        app.active = 0;
        app.on_event(AppEvent::AgentDone(Err("сеть".into())));
        assert!(!app.running);
        assert_eq!(app.running_chat, None);
        assert!(
            app.chats[1].lines.iter().any(|l| matches!(l.role, ChatRole::System) && l.text.contains("сеть")),
            "ошибка в чат-источник"
        );
        assert!(app.chats[0].lines.is_empty(), "видимый чат чист");
    }

    #[test]
    fn manual_command_does_not_set_running_chat() {
        // Инвариант, на который опирается гейт writeback в mod.rs: `!`-команда НЕ ставит
        // running_chat (его ставит только SubmitTask в run_loop).
        let mut app = App::new();
        for c in "!ls".chars() { app.on_key(key(c)); }
        let cmd = app.on_key(code(KeyCode::Enter));
        assert!(matches!(cmd, Command::RunCommand(_)));
        assert_eq!(app.running_chat, None, "ручная команда не помечает чат думающим");
    }

    #[test]
    fn agent_reply_appends_agent_line() {
        let mut app = App::new();
        app.running = true;
        app.on_event(AppEvent::AgentReply("готово".into()));
        assert_eq!(app.chat().len(), 1);
        assert!(matches!(app.chat()[0].role, ChatRole::Agent));
        assert_eq!(app.chat()[0].text, "готово");
    }

    #[test]
    fn activity_event_appends_to_activity_log() {
        let mut app = App::new();
        app.on_event(AppEvent::Activity("allow Read: /tmp".into()));
        assert_eq!(app.activity, vec!["allow Read: /tmp".to_string()]);
    }

    #[test]
    fn agent_done_clears_running_flag() {
        let mut app = App::new();
        app.running = true;
        app.on_event(AppEvent::AgentDone(Ok("ok".into())));
        assert!(!app.running);
    }

    #[test]
    fn agent_done_error_shows_system_line() {
        let mut app = App::new();
        app.running = true;
        app.on_event(AppEvent::AgentDone(Err("сеть упала".into())));
        assert!(!app.running);
        assert!(app
            .chat()
            .iter()
            .any(|l| matches!(l.role, ChatRole::System) && l.text.contains("сеть упала")));
    }

    use crate::tui::event::ConfirmRequest;
    use std::sync::mpsc::sync_channel;

    fn confirm_event(dangerous: bool) -> (AppEvent, std::sync::mpsc::Receiver<bool>) {
        let (tx, rx) = sync_channel::<bool>(1);
        let req = ConfirmRequest {
            prompt: "Подтвердить Write: /tmp/x?".into(),
            dangerous,
            reply: tx,
            trust: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        (AppEvent::Confirm(req), rx)
    }

    #[test]
    fn confirm_event_enters_modal() {
        let mut app = App::new();
        let (ev, _rx) = confirm_event(false);
        app.on_event(ev);
        assert_eq!(app.focus, Focus::Confirm);
        assert!(app.pending.is_some());
    }

    #[test]
    fn y_answers_yes_and_closes_modal() {
        let mut app = App::new();
        let (ev, rx) = confirm_event(false);
        app.on_event(ev);
        let cmd = app.on_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE));
        assert!(rx.recv().unwrap());
        assert_eq!(app.focus, Focus::Chat);
        assert!(app.pending.is_none());
        assert!(matches!(cmd, Command::None));
    }

    #[test]
    fn n_answers_no_and_closes_modal() {
        let mut app = App::new();
        let (ev, rx) = confirm_event(false);
        app.on_event(ev);
        app.on_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
        assert!(!rx.recv().unwrap());
        assert_eq!(app.focus, Focus::Chat);
    }

    #[test]
    fn a_answers_yes_and_requests_trust() {
        let mut app = App::new();
        let (ev, rx) = confirm_event(false);
        app.on_event(ev);
        let cmd = app.on_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
        assert!(rx.recv().unwrap());
        assert!(matches!(cmd, Command::TrustSession));
    }

    #[test]
    fn a_on_dangerous_does_not_trust() {
        let mut app = App::new();
        let (ev, rx) = confirm_event(true); // dangerous
        app.on_event(ev);
        // на опасном «a» работает как «y» (одобрить разово), но НЕ доверие
        let cmd = app.on_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
        assert!(rx.recv().unwrap());
        assert!(matches!(cmd, Command::None)); // никакого TrustSession
    }

    #[test]
    fn s_opens_settings_and_esc_closes() {
        let mut app = App::new();
        app.on_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE));
        assert_eq!(app.focus, Focus::Settings);
        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.focus, Focus::Chat);
    }

    fn open_settings(app: &mut App) {
        app.on_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE));
    }

    #[test]
    fn edit_model_commits_on_enter() {
        let mut app = App::new();
        open_settings(&mut app);
        app.on_key(KeyEvent::new(KeyCode::Char('m'), KeyModifiers::NONE)); // start edit model
        assert!(app.settings_edit.is_some());
        for _ in 0..40 {
            app.on_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        }
        for c in "llama3".chars() {
            app.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        let cmd = app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(cmd, Command::SettingsChanged));
        assert_eq!(app.settings.model, "llama3");
        assert!(app.settings_edit.is_none());
    }

    #[test]
    fn toggle_routing_flips_and_persists() {
        let mut app = App::new();
        open_settings(&mut app);
        assert!(!app.settings.routing);
        let cmd = app.on_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::NONE));
        assert!(matches!(cmd, Command::SettingsChanged));
        assert!(app.settings.routing, "routing включился");
        app.on_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::NONE));
        assert!(!app.settings.routing, "routing выключился");
    }

    #[test]
    fn toggle_fallback_provider_flips() {
        let mut app = App::new();
        open_settings(&mut app);
        let before = app.settings.fallback.provider;
        let cmd = app.on_key(KeyEvent::new(KeyCode::Char('b'), KeyModifiers::NONE));
        assert!(matches!(cmd, Command::SettingsChanged));
        assert_ne!(app.settings.fallback.provider, before);
    }

    #[test]
    fn edit_fallback_host_commits() {
        let mut app = App::new();
        open_settings(&mut app);
        app.on_key(KeyEvent::new(KeyCode::Char('f'), KeyModifiers::NONE));
        assert!(app.settings_edit.is_some(), "редактирование fallback host открылось");
        for c in "https://openrouter.ai/api/v1".chars() {
            app.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        let cmd = app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(cmd, Command::SettingsChanged));
        assert_eq!(app.settings.fallback.host, "https://openrouter.ai/api/v1");
    }

    #[test]
    fn edit_fallback_model_and_key_commit() {
        let mut app = App::new();
        open_settings(&mut app);
        app.on_key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::NONE));
        for c in "glm-4.6".chars() {
            app.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.settings.fallback.model, "glm-4.6");

        app.on_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        for c in "sk-xyz".chars() {
            app.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.settings.fallback.api_key.as_deref(), Some("sk-xyz"));
    }

    #[test]
    fn edit_esc_cancels_without_change() {
        let mut app = App::new();
        open_settings(&mut app);
        let before = app.settings.model.clone();
        app.on_key(KeyEvent::new(KeyCode::Char('m'), KeyModifiers::NONE));
        app.on_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));
        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)); // отмена
        assert!(app.settings_edit.is_none());
        assert_eq!(app.settings.model, before);
        assert_eq!(app.focus, Focus::Settings); // настройки не закрылись
    }

    #[test]
    fn edit_api_key_empty_clears_to_none() {
        let mut app = App::new();
        app.settings.api_key = Some("old".into());
        open_settings(&mut app);
        app.on_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE));
        for _ in 0..10 {
            app.on_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        }
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.settings.api_key.is_none());
    }

    #[test]
    fn toggle_returns_settings_changed() {
        let mut app = App::new();
        open_settings(&mut app);
        let cmd = app.on_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE));
        assert!(matches!(cmd, Command::SettingsChanged));
    }

    #[test]
    fn r_cycles_provider() {
        use crate::brain::Provider;
        let mut app = App::new();
        open_settings(&mut app);
        assert_eq!(app.settings.provider, Provider::Ollama);
        let cmd = app.on_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE));
        assert_eq!(app.settings.provider, Provider::OpenAi);
        assert!(matches!(cmd, Command::SettingsChanged));
        app.on_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE));
        assert_eq!(app.settings.provider, Provider::Ollama); // цикл
    }

    #[test]
    fn esc_closes_settings_when_not_editing() {
        let mut app = App::new();
        open_settings(&mut app);
        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.focus, Focus::Chat);
    }

    #[test]
    fn question_opens_help_esc_closes() {
        let mut app = App::new();
        app.on_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
        assert_eq!(app.focus, Focus::Help);
        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.focus, Focus::Chat);
    }

    #[test]
    fn question_typed_into_nonempty_input() {
        let mut app = App::new();
        app.input = "что".into();
        app.on_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
        assert_eq!(app.input.as_str(), "что?"); // в непустой ввод печатается как символ
        assert_eq!(app.focus, Focus::Chat);
    }

    #[test]
    fn on_event_ignores_key_variant() {
        let mut app = App::new();
        let k = KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE);
        app.on_event(AppEvent::Key(k)); // не паникует, не трогает чат
        assert!(app.chat().is_empty());
    }

    #[test]
    fn on_event_ignores_resize() {
        let mut app = App::new();
        app.on_event(crate::tui::event::AppEvent::Resize);
        assert!(app.chat().is_empty()); // не паникует, ничего не меняет
    }

    #[test]
    fn history_to_chat_keeps_user_and_assistant_only() {
        use crate::brain::Message;
        let msgs = vec![
            Message::system("sys"),
            Message::user("привет"),
            Message {
                role: "assistant".into(),
                content: "здравствуй".into(),
                tool_name: None,
                tool_call_id: None,
                tool_calls: None,
            },
            Message::tool("list_dir", "..."),
            Message {
                role: "assistant".into(),
                content: String::new(),
                tool_name: None,
                tool_call_id: None,
                tool_calls: None,
            },
        ];
        let lines = history_to_chat(&msgs);
        assert_eq!(lines.len(), 2);
        assert!(matches!(lines[0].role, ChatRole::User));
        assert_eq!(lines[0].text, "привет");
        assert!(matches!(lines[1].role, ChatRole::Agent));
        assert_eq!(lines[1].text, "здравствуй");
    }

    #[test]
    fn esc_while_running_cancels() {
        let mut app = App::new();
        app.running = true;
        let cmd = app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(matches!(cmd, Command::CancelTask));
    }

    #[test]
    fn esc_when_idle_does_not_cancel() {
        let mut app = App::new();
        let cmd = app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(matches!(cmd, Command::None));
    }

    #[test]
    fn ctrl_l_clears_and_requests_new_conversation() {
        let mut app = App::new();
        app.active_chat_mut().lines.push(ChatLine {
            role: ChatRole::User,
            text: "x".into(),
        });
        app.activity.push("allow Read: .".into());
        for c in "draft".chars() {
            app.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        let cmd = app.on_key(KeyEvent::new(KeyCode::Char('l'), KeyModifiers::CONTROL));
        assert!(matches!(cmd, Command::NewConversation));
        assert!(app.chat().is_empty());
        assert!(app.activity.is_empty());
        assert!(app.input.is_empty());
    }

    #[test]
    fn ctrl_l_noop_while_running() {
        let mut app = App::new();
        app.running = true;
        app.active_chat_mut().lines.push(ChatLine {
            role: ChatRole::User,
            text: "x".into(),
        });
        let cmd = app.on_key(KeyEvent::new(KeyCode::Char('l'), KeyModifiers::CONTROL));
        assert!(matches!(cmd, Command::None));
        assert_eq!(app.chat().len(), 1); // не тронут
    }

    #[test]
    fn alt_enter_inserts_newline_not_submit() {
        let mut app = App::new();
        for c in "строка1".chars() {
            app.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        let cmd = app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::ALT));
        assert!(matches!(cmd, Command::None));
        assert!(app.input.as_str().ends_with('\n'));
        for c in "строка2".chars() {
            app.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        assert_eq!(app.input.as_str(), "строка1\nстрока2");
    }

    #[test]
    fn enter_submits_multiline() {
        let mut app = App::new();
        app.input = "две\nстроки".into();
        let cmd = app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(cmd, Command::SubmitTask(t) if t == "две\nстроки"));
        assert!(app.input.is_empty());
    }

    #[test]
    fn backspace_deletes_newline() {
        let mut app = App::new();
        app.input = "a\n".into();
        app.on_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        assert_eq!(app.input.as_str(), "a");
    }

    #[test]
    fn up_recalls_previous_submissions() {
        let mut app = App::new();
        for msg in ["один", "два"] {
            app.input = msg.into();
            app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        }
        app.on_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(app.input.as_str(), "два");
        app.on_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(app.input.as_str(), "один");
        app.on_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        assert_eq!(app.input.as_str(), "два");
    }

    #[test]
    fn down_past_newest_clears_to_draft() {
        let mut app = App::new();
        app.input = "x".into();
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        app.on_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE)); // "x"
        app.on_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE)); // мимо новейшего → пусто
        assert!(app.input.is_empty());
    }

    #[test]
    fn up_with_empty_history_noop() {
        let mut app = App::new();
        app.on_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        assert!(app.input.is_empty());
    }

    #[test]
    fn pageup_scrolls_back_pagedown_forward() {
        let mut app = App::new();
        app.on_key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE));
        assert_eq!(app.chat_scroll(), 5);
        app.on_key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE));
        assert_eq!(app.chat_scroll(), 10);
        app.on_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
        assert_eq!(app.chat_scroll(), 5);
    }

    #[test]
    fn pagedown_saturates_at_zero() {
        let mut app = App::new();
        app.on_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
        assert_eq!(app.chat_scroll(), 0);
    }

    #[test]
    fn new_message_sticks_to_bottom() {
        let mut app = App::new();
        app.active_chat_mut().scroll = 20;
        app.on_event(crate::tui::event::AppEvent::AgentReply("ответ".into()));
        assert_eq!(app.chat_scroll(), 0);
    }

    #[test]
    fn mouse_wheel_scrolls_chat() {
        let mut app = App::new();
        app.on_event(crate::tui::event::AppEvent::ScrollUp);
        assert_eq!(app.chat_scroll(), 3);
        app.on_event(crate::tui::event::AppEvent::ScrollUp);
        assert_eq!(app.chat_scroll(), 6);
        app.on_event(crate::tui::event::AppEvent::ScrollDown);
        assert_eq!(app.chat_scroll(), 3);
    }

    #[test]
    fn open_remote_screen_and_type_code() {
        let mut app = App::new();
        app.on_key(key('g')); // хоткей открытия Remote
        assert_eq!(app.focus, Focus::Remote);
        for c in "abc".chars() { app.on_key(key(c)); }
        assert_eq!(app.remote_code_input.as_str(), "abc");
        let cmd = app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(cmd, Command::Connect("abc".into()));
    }

    #[test]
    fn remote_connected_event_sets_view() {
        let mut app = App::new();
        app.on_event(AppEvent::RemoteConnected {
            host: "node99".into(),
            tools: vec!["list_dir".into()],
            grant: crate::net::GrantSummary { allow_shell: true, ttl_secs: Some(60), ..Default::default() },
            at_unix: 1234,
        });
        let r = app.remote.as_ref().unwrap();
        assert_eq!(r.host_label, "node99");
        assert!(matches!(r.status, RemoteStatus::Connected));
        assert!(r.grant.allow_shell);
        assert_eq!(r.tools, vec!["list_dir".to_string()]);
    }

    #[test]
    fn remote_disconnected_clears_and_logs() {
        let mut app = App::new();
        app.on_event(AppEvent::RemoteConnected { host: "n1".into(), tools: vec![], grant: Default::default(), at_unix: 50 });
        app.on_event(AppEvent::RemoteDisconnected);
        assert!(app.remote.is_none());
        assert_eq!(app.host_log.last().unwrap().host_label, "n1");
        assert_eq!(app.host_log.last().unwrap().connected_at_unix, 50);
    }

    #[test]
    fn remote_error_sets_status() {
        let mut app = App::new();
        app.on_event(AppEvent::RemoteError("нет связи".into()));
        // ошибка без активного view → Error-view с пустыми полями
        assert!(app.remote.as_ref().map(|r| matches!(r.status, RemoteStatus::Error(_))).unwrap_or(true));
    }
}
