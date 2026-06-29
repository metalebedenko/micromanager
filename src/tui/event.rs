//! События, которыми бэкенд (агент-поток) и ввод кормят редьюсер `App`.

use std::sync::atomic::AtomicBool;
use std::sync::mpsc::SyncSender;
use std::sync::Arc;

/// Запрос подтверждения от `ChannelConfirmer`: показать модалку и вернуть ответ.
pub struct ConfirmRequest {
    /// Человекочитаемое описание действия (что подтверждаем).
    pub prompt: String,
    /// true → катастрофичное действие (отдельная громкая модалка, без доверия-на-сессию).
    pub dangerous: bool,
    /// Канал ответа: true=да, false=нет. Одноразовый.
    pub reply: SyncSender<bool>,
    /// Флаг доверия-на-сессию ИМЕННО того confirmer-а, что прислал запрос (для ответа «На
    /// сессию»). При нескольких удалённых A у каждого свой `ChannelConfirmer` → доверие
    /// ставится точечно. dangerous его не трогает.
    pub trust: Arc<AtomicBool>,
}

/// Событие в адрес UI.
pub enum AppEvent {
    /// Нажатие клавиши (из input-потока). Обрабатывается циклом через `App::on_key`,
    /// НЕ в `on_event` — цикл перехватывает `Key` до вызова `on_event`.
    Key(ratatui::crossterm::event::KeyEvent),
    /// Финальный/промежуточный текст от агента → строка чата.
    AgentReply(String),
    /// Строка журнала действий → панель активности.
    Activity(String),
    /// Агент завершил задачу (Ok=итог, Err=ошибка цикла).
    AgentDone(Result<String, String>),
    /// Агент просит подтверждение (мутация/опасное).
    Confirm(ConfirmRequest),
    /// Терминал изменил размер — цикл просто перерисуется (no-op в on_event).
    Resize,
    /// Колесо мыши вверх — прокрутка чата назад.
    ScrollUp,
    /// Колесо мыши вниз — прокрутка чата вперёд.
    ScrollDown,
    /// Удалённый узел подключился: лейбл хоста, список инструментов, грант прав, unix-время.
    RemoteConnected {
        host: String,
        tools: Vec<String>,
        grant: crate::net::GrantSummary,
        at_unix: u64,
    },
    /// Ошибка соединения с удалённым узлом.
    RemoteError(String),
    /// Удалённый узел отключился.
    RemoteDisconnected,
    /// Шеринг поднял эндпоинт — код-приглашение для друга A.
    ShareInvite(String),
    /// К нам (B) подключился A: короткий node-id.
    SharePeerConnected(String),
    /// A отключился: короткий node-id.
    SharePeerGone(String),
    /// Ошибка шеринга (напр. bind упал).
    ShareError(String),
    /// Шеринг остановлен (эндпоинт закрыт).
    ShareStopped,
    /// Результат копирования кода-приглашения в буфер обмена (true — успех).
    ShareCopied(bool),
}
