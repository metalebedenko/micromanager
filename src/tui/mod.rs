//! TUI-фронт: стандартный интерфейс приложения (чат + поток действий +
//! confirm клавишей + настройки). Чистый `App`-редьюсер (app.rs) + канальные швы
//! Confirmer/Audit (bridge.rs); тонкий ratatui-цикл (`run`) — единственный не-юнит-код.

pub mod app;
pub mod bridge;
pub mod config;
pub mod event;
pub mod history;
pub mod hosts;
pub mod manual;
pub mod remote;
pub mod render;
pub mod session;
pub mod settings;
pub mod share;
pub mod textinput;
pub mod theme;
pub use app::{App, ChatLine, ChatRole, Command, Focus};
pub use bridge::{ChannelAudit, ChannelConfirmer};
pub use event::{AppEvent, ConfirmRequest};
pub use render::draw;
pub use settings::Settings;

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use ratatui::crossterm::event::{
    read as read_event, DisableMouseCapture, EnableMouseCapture, Event, KeyEventKind, MouseEventKind,
};
use ratatui::crossterm::{execute, terminal};
use ratatui::prelude::CrosstermBackend;
use ratatui::Terminal;

use crate::brain::{new_conversation, run_agent_with, Message};
use crate::net::McpToolRunner;
use crate::tui::remote::ActivityRunner;

/// TTL подтверждения: нет ответа за это время → fail-closed deny (дизайн требует).
const TUI_CONFIRM_TTL: Duration = Duration::from_secs(120);

/// Подключиться к удалённому узлу B по коду-приглашению.
/// Ошибка на list_tools → закрыть частичную сессию, не стартуем раннер.
async fn connect_remote(
    code: &str,
) -> Result<(McpToolRunner, String, Vec<String>, crate::net::GrantSummary)> {
    let session = crate::net::McpSession::connect(code).await?;
    let grant = session.grant().clone();
    let tools_full = match session.list_tools_full().await {
        Ok(t) => t,
        Err(e) => {
            // частичное состояние → закрыть, не стартуем раннер
            session.close().await;
            return Err(e);
        }
    };
    let names: Vec<String> = tools_full.iter().map(|t| t.name.to_string()).collect();
    let specs = tools_full.iter().map(crate::net::map_tool).collect();
    let host = session.host_label().to_string();
    let runner = McpToolRunner::start(session, specs);
    Ok((runner, host, names, grant))
}

/// Поднять TUI: владеет терминалом, крутит цикл до выхода.
pub fn run(settings: Settings) -> Result<()> {
    // Tokio runtime живёт на всё время TUI — нужен для async connect.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    let (tx, rx) = mpsc::channel::<AppEvent>();
    let confirmer = Arc::new(ChannelConfirmer::new(tx.clone(), TUI_CONFIRM_TTL));
    // Авторитетная история диалога для мозга + флаг отмены, общие с агент-потоком.
    let conversation = Arc::new(Mutex::new(new_conversation()));
    let cancel = Arc::new(AtomicBool::new(false));

    // ввод в отдельном потоке → тот же канал
    {
        let tx = tx.clone();
        std::thread::spawn(move || loop {
            let ev = match read_event() {
                Ok(Event::Key(k)) if k.kind == KeyEventKind::Press => AppEvent::Key(k),
                Ok(Event::Resize(_, _)) => AppEvent::Resize,
                Ok(Event::Mouse(m)) => match m.kind {
                    MouseEventKind::ScrollUp => AppEvent::ScrollUp,
                    MouseEventKind::ScrollDown => AppEvent::ScrollDown,
                    _ => continue,
                },
                Ok(_) => continue,
                Err(_) => break,
            };
            if tx.send(ev).is_err() {
                break;
            }
        });
    }

    terminal::enable_raw_mode()?;
    let mut out = io::stdout();
    // EnableMouseCapture — чтобы ловить колесо для скролла чата.
    execute!(out, terminal::EnterAlternateScreen, EnableMouseCapture)?;
    let mut term = Terminal::new(CrosstermBackend::new(out))?;

    let sessions_file = session::sessions_path();
    let legacy_session = session::session_path();
    let config_file = config::config_path();
    let mut app = App::new();
    // Загрузить журнал прошлых подключений из диска.
    app.host_log = hosts::load_hosts(&hosts::hosts_path());
    // Восстановить все чаты (миграция session.json при первом запуске нового формата).
    let stored = session::load_sessions(&sessions_file, &legacy_session);
    app.chats = stored
        .chats
        .iter()
        .map(|sc| crate::tui::app::Chat {
            title: sc.title.clone(),
            lines: crate::tui::app::history_to_chat(&sc.messages),
            brain: sc.messages.clone(),
            scroll: 0,
        })
        .collect();
    app.active = stored.active;
    // Настройки: сохранённый конфиг важнее CLI-флагов; нет конфига → первый запуск (онбординг).
    let first_run = match config::load_config(&config_file) {
        Some(saved) => {
            app.settings = saved;
            false
        }
        None => {
            app.settings = settings; // из CLI-аргументов
            true
        }
    };
    if first_run {
        app.focus = Focus::Settings;
        app.push_system("Первый запуск — проверь настройки (m/h/k/p), затем Esc.");
    }
    let loop_result = run_loop(
        &mut term,
        &mut app,
        &rx,
        &tx,
        &confirmer,
        &conversation,
        &cancel,
        &sessions_file,
        &config_file,
        &rt,
    );

    terminal::disable_raw_mode().ok();
    execute!(
        term.backend_mut(),
        terminal::LeaveAlternateScreen,
        DisableMouseCapture
    )
    .ok();
    term.show_cursor().ok();
    loop_result
}

/// Снимок всего App → StoredSessions для записи на диск.
fn snapshot_sessions(app: &App) -> session::StoredSessions {
    session::StoredSessions {
        active: app.active,
        chats: app
            .chats
            .iter()
            .map(|c| session::StoredChat {
                title: c.title.clone(),
                messages: c.brain.clone(),
            })
            .collect(),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_loop(
    term: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    rx: &mpsc::Receiver<AppEvent>,
    tx: &mpsc::Sender<AppEvent>,
    confirmer: &Arc<ChannelConfirmer>,
    conversation: &Arc<Mutex<Vec<Message>>>,
    cancel: &Arc<AtomicBool>,
    sessions_file: &std::path::Path,
    config_file: &std::path::Path,
    rt: &tokio::runtime::Runtime,
) -> Result<()> {
    // Слот для активного удалённого раннера; Arc<Mutex> — async-таск кладёт, run_loop берёт.
    let remote_slot: Arc<Mutex<Option<McpToolRunner>>> = Arc::new(Mutex::new(None));
    // Анти-TOCTOU: connect_remote кладёт раннер в слот АСИНХРОННО (позже проверки is_some).
    // Без этого флага два быстрых Connect оба прошли бы проверку и второй молча вытеснил
    // бы первый раннер. Флаг резервирует «подключаемся» сразу, сбрасывается по Ok/Err.
    let connecting = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // Стоп-сигнал фоновой задачи шеринга (Some, пока «поделиться» активно).
    let mut share_stop: Option<tokio::sync::oneshot::Sender<()>> = None;

    loop {
        term.draw(|f| draw(f, app))?;
        let Ok(ev) = rx.recv() else { break };
        match ev {
            AppEvent::Key(k) => match app.on_key(k) {
                Command::SubmitTask(task) => {
                    app.running = true;
                    app.running_chat = Some(app.active);
                    cancel.store(false, Ordering::SeqCst);
                    // Рабочая копия текущего хода = история мозга активного чата.
                    *conversation.lock().unwrap() = app.active_chat().brain.clone();
                    // Маршрутизированный раннер (remote ActivityRunner / локальный).
                    // Инвариант времени жизни handle: клон handle из слота безопасен, потому что
                    // Disconnect и SubmitTask сериализованы на одном TUI event-цикле (rx.recv).
                    // Disconnect не может вклиниться в середину текущего прохода recv — handle не
                    // может стать осиротевшим до завершения этой ветки.
                    let routed = routed_runner(&remote_slot, tx);
                    spawn_agent(
                        task,
                        app.settings.clone(),
                        confirmer.clone(),
                        conversation.clone(),
                        cancel.clone(),
                        tx.clone(),
                        routed,
                    );
                }
                // Прямая команда оператора (`!`) — исполнить без мозга на активном
                // раннере. Тот же routed/local выбор и инвариант времени жизни handle,
                // что у SubmitTask. `running` снимется по AgentDone из spawn_command.
                Command::RunCommand(raw) => {
                    app.running = true;
                    cancel.store(false, Ordering::SeqCst);
                    // На экране «поделиться» команда идёт на СВОЮ машину (routed=None),
                    // помечается «ты→»; иначе — прежний чат-путь (remote/local + без метки).
                    if app.focus == Focus::Share {
                        spawn_command(raw, app.settings.clone(), confirmer.clone(), tx.clone(), None, "ты→ ");
                    } else {
                        let routed = routed_runner(&remote_slot, tx);
                        spawn_command(raw, app.settings.clone(), confirmer.clone(), tx.clone(), routed, "");
                    }
                }
                Command::CancelTask => cancel.store(true, Ordering::SeqCst),
                Command::NewConversation => {
                    // Ctrl-L: reducer уже очистил lines активного чата; синхронизируем brain+title+персист.
                    app.active_chat_mut().brain = new_conversation();
                    app.active_chat_mut().title.clear();
                    let _ = session::save_sessions(sessions_file, &snapshot_sessions(app));
                }
                Command::TrustSession => confirmer.trust_session(),
                Command::SettingsChanged => {
                    let _ = config::save_config(config_file, &app.settings);
                }
                Command::ChatsChanged => {
                    let _ = session::save_sessions(sessions_file, &snapshot_sessions(app));
                }
                Command::Quit => break,
                Command::None => {}
                // Подключение к удалённому узлу: не блокировать UI — запускаем на rt.
                Command::Connect(code) => {
                    use std::sync::atomic::Ordering;
                    // Анти-TOCTOU: атомарно «застолбить» подключение. Если слот занят ИЛИ
                    // уже идёт подключение (swap вернул true) — отказ, не плодим второй раннер.
                    let already = remote_slot.lock().unwrap().is_some()
                        || connecting.swap(true, Ordering::SeqCst);
                    if already {
                        let _ = tx.send(AppEvent::RemoteError(
                            "уже подключены или подключаемся — сначала /disconnect (Ctrl-D)".to_string(),
                        ));
                    } else {
                        let tx2 = tx.clone();
                        let slot2 = remote_slot.clone();
                        let connecting2 = connecting.clone();
                        rt.spawn(async move {
                            match connect_remote(&code).await {
                                Ok((runner, host, tools, grant)) => {
                                    let at_unix = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();
                                    // Положить раннер в слот ДО события (guard сразу дропается).
                                    slot2.lock().unwrap().replace(runner);
                                    connecting2.store(false, Ordering::SeqCst);
                                    let _ = tx2.send(AppEvent::RemoteConnected {
                                        host,
                                        tools,
                                        grant,
                                        at_unix,
                                    });
                                }
                                Err(e) => {
                                    connecting2.store(false, Ordering::SeqCst);
                                    let _ = tx2.send(AppEvent::RemoteError(e.to_string()));
                                }
                            }
                        });
                    }
                }
                // Отключение: взять раннер из слота и погасить в отдельном std-потоке
                // (shutdown блокирующий — не гонять на async-worker).
                // RemoteDisconnected отправляем только если раннер реально был — иначе
                // событие было бы ложным, а on_event добавил бы пустой HostLogEntry.
                Command::Disconnect => {
                    let maybe_runner = remote_slot.lock().unwrap().take();
                    if let Some(runner) = maybe_runner {
                        std::thread::spawn(move || runner.shutdown());
                        let _ = tx.send(AppEvent::RemoteDisconnected);
                    }
                }
                // «Поделиться своим ПК»: поднять эндпоинт фоновой задачей на rt.
                // Идемпотентно — если уже слушаем, не поднимаем второй.
                Command::StartShare => {
                    if share_stop.is_none() {
                        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
                        share_stop = Some(stop_tx);
                        let grant = app.settings.to_grant();
                        let remember = app.settings.remember;
                        let tx2 = tx.clone();
                        rt.spawn(share::run_share(
                            grant,
                            remember,
                            tx2,
                            TUI_CONFIRM_TTL,
                            stop_rx,
                        ));
                    }
                }
                // Прекратить шеринг: послать стоп-сигнал (задача закроет эндпоинт + A).
                Command::StopShare => {
                    if let Some(stop_tx) = share_stop.take() {
                        let _ = stop_tx.send(());
                    }
                }
                // Скопировать код-приглашение в системный буфер (best-effort).
                Command::CopyInvite(code) => {
                    let ok = arboard::Clipboard::new()
                        .and_then(|mut cb| cb.set_text(code))
                        .is_ok();
                    let _ = tx.send(AppEvent::ShareCopied(ok));
                }
            },
            AppEvent::AgentDone(ref res) => {
                // writeback истории мозга в чат-источник ДО сброса running_chat — ТОЛЬКО для
                // агент-задач (running_chat=Some). Ручные `!`-команды brain не меняют → пропускаем
                // (иначе затёрли бы активный чат устаревшей рабочей копией conversation).
                let was_agent = app.running_chat.is_some();
                if let Some(rc) = app.running_chat {
                    app.chats[rc].brain = conversation.lock().unwrap().clone();
                    if app.chats[rc].title.is_empty() {
                        app.chats[rc].title = crate::tui::app::derive_title(&app.chats[rc].brain);
                    }
                }
                let res2 = match res {
                    Ok(s) => Ok(s.clone()),
                    Err(e) => Err(e.clone()),
                };
                app.on_event(AppEvent::AgentDone(res2)); // сброс running/running_chat, ошибка в target
                if was_agent {
                    let _ = session::save_sessions(sessions_file, &snapshot_sessions(app));
                }
            }
            AppEvent::RemoteConnected {
                ref host,
                ref tools,
                ref grant,
                at_unix,
            } => {
                app.on_event(AppEvent::RemoteConnected {
                    host: host.clone(),
                    tools: tools.clone(),
                    grant: grant.clone(),
                    at_unix,
                });
                // RemoteConnected не изменяет host_log (запись туда происходит при
                // RemoteDisconnected в on_event). Сохранение здесь не нужно.
            }
            other => {
                let is_disconnected = matches!(other, AppEvent::RemoteDisconnected);
                app.on_event(other);
                // После отключения — сохранить обновлённый host_log (on_event добавил запись).
                if is_disconnected {
                    let _ = hosts::save_hosts(&hosts::hosts_path(), &app.host_log);
                }
            }
        }
        if app.should_quit {
            break;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn spawn_agent(
    task: String,
    settings: Settings,
    confirmer: Arc<ChannelConfirmer>,
    conversation: Arc<Mutex<Vec<Message>>>,
    cancel: Arc<AtomicBool>,
    tx: mpsc::Sender<AppEvent>,
    routed: Option<Box<dyn crate::brain::ToolRunner>>,
) {
    std::thread::spawn(move || {
        // Мозг из настроек: хост + модель + опц. cloud-ключ.
        let brain = settings.build_brain();
        // Снимок истории + новый user-ход (running=true блокирует параллельный submit/clear).
        let mut messages = {
            let guard = conversation.lock().unwrap();
            guard.clone()
        };
        messages.push(Message::user(&task));
        // Свёртка истории до хода: длинная история → старое в LLM-саммари (или
        // обрезка-страховка). Только TUI копит историю; CLI/Telegram stateless.
        // Это A-side операция нашим локальным `brain` — одинаково для обеих веток
        // ниже (routed/local): сворачиваем СВОЮ историю, не зависит от того, где
        // исполняются тулы (B по сети или in-process).
        crate::tui::history::summarize_if_needed(&*brain, &mut messages, &tx);
        // Маршрутизация: если есть удалённый раннер → гонять через него;
        // иначе построить локальный MCP-раннер + аудит (только когда нужны).
        let result = if let Some(remote_runner) = routed {
            run_agent_with(&*brain, remote_runner.as_ref(), &mut messages, &cancel)
        } else {
            // Локальный MCP-раннер строится тем же хелпером, что и для прямых команд —
            // safety/audit гарантированно идентичны (build_local_runner). Раннер живёт
            // до конца хода и гасится по Drop (закрывает in-process сессию).
            let runner = build_local_runner(&settings, confirmer, &tx, "");
            // Ошибка обращения к Ollama всплывёт здесь, на HTTP-вызове внутри run_agent_with.
            run_agent_with(&*brain, &runner.handle(), &mut messages, &cancel)
        };
        // Записать историю в рабочую копию — run_loop заберёт её в чат-источник на AgentDone
        // и сам персистит sessions.json (файл здесь больше не пишем).
        *conversation.lock().unwrap() = messages;
        match result {
            Ok(answer) => {
                let _ = tx.send(AppEvent::AgentReply(answer));
                let _ = tx.send(AppEvent::AgentDone(Ok(String::new())));
            }
            Err(e) => {
                let _ = tx.send(AppEvent::AgentDone(Err(e.to_string())));
            }
        }
    });
}

/// Поднять локальный MCP-раннер (in-process rmcp ↔ HandsServer) с тем же
/// safety+audit, что и agent-loop: policy из настроек, owner-confirmer, журнал в
/// два приёмника (`FileAudit` fail-closed + `ChannelAudit` в панель с меткой).
/// Единый источник — и agent-loop, и прямые команды (`!`) идут через идентичный
/// MCP-гейт. Строится per-task (start_local спавнит свой driver-поток, внешний
/// рантайм не нужен); доверие-на-сессию сохраняется через общий `Arc`-confirmer.
fn build_local_runner(
    settings: &Settings,
    confirmer: Arc<ChannelConfirmer>,
    tx: &mpsc::Sender<AppEvent>,
    label: &str,
) -> McpToolRunner {
    let audit = bridge::DualAudit::new(
        Box::new(crate::audit::FileAudit::new(crate::audit::default_path())),
        Box::new(ChannelAudit::labeled(tx.clone(), label)),
    );
    let confirmer: Arc<dyn crate::safety::Confirmer> = confirmer;
    McpToolRunner::start_local(settings.to_policy(), confirmer, Arc::new(audit))
}

/// Построить маршрутизированный раннер для активной сессии: если есть
/// удалённое подключение → завернуть его в `ActivityRunner` (tee действий B
/// в панель); иначе `None` (локальная ветка строит MCP-раннер сама).
/// Тот же блок, что у `SubmitTask` и `RunCommand` — извлечён ради DRY.
fn routed_runner(
    remote_slot: &Arc<Mutex<Option<McpToolRunner>>>,
    tx: &mpsc::Sender<AppEvent>,
) -> Option<Box<dyn crate::brain::ToolRunner>> {
    let guard = remote_slot.lock().unwrap();
    guard.as_ref().map(|r| {
        Box::new(ActivityRunner {
            inner: r.handle(),
            tx: tx.clone(),
        }) as Box<dyn crate::brain::ToolRunner>
    })
}

/// Исполнить прямую команду оператора (`!`) без мозга, в фоновом потоке.
/// Маршрут тот же, что у agent-loop: удалённый `routed` (под вето B) или
/// локальный MCP-раннер из `build_local_runner` — safety не ослаблен.
/// Результат/подсказка → чат; `AgentDone` снимает флаг `running`.
fn spawn_command(
    raw: String,
    settings: Settings,
    confirmer: Arc<ChannelConfirmer>,
    tx: mpsc::Sender<AppEvent>,
    routed: Option<Box<dyn crate::brain::ToolRunner>>,
    label: &'static str,
) {
    std::thread::spawn(move || {
        let outcome = if let Some(remote) = routed {
            manual::run_manual(remote.as_ref(), &raw)
        } else {
            let runner = build_local_runner(&settings, confirmer, &tx, label);
            manual::run_manual(&runner.handle(), &raw)
        };
        let text = match outcome {
            manual::ManualOutcome::Done(t) => t,
            manual::ManualOutcome::Hint(h) => h,
        };
        let _ = tx.send(AppEvent::AgentReply(text));
        let _ = tx.send(AppEvent::AgentDone(Ok(String::new())));
    });
}
