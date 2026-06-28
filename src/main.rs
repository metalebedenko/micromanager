//! micromanager — кросс-платформенные «руки для LLM».
//!
//! Принцип: тонкие руки, сменный мозг. Безопасный execution-endpoint
//! (MCP-сервер), интеллект подключается клиентом. См. ../design.md.
//!
//! micromanager: безопасный MCP-сервер исполнения + локальный/удалённый мозг.
//! Логика — в библиотечном крейте (src/lib.rs), этот файл — CLI-вход.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "micromanager", version, about = "Руки для LLM (MCP-сервер)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Запустить MCP-сервер «руки» по stdio (для подключения MCP-клиентом).
    Serve,
    /// Выполнить задачу естественным языком через LLM,
    /// которая сама рулит «руками».
    Agent {
        /// Задача обычным текстом, напр. "покажи что в папке Загрузки".
        task: String,
        /// Модель (по умолч. gemma4:12b или $MM_MODEL).
        #[arg(long)]
        model: Option<String>,
        /// Бэкенд мозга: ollama (локально) или openai (OpenRouter/совместимый).
        #[arg(long, default_value = "ollama", value_parser = parse_provider)]
        provider: micromanager::brain::Provider,
    },
    /// B-сторона: выставить «руки» в сеть по iroh, напечатать код-приглашение.
    /// Capability-грант сужает доступ гостя.
    Listen {
        /// Разрешить гостю только эти пути (можно повторять). Пусто = весь диск.
        #[arg(long = "allow-path")]
        allow_path: Vec<String>,
        /// Запретить гостю выполнение команд (run_shell).
        #[arg(long = "no-shell")]
        no_shell: bool,
        /// TTL сессии в секундах (по истечении — отключение). Нет = без лимита.
        #[arg(long)]
        ttl: Option<u64>,
        /// Owner-override: разрешить КАТАСТРОФИЧНЫЕ команды (format/diskpart/reg delete HKLM…)
        /// — но каждая потребует отдельного громкого подтверждения владельца. Опасно.
        #[arg(long = "allow-dangerous")]
        allow_dangerous: bool,
        /// Дублировать отчёты о действиях в Telegram владельца. Нужны env
        /// MM_TG_TOKEN и MM_TG_OWNER (бот и chat_id владельца ЭТОЙ машины).
        #[arg(long = "report-tg")]
        report_tg: bool,
        /// Опт-ин: ПОМНИТЬ этого друга после рестарта (персист ключа+allowlist) —
        /// он переподключится без нового кода (`connect --resume`). Отозвать — `forget`.
        #[arg(long = "remember")]
        remember: bool,
    },
    /// A-сторона: дозвониться до B по коду и вызвать его руки.
    /// Без --nl: прямой вызов list_dir на B (отладочный режим).
    /// С --nl: A-мозг гоняет тулы B в естественном языке (NL-over-remote).
    Connect {
        /// Код-приглашение, полученный от B. Не нужен с --resume.
        ticket: Option<String>,
        /// Реконнект к ЗАПОМНЕННОМУ B без кода (если ранее был `listen --remember`).
        #[arg(long)]
        resume: bool,
        /// К какому запомненному B резюмить (префикс метки/id). Требует --resume.
        /// Без него при нескольких — интерактивное меню.
        #[arg(long = "host")]
        host: Option<String>,
        /// Путь для list_dir на стороне B (только без --nl).
        #[arg(long, default_value = ".")]
        path: String,
        /// NL-режим: задача обычным текстом, мозг A гоняет тулы на B.
        #[arg(long)]
        nl: Option<String>,
        /// Модель мозга (для --nl).
        #[arg(long)]
        model: Option<String>,
        /// Провайдер мозга (для --nl): ollama|openai.
        #[arg(long, default_value = "ollama", value_parser = parse_provider)]
        provider: micromanager::brain::Provider,
    },
    /// Управлять своим компом из Telegram. Нужны env: MM_TG_TOKEN, MM_TG_OWNER.
    /// Raw-команды по умолчанию; с --nl — человеческий текст через выбранный мозг (--provider).
    Telegram {
        /// NL-режим: текст-не-команда идёт в мозг как agent-loop.
        #[arg(long)]
        nl: bool,
        /// Модель для NL-режима (по умолч. gemma4:12b / $MM_MODEL).
        #[arg(long)]
        model: Option<String>,
        /// Бэкенд мозга: ollama (локально) или openai (OpenRouter/совместимый).
        #[arg(long, default_value = "ollama", value_parser = parse_provider)]
        provider: micromanager::brain::Provider,
    },
    /// Поднять TUI — стандартный интерфейс (чат + действия + confirm + настройки).
    Tui {
        /// Модель мозга (по умолчанию — общий дефолт gemma4:12b / $MM_MODEL).
        #[arg(long)]
        model: Option<String>,
        /// Ограничить действия этим путём (scope). По умолчанию — без ограничения.
        #[arg(long = "allow-path")]
        allow_path: Option<std::path::PathBuf>,
        /// Запретить shell-команды.
        #[arg(long = "no-shell")]
        no_shell: bool,
        /// Разрешить owner-override катастрофичных команд (громкое подтверждение).
        #[arg(long = "allow-dangerous")]
        allow_dangerous: bool,
    },
    /// Отозвать постоянный доступ (опт-ин персист pairing): забыть запомненного
    /// друга (B-сторона, allowlist) / запомненного B (A-сторона, peers).
    Forget {
        /// Префикс id/метки кого забыть. Без него нужен --all.
        who: Option<String>,
        /// Забыть ВСЕХ запомненных.
        #[arg(long)]
        all: bool,
    },
}

/// Разбирает строку провайдера → вариант `Provider`.
/// "openai" | "openrouter" → `Ok(OpenAi)`; "ollama" → `Ok(Ollama)`;
/// всё остальное → `Err` с понятным сообщением.
fn parse_provider(s: &str) -> Result<micromanager::brain::Provider, String> {
    match s.to_ascii_lowercase().as_str() {
        "ollama" => Ok(micromanager::brain::Provider::Ollama),
        "openai" | "openrouter" => Ok(micromanager::brain::Provider::OpenAi),
        _ => Err(format!(
            "неизвестный провайдер: {s} (допустимо: ollama, openai)"
        )),
    }
}

/// Разрешает конфигурацию мозга из аргументов CLI + переменных окружения.
/// Возвращает `(provider, host, model, api_key)`.
///
/// Ollama: OLLAMA_HOST → http://localhost:11434; OLLAMA_API_KEY → ключ.
/// OpenAi: MM_BASE_URL → https://openrouter.ai/api/v1; MM_API_KEY || OPENROUTER_API_KEY → ключ.
/// Модель: аргумент → MM_MODEL → default_model().
fn resolve_brain_cfg(
    provider: micromanager::brain::Provider,
    model: Option<String>,
) -> (micromanager::brain::Provider, String, String, Option<String>) {
    use micromanager::brain::Provider;
    let model = model
        .or_else(|| std::env::var("MM_MODEL").ok())
        .unwrap_or_else(micromanager::brain::default_model);
    match provider {
        Provider::Ollama => {
            let host = std::env::var("OLLAMA_HOST")
                .unwrap_or_else(|_| "http://localhost:11434".to_string());
            let key = std::env::var("OLLAMA_API_KEY").ok().filter(|k| !k.is_empty());
            (Provider::Ollama, host, model, key)
        }
        Provider::OpenAi => {
            let host = std::env::var("MM_BASE_URL")
                .unwrap_or_else(|_| "https://openrouter.ai/api/v1".to_string());
            let key = std::env::var("MM_API_KEY")
                .or_else(|_| std::env::var("OPENROUTER_API_KEY"))
                .ok()
                .filter(|k| !k.is_empty());
            (Provider::OpenAi, host, model, key)
        }
    }
}

/// Откуда CLI/Telegram берут мозг: роутер из конфига или флаги/env.
#[derive(Debug, PartialEq)]
enum BrainChoice {
    Routed,
    FromFlags,
}

/// Чистое решение: роутер активен в конфиге → `Routed`, иначе `FromFlags`.
/// `micromanager.config.json` — единый источник правды (его правит TUI); CLI-флаги
/// (--provider/--model) применяются только в не-routing пути.
fn choose_brain_source(config: Option<&micromanager::tui::Settings>) -> BrainChoice {
    match config {
        Some(s) if s.routing_active() => BrainChoice::Routed,
        _ => BrainChoice::FromFlags,
    }
}

/// Построить мозг для CLI/Telegram. Если в `micromanager.config.json` включён
/// routing — берём `RoutingBrain` из конфига (primary→fallback); иначе строим из
/// флагов/env, как раньше (полная обратная совместимость).
fn build_cli_brain(
    provider: micromanager::brain::Provider,
    model: Option<String>,
) -> Box<dyn micromanager::brain::Brain> {
    let config = micromanager::tui::config::load_config(&micromanager::tui::config::config_path());
    match choose_brain_source(config.as_ref()) {
        BrainChoice::Routed => {
            let s = config.expect("Routed ⇒ конфиг загружен");
            eprintln!("[micromanager] routing=on → мозг из config.json (primary→fallback)");
            s.build_brain()
        }
        BrainChoice::FromFlags => {
            let (p, host, model, key) = resolve_brain_cfg(provider, model);
            eprintln!("[micromanager] мозг: {p:?}, модель {model}");
            micromanager::brain::build_brain(p, &host, &model, key)
        }
    }
}

/// Чистый разбор ввода меню: 1-based номер строки → 0-based индекс среза.
/// Не число / 0 / вне диапазона [1, len] / пусто → None.
fn parse_menu_choice(input: &str, len: usize) -> Option<usize> {
    let n: usize = input.trim().parse().ok()?;
    if n >= 1 && n <= len {
        Some(n - 1)
    } else {
        None
    }
}

/// Человекочитаемое «сколько назад» из last_used_unix. 0 → «давно».
fn ago(last_used_unix: u64) -> String {
    if last_used_unix == 0 {
        return "давно".to_string();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let secs = now.saturating_sub(last_used_unix);
    if secs < 60 {
        format!("{secs}s назад")
    } else if secs < 3600 {
        format!("{}m назад", secs / 60)
    } else if secs < 86400 {
        format!("{}h назад", secs / 3600)
    } else {
        format!("{}d назад", secs / 86400)
    }
}

/// Печатает меню (свежие сверху, 1-based) и читает выбор со stdin.
/// Кривой ввод → переспрос; пусто/EOF (Ctrl-D) → None (отмена).
fn choose_from_menu(peers: &[micromanager::net::KnownPeer]) -> Option<usize> {
    use std::io::Write;
    eprintln!("Запомненные хосты (свежие сверху):");
    for (i, p) in peers.iter().enumerate() {
        eprintln!("  {}) {} — {}", i + 1, p.label, ago(p.last_used_unix));
    }
    loop {
        eprint!("Выбери номер (Enter — отмена): ");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        match std::io::stdin().read_line(&mut line) {
            Ok(0) => return None, // EOF (Ctrl-D)
            Ok(_) => {}
            Err(_) => return None,
        }
        if line.trim().is_empty() {
            return None; // пустая строка → отмена
        }
        if let Some(idx) = parse_menu_choice(&line, peers.len()) {
            return Some(idx);
        }
        eprintln!("Неверный номер, попробуй ещё.");
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    // Один раз: создать per-user state-dir + мигрировать легаси `micromanager.*` из CWD.
    micromanager::paths::init();
    match cli.command {
        Command::Serve => micromanager::server::run_stdio().await,
        Command::Agent { task, model, provider } => {
            // reqwest blocking нельзя крутить в async-рантайме → отдельный поток.
            let answer = tokio::task::spawn_blocking(move || -> anyhow::Result<String> {
                let brain = build_cli_brain(provider, model);
                // Мозг исполняет тулы через настоящий MCP (in-process), не через ярлык.
                let runner = micromanager::net::McpToolRunner::start_local(
                    micromanager::safety::Policy::default(),
                    std::sync::Arc::new(micromanager::safety::StdinConfirmer::default()),
                    std::sync::Arc::new(micromanager::audit::FileAudit::new(
                        micromanager::audit::default_path(),
                    )),
                );
                micromanager::brain::run_agent(&*brain, &runner.handle(), &task)
            })
            .await??;
            println!("{answer}");
            Ok(())
        }
        Command::Telegram { nl, model, provider } => {
            let token = std::env::var("MM_TG_TOKEN")
                .map_err(|_| anyhow::anyhow!("нет env MM_TG_TOKEN (токен бота от BotFather)"))?;
            let owner: i64 = std::env::var("MM_TG_OWNER")
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .ok_or_else(|| anyhow::anyhow!("нет env MM_TG_OWNER (chat_id владельца, число)"))?;
            // confirm через inline-кнопки; pending делится между фронтом и confirmer.
            let pending = std::sync::Arc::new(micromanager::tg::PendingConfirms::new());
            let confirmer = micromanager::tg::TelegramConfirmer::new(
                owner,
                pending.clone(),
                Box::new(micromanager::tg::ReqwestButtonSender::new(token.clone())),
                std::time::Duration::from_secs(120),
            );
            // Локальные руки Telegram — через настоящий MCP (in-process), не ярлык.
            let local = micromanager::net::McpToolRunner::start_local(
                micromanager::safety::Policy::default(),
                std::sync::Arc::new(confirmer),
                std::sync::Arc::new(micromanager::audit::FileAudit::new(
                    micromanager::audit::default_path(),
                )),
            );
            let api = micromanager::tg::ReqwestTelegram::new(token);
            let mut front = micromanager::tg::TelegramFront::new(api, owner, local, pending);
            if nl {
                let brain: std::sync::Arc<dyn micromanager::brain::Brain> =
                    build_cli_brain(provider, model).into();
                eprintln!("[tg] NL-режим");
                front = front.with_brain(brain);
            }
            front.run().await
        }
        Command::Listen {
            allow_path,
            no_shell,
            ttl,
            allow_dangerous,
            report_tg,
            remember,
        } => {
            let policy = micromanager::safety::Policy {
                allowed_paths: allow_path.iter().map(std::path::PathBuf::from).collect(),
                blocked_patterns: Vec::new(),
                allow_shell: !no_shell,
                allow_dangerous,
            };
            let grant = micromanager::net::Grant {
                policy,
                ttl: ttl.map(std::time::Duration::from_secs),
            };
            let report = if report_tg {
                let token = std::env::var("MM_TG_TOKEN")
                    .map_err(|_| anyhow::anyhow!("--report-tg: нет env MM_TG_TOKEN"))?;
                let owner: i64 = std::env::var("MM_TG_OWNER")
                    .ok()
                    .and_then(|s| s.trim().parse().ok())
                    .ok_or_else(|| anyhow::anyhow!("--report-tg: нет env MM_TG_OWNER (chat_id)"))?;
                let sink: std::sync::Arc<dyn micromanager::tg::ReportSink> =
                    std::sync::Arc::new(micromanager::tg::ReqwestReportSink::new(token));
                Some((sink, owner))
            } else {
                None
            };
            micromanager::net::run_listen(grant, report, remember).await
        }
        Command::Connect { ticket, resume, host, path, nl, model, provider } => {
            // --host имеет смысл только в resume-флоу.
            if host.is_some() && !resume {
                anyhow::bail!("--host требует --resume");
            }
            // Реконнект к запомненному B (--resume) или дозвон по коду.
            let resumed = if resume {
                Some(micromanager::net::McpSession::resume(host.as_deref(), choose_from_menu).await?)
            } else {
                None
            };
            match nl {
                None => match resumed {
                    Some(session) => {
                        let out = session
                            .call_tool("list_dir", serde_json::json!({ "path": path }))
                            .await?;
                        println!("list_dir(\"{path}\") у запомненного B →\n{out}");
                        session.close().await;
                        Ok(())
                    }
                    None => {
                        let ticket = ticket.ok_or_else(|| {
                            anyhow::anyhow!("укажи код-приглашение или --resume")
                        })?;
                        micromanager::net::run_connect(&ticket, &path).await
                    }
                },
                Some(task) => {
                    let session = match resumed {
                        Some(s) => s,
                        None => {
                            let ticket = ticket.ok_or_else(|| {
                                anyhow::anyhow!("укажи код-приглашение или --resume")
                            })?;
                            micromanager::net::McpSession::connect(&ticket).await?
                        }
                    };
                    let tools = session.list_tools_full().await?;
                    let specs = tools.iter().map(micromanager::net::map_tool).collect();
                    let runner = micromanager::net::McpToolRunner::start(session, specs);
                    let h = runner.handle();
                    let answer = tokio::task::spawn_blocking(move || -> anyhow::Result<String> {
                        // Локальный A-мозг (с routing-fallback, если включён) рулит тулами B.
                        let brain = build_cli_brain(provider, model);
                        eprintln!("[connect --nl] тулы B исполняются под вето владельца B");
                        let mut msgs = micromanager::brain::new_conversation();
                        msgs.push(micromanager::brain::Message::user(&task));
                        micromanager::brain::run_agent_with(
                            &*brain,
                            &h,
                            &mut msgs,
                            &std::sync::atomic::AtomicBool::new(false),
                        )
                    })
                    .await??;
                    println!("{answer}");
                    tokio::task::spawn_blocking(move || runner.shutdown()).await.ok();
                    Ok(())
                }
            }
        }
        Command::Tui {
            model,
            allow_path,
            no_shell,
            allow_dangerous,
        } => {
            let mut settings = micromanager::tui::Settings::default();
            if let Some(m) = model {
                settings.model = m;
            }
            settings.allowed_path = allow_path;
            settings.allow_shell = !no_shell;
            settings.allow_dangerous = allow_dangerous;
            // run синхронен и владеет терминалом → off the async reactor.
            // .await? снимает JoinError, оставляя Result<()> (как у других веток match).
            tokio::task::spawn_blocking(move || micromanager::tui::run(settings)).await?
        }
        Command::Forget { who, all } => {
            let prefix = if all {
                None
            } else {
                Some(who.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("укажи <id-префикс> кого забыть, или --all для всех")
                })?)
            };
            let (on_a, on_b) = micromanager::net::forget(prefix);
            println!(
                "Забыто: запомненных B (как A)={on_a}; друзей в allowlist (как B)={on_b}"
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Оба теста изменяют env: держим их в одном модуле и сериализуем через Mutex
    // (без внешнего crate serial_test — только std).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn resolve_openai_defaults_to_openrouter_base() {
        // Без MM_BASE_URL openai → база OpenRouter; модель из аргумента.
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("MM_BASE_URL");
        let (p, host, model, _key) =
            resolve_brain_cfg(micromanager::brain::Provider::OpenAi, Some("z-ai/glm-4.6".into()));
        assert_eq!(p, micromanager::brain::Provider::OpenAi);
        assert!(host.contains("openrouter.ai"), "host={host}");
        assert_eq!(model, "z-ai/glm-4.6");
    }

    #[test]
    fn resolve_ollama_uses_local_host_default() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("OLLAMA_HOST");
        std::env::remove_var("MM_BASE_URL");
        let (_p, host, _model, _key) =
            resolve_brain_cfg(micromanager::brain::Provider::Ollama, None);
        assert!(host.contains("11434"), "host={host}");
    }

    #[test]
    fn choose_brain_source_routes_only_when_config_routing_active() {
        use micromanager::brain::{BrainProfile, Provider};
        use micromanager::tui::Settings;
        // нет конфига → флаги/env (как раньше)
        assert!(matches!(choose_brain_source(None), BrainChoice::FromFlags));
        // конфиг есть, routing выкл → флаги
        assert!(matches!(
            choose_brain_source(Some(&Settings::default())),
            BrainChoice::FromFlags
        ));
        // routing вкл + полный fallback → роутер из конфига
        let on = Settings {
            routing: true,
            fallback: BrainProfile {
                provider: Provider::OpenAi,
                host: "https://openrouter.ai/api/v1".into(),
                model: "m".into(),
                api_key: Some("k".into()),
            },
            ..Default::default()
        };
        assert!(matches!(choose_brain_source(Some(&on)), BrainChoice::Routed));
        // routing вкл, но fallback пуст → флаги (не уводим на нерабочий fallback)
        let on_empty = Settings {
            routing: true,
            ..Default::default()
        };
        assert!(matches!(
            choose_brain_source(Some(&on_empty)),
            BrainChoice::FromFlags
        ));
    }

    #[test]
    fn parse_provider_known_values() {
        use micromanager::brain::Provider;
        assert_eq!(parse_provider("ollama"), Ok(Provider::Ollama));
        assert_eq!(parse_provider("openai"), Ok(Provider::OpenAi));
        assert_eq!(parse_provider("openrouter"), Ok(Provider::OpenAi));
        assert_eq!(parse_provider("OLLAMA"), Ok(Provider::Ollama)); // case-insensitive
        assert_eq!(parse_provider("OPENAI"), Ok(Provider::OpenAi));
    }

    #[test]
    fn parse_provider_unknown_returns_error() {
        let err = parse_provider("gemini").unwrap_err();
        assert!(err.contains("неизвестный провайдер"), "err={err}");
        assert!(err.contains("gemini"), "err={err}");
        assert!(err.contains("ollama"), "err={err}");
    }

    #[test]
    fn menu_one_based_input_to_zero_based_index() {
        assert_eq!(parse_menu_choice("1", 2), Some(0)); // «1» → первая
        assert_eq!(parse_menu_choice("2", 2), Some(1)); // «2» → вторая
    }

    #[test]
    fn menu_out_of_range_and_garbage_are_none() {
        assert_eq!(parse_menu_choice("3", 2), None);   // вне диапазона
        assert_eq!(parse_menu_choice("0", 2), None);   // 0 невалиден (1-based)
        assert_eq!(parse_menu_choice("abc", 2), None); // не число
        assert_eq!(parse_menu_choice("", 2), None);    // пусто
    }
}
