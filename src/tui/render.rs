//! Презентация: чистая `draw(frame, &App)`, оформленная темой. Тест через ratatui TestBackend.

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::tui::app::{App, ChatRole, Focus};
use crate::tui::theme;

/// Полная отрисовка кадра.
pub fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // статус-бар
            Constraint::Min(3),    // тело (чат | активность)
            Constraint::Length(5), // ввод (≈3 строки + рамки)
        ])
        .split(area);

    draw_status(frame, rows[0], app);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
        .split(rows[1]);
    draw_chat(frame, body[0], app);
    draw_activity(frame, body[1], app);
    draw_input(frame, rows[2], app);

    match app.focus {
        Focus::Confirm => draw_confirm(frame, area, app),
        Focus::Settings => draw_settings(frame, area, app),
        Focus::Help => draw_help(frame, area),
        Focus::Chat => {}
        // Remote-экран рендерится поверх основного layout отдельной панелью.
        Focus::Remote => draw_remote(frame, area, app),
        // Share-экран («поделиться своим ПК») — полноэкранный рендер.
        Focus::Share => draw_share(frame, area, app),
        // Оверлей выбора чата — поверх базового чат-layout.
        Focus::Chats => draw_chats_menu(frame, area, app),
    }
}

/// Оверлей-меню чатов: список с маркером активного (*), курсором (›) и ⏳ у думающего.
fn draw_chats_menu(frame: &mut Frame, area: Rect, app: &App) {
    let popup = centered(area, 60, 60);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::border(true))
        .title(Span::styled(
            " Чаты (n новый · d удалить · Enter выбрать · Esc) ",
            theme::accent(),
        ));
    let lines: Vec<Line> = app
        .chats
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let marker = if i == app.chats_cursor { "› " } else { "  " };
            let active = if i == app.active { "*" } else { " " };
            let thinking = if app.running_chat == Some(i) { " ⏳" } else { "" };
            let title = if c.title.is_empty() { "Новый чат" } else { c.title.as_str() };
            let style = if i == app.chats_cursor {
                theme::accent()
            } else {
                Style::default().fg(theme::FG)
            };
            Line::from(Span::styled(
                format!("{marker}{active} {}. {title}{thinking}", i + 1),
                style,
            ))
        })
        .collect();
    frame.render_widget(Paragraph::new(lines).block(block), popup);
}

/// Экран «поделиться своим ПК»: код-приглашение + грант + подключённые A,
/// панель действий (поток A с меткой `A→` и свои `!`-команды), поле ввода.
fn draw_share(frame: &mut Frame, area: Rect, app: &App) {
    frame.render_widget(Clear, area); // перекрыть нижележащий чат-layout
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6), // шапка: код + грант + peers
            Constraint::Min(3),    // поток действий
            Constraint::Length(3), // поле `!`-ввода
        ])
        .split(area);

    let fg = Style::default().fg(theme::FG);
    let g = &app.share.grant;
    let code = app
        .share
        .invite_code
        .clone()
        .unwrap_or_else(|| "поднимаю эндпоинт…".into());
    let paths = if g.allowed_paths.is_empty() {
        "весь диск".to_string()
    } else {
        g.allowed_paths.join(", ")
    };
    let ttl = g.ttl_secs.map(|s| format!("{s}с")).unwrap_or_else(|| "∞".into());
    let peers = if app.share.peers.is_empty() {
        "нет".to_string()
    } else {
        app.share.peers.join(", ")
    };
    let mut lines = vec![
        Line::from(vec![
            Span::styled("код другу A: ", theme::dim()),
            Span::styled(code, Style::default().fg(theme::MATRIX_GREEN)),
        ]),
        Line::from(vec![
            Span::styled("грант: ", theme::dim()),
            Span::styled(
                format!(
                    "пути={paths}  shell={}  опасные={}  TTL={ttl}",
                    if g.allow_shell { "ON" } else { "off" },
                    if g.allow_dangerous { "ON" } else { "off" },
                ),
                fg,
            ),
        ]),
        Line::from(vec![
            Span::styled("подключены: ", theme::dim()),
            Span::styled(peers, fg),
        ]),
    ];
    if let Some(e) = &app.share.error {
        lines.push(Line::from(Span::styled(
            format!("ОШИБКА: {e}"),
            Style::default().fg(theme::GLITCH_RED),
        )));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(theme::accent())
                    .title(Span::styled(" ▓ Поделиться своим ПК ▓ ", theme::accent())),
            )
            .wrap(Wrap { trim: false }),
        rows[0],
    );

    draw_activity(frame, rows[1], app);

    let (_, scc) = app.input.cursor_line_col();
    let share_body = input_lines_with_cursor(app.input.as_str(), 0, scc, theme::accent())
        .into_iter()
        .next()
        .unwrap_or_else(|| Line::from(""));
    let mut share_spans = vec![Span::styled("! ", theme::accent())];
    share_spans.extend(share_body.spans);
    frame.render_widget(
        Paragraph::new(Line::from(share_spans)).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::accent())
                .title(Span::styled(
                    " команда на свою машину · Esc — стоп ",
                    theme::dim(),
                )),
        ),
        rows[2],
    );

    // Вето-модалка поверх (та же, что в чате).
    if app.pending.is_some() {
        draw_confirm(frame, area, app);
    }
}

fn draw_status(frame: &mut Frame, area: Rect, app: &App) {
    let (mark, label) = if app.running {
        ("●", "работает")
    } else {
        ("○", "готов")
    };
    // память = число реплик диалога (user+agent), которые помнит мозг
    let mem = app
        .chat()
        .iter()
        .filter(|l| matches!(l.role, ChatRole::User | ChatRole::Agent))
        .count();
    let remote_marker = if app.remote.as_ref().is_some_and(|r| matches!(r.status, crate::tui::app::RemoteStatus::Connected)) {
        "  ·  →B"
    } else {
        ""
    };
    let text = format!(
        " micromanager  {mark} {label}  ·  {}  ·  память:{mem}{remote_marker}  ·  ?:справка  ·  Ctrl-C:выход ",
        app.settings.model
    );
    frame.render_widget(
        Paragraph::new(text).style(theme::accent().add_modifier(Modifier::REVERSED)),
        area,
    );
}

fn draw_help(frame: &mut Frame, area: Rect) {
    let modal = centered(area, 70, 70);
    let fg = Style::default().fg(theme::FG);
    let key = |k: &str, d: &str| -> Line<'static> {
        Line::from(vec![
            Span::styled(format!("  {k:<18}"), theme::accent()),
            Span::styled(d.to_string(), fg),
        ])
    };
    let body = Text::from(vec![
        Line::from(""),
        key("Enter", "отправить сообщение"),
        key("!ls / !sh …", "прямая команда руками (без мозга)"),
        key("Alt+Enter", "перенос строки"),
        key("↑ / ↓", "история отправленных"),
        key("PgUp/PgDn, колесо", "скролл чата"),
        key("Ctrl-L", "очистить текущий чат (сбросить память)"),
        key("Ctrl-T", "чаты: список, новый (n), удалить (d), выбрать"),
        key("Esc", "отмена текущей задачи"),
        key("s", "настройки (провайдер, модель, хост, ключ, путь)"),
        key("g", "подключиться к чужому ПК (управлять другом)"),
        key("p", "поделиться своим ПК (owner-монитор)"),
        key("?", "эта справка"),
        key("Ctrl-C", "выход"),
        Line::from(""),
        Line::from(Span::styled(
            "  Память = весь диалог; все чаты хранятся в sessions.json",
            theme::dim(),
        )),
        Line::from(Span::styled(
            "  и восстанавливаются при следующем запуске.",
            theme::dim(),
        )),
        Line::from(""),
        Line::from(Span::styled("  Esc — закрыть", theme::dim())),
    ]);
    frame.render_widget(Clear, modal);
    frame.render_widget(
        Paragraph::new(body)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(theme::accent())
                    .title(Span::styled(" ▓ Справка ▓ ", theme::accent())),
            )
            .wrap(Wrap { trim: false }),
        modal,
    );
}

fn draw_chat(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::border(app.focus == Focus::Chat))
        .title(Span::styled(" Чат ", theme::accent()));

    // Пустой чат → сплэш: логотип + хинт по центру.
    if app.chat().is_empty() {
        let mut lines: Vec<Line> = theme::LOGO
            .trim_matches('\n')
            .lines()
            .map(|l| Line::from(Span::styled(l.to_string(), theme::accent())))
            .collect();
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Опиши задачу и нажми Enter   ·   !ls /путь — команда руками без мозга",
            Style::default().fg(theme::FG),
        )));
        lines.push(Line::from(Span::styled(
            "? — справка   ·   s — настройки   ·   Ctrl-C — выход",
            theme::dim(),
        )));
        frame.render_widget(
            Paragraph::new(lines).block(block).alignment(Alignment::Center),
            area,
        );
        return;
    }

    let lines: Vec<Line> = app
        .chat()
        .iter()
        .map(|l| {
            let (prefix, style) = match l.role {
                ChatRole::User => ("вы › ", theme::dim()),
                ChatRole::Agent => ("agent › ", theme::accent()),
                ChatRole::System => ("· ", Style::default().fg(theme::AMBER)),
            };
            Line::from(vec![
                Span::styled(prefix, style),
                Span::styled(l.text.clone(), Style::default().fg(theme::FG)),
            ])
        })
        .collect();
    let para = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
    // реальное число строк ПОСЛЕ переноса (line_count учитывает wrap; вычитаем 2 рамки блока)
    let inner_w = area.width.saturating_sub(2);
    let inner_h = area.height.saturating_sub(2);
    let total_rows = (para.line_count(inner_w) as u16).saturating_sub(2);
    let max_top = total_rows.saturating_sub(inner_h);
    app.chat_max_scroll.set(max_top); // редьюсер клампит PgUp по этому максимуму
    // top=0 при chat_scroll>=max_top → прилипание к низу (свежий текст виден)
    let top = max_top.saturating_sub(app.chat_scroll());
    frame.render_widget(para.scroll((top, 0)), area);
}

fn draw_activity(frame: &mut Frame, area: Rect, app: &App) {
    let cap = area.height.saturating_sub(2) as usize;
    let start = app.activity.len().saturating_sub(cap.max(1));
    let lines: Vec<Line> = app.activity[start..]
        .iter()
        .map(|s| Line::from(Span::styled(s.clone(), theme::activity_style(s))))
        .collect();
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(theme::dim())
                    .title(Span::styled(" Действия ", theme::accent())),
            )
            .wrap(Wrap { trim: true }),
        area,
    );
}

/// Строки Paragraph с видимым курсором (reverse-video) в позиции (cursor_line, cursor_col).
/// Курсор — инвертированный символ под ним; в конце строки — инвертированный пробел.
fn input_lines_with_cursor(
    text: &str,
    cursor_line: usize,
    cursor_col: usize,
    base: Style,
) -> Vec<Line<'static>> {
    let cursor_style = base.add_modifier(Modifier::REVERSED);
    let mut out = Vec::new();
    for (li, line) in text.split('\n').enumerate() {
        if li != cursor_line {
            out.push(Line::from(Span::styled(line.to_string(), base)));
            continue;
        }
        let chars: Vec<char> = line.chars().collect();
        let col = cursor_col.min(chars.len());
        let before: String = chars[..col].iter().collect();
        let (at, after): (String, String) = if col < chars.len() {
            (chars[col].to_string(), chars[col + 1..].iter().collect())
        } else {
            (" ".to_string(), String::new())
        };
        out.push(Line::from(vec![
            Span::styled(before, base),
            Span::styled(at, cursor_style),
            Span::styled(after, base),
        ]));
    }
    out
}

fn draw_input(frame: &mut Frame, area: Rect, app: &App) {
    let lines: Vec<Line> = if app.input.is_empty() {
        vec![Line::from(Span::styled(
            "Опиши задачу…  (Enter — отправить, Alt+Enter — перенос)",
            theme::dim(),
        ))]
    } else {
        let (cl, cc) = app.input.cursor_line_col();
        input_lines_with_cursor(app.input.as_str(), cl, cc, Style::default().fg(theme::FG))
    };
    let para = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::border(app.focus == Focus::Chat))
                .title(Span::styled(" Сообщение ", theme::accent())),
        )
        .wrap(Wrap { trim: false });
    // авто-прокрутка к низу: текущая (последняя) строка ввода всегда видна
    let inner_w = area.width.saturating_sub(2);
    let inner_h = area.height.saturating_sub(2);
    let total = (para.line_count(inner_w) as u16).saturating_sub(2);
    let off = total.saturating_sub(inner_h);
    frame.render_widget(para.scroll((off, 0)), area);
}

fn draw_remote(frame: &mut Frame, area: Rect, app: &App) {
    use crate::tui::app::RemoteStatus;
    let modal = centered(area, 80, 80);
    let fg = Style::default().fg(theme::FG);

    let status_line = match &app.remote {
        Some(r) => match &r.status {
            RemoteStatus::Connecting => Span::styled("● подключаемся…", theme::dim()),
            RemoteStatus::Connected => Span::styled(
                format!("✓ подключён: {}", r.host_label),
                Style::default().fg(theme::MATRIX_GREEN),
            ),
            RemoteStatus::Error(e) => Span::styled(
                format!("✗ ошибка: {e}"),
                Style::default().fg(theme::GLITCH_RED),
            ),
        },
        None => Span::styled("нет активного подключения", theme::dim()),
    };

    let (_, cc) = app.remote_code_input.cursor_line_col();
    let code_line = input_lines_with_cursor(
        app.remote_code_input.as_str(),
        0,
        cc,
        Style::default().fg(theme::MATRIX_GREEN),
    )
    .into_iter()
    .next()
    .unwrap_or_else(|| Line::from(""));
    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled("Код узла (node-id или адрес):", fg)),
        code_line,
        Line::from(""),
        Line::from(status_line),
        Line::from(""),
    ];

    // Grant summary + tools + session time — только когда подключён.
    if let Some(r) = &app.remote {
        if matches!(r.status, RemoteStatus::Connected) {
            let g = &r.grant;

            // Пути
            let paths_str = if g.allowed_paths.is_empty() {
                "весь диск".to_string()
            } else {
                g.allowed_paths.join(", ")
            };
            // TTL: приблизительный обратный отсчёт на стороне A
            let ttl_str = match g.ttl_secs {
                None => "∞".to_string(),
                Some(ttl) => {
                    let elapsed = r.connected_at.elapsed().as_secs();
                    let remaining = ttl.saturating_sub(elapsed);
                    format!("{remaining}с")
                }
            };

            let shell_s = if g.allow_shell { "ON" } else { "off" };
            let danger_s = if g.allow_dangerous { "ON" } else { "off" };

            lines.push(Line::from(vec![
                Span::styled("  пути: ", theme::dim()),
                Span::styled(paths_str, fg),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  shell: ", theme::dim()),
                Span::styled(shell_s.to_string(), fg),
                Span::styled("  опасные: ", theme::dim()),
                Span::styled(danger_s.to_string(), fg),
                Span::styled("  TTL: ", theme::dim()),
                Span::styled(ttl_str, fg),
            ]));
            lines.push(Line::from(""));

            // Tools list
            if !r.tools.is_empty() {
                lines.push(Line::from(Span::styled("  инструменты:", theme::dim())));
                for t in &r.tools {
                    lines.push(Line::from(vec![
                        Span::styled("    • ", theme::dim()),
                        Span::styled(t.clone(), fg),
                    ]));
                }
                lines.push(Line::from(""));
            }

            // Session time
            let secs = r.connected_at.elapsed().as_secs();
            lines.push(Line::from(vec![
                Span::styled("  в сессии: ", theme::dim()),
                Span::styled(format!("{secs}с"), fg),
            ]));
            lines.push(Line::from(""));
        }
    }

    // Host log
    if !app.host_log.is_empty() {
        lines.push(Line::from(Span::styled("  история подключений:", theme::dim())));
        for entry in app.host_log.iter().rev().take(5) {
            // Показываем unix timestamp как читаемое время (просто секунды от эпохи)
            lines.push(Line::from(vec![
                Span::styled("    ", theme::dim()),
                Span::styled(entry.host_label.clone(), fg),
                Span::styled(format!(" (at {})", entry.connected_at_unix), theme::dim()),
            ]));
        }
        lines.push(Line::from(""));
    }

    lines.push(Line::from(Span::styled(
        "Enter — подключить  ·  Ctrl-D — отключить  ·  Esc — назад",
        theme::dim(),
    )));

    frame.render_widget(Clear, modal);
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(theme::accent())
                    .title(Span::styled(" ▓ Удалённый узел ▓ ", theme::accent())),
            )
            .wrap(Wrap { trim: false }),
        modal,
    );
}

fn centered(area: Rect, pct_x: u16, pct_y: u16) -> Rect {
    let v = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - pct_y) / 2),
            Constraint::Percentage(pct_y),
            Constraint::Percentage((100 - pct_y) / 2),
        ])
        .split(area)[1];
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - pct_x) / 2),
            Constraint::Percentage(pct_x),
            Constraint::Percentage((100 - pct_x) / 2),
        ])
        .split(v)[1]
}

fn draw_confirm(frame: &mut Frame, area: Rect, app: &App) {
    let Some(req) = &app.pending else { return };
    let modal = centered(area, 70, 40);
    let (style, title, keys) = if req.dangerous {
        (
            Style::default()
                .fg(theme::GLITCH_RED)
                .add_modifier(Modifier::BOLD),
            " ⚠ ОПАСНО ",
            "y=ВЫПОЛНИТЬ   n/Esc=отказать",
        )
    } else {
        (
            Style::default().fg(theme::AMBER).add_modifier(Modifier::BOLD),
            " Подтверждение ",
            "y=да   a=да+доверять сессии   n/Esc=нет",
        )
    };
    let body = Text::from(vec![
        Line::from(Span::styled(
            req.prompt.clone(),
            Style::default().fg(theme::FG),
        )),
        Line::from(""),
        Line::from(Span::styled(keys, style)),
    ]);
    frame.render_widget(Clear, modal);
    frame.render_widget(
        Paragraph::new(body)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(style)
                    .title(Span::styled(title, style)),
            )
            .wrap(Wrap { trim: false }),
        modal,
    );
}

fn draw_settings(frame: &mut Frame, area: Rect, app: &App) {
    use crate::tui::app::SettingsField;
    let modal = centered(area, 64, 85);
    let s = &app.settings;
    let fg = Style::default().fg(theme::FG);

    // значение поля: если оно сейчас редактируется — показываем буфер с курсором
    let field_val = |f: SettingsField, shown: String| -> Line {
        match &app.settings_edit {
            Some(ed) if ed.field == f => {
                let (_, cc) = ed.buffer.cursor_line_col();
                input_lines_with_cursor(
                    ed.buffer.as_str(),
                    0,
                    cc,
                    Style::default().fg(theme::MATRIX_GREEN),
                )
                .into_iter()
                .next()
                .unwrap_or_else(|| Line::from(""))
            }
            _ => Line::from(Span::styled(shown, fg)),
        }
    };
    let key_shown = match &s.api_key {
        Some(_) => "•••• (задан)".to_string(),
        None => "(не задан)".to_string(),
    };
    let path_shown = s
        .allowed_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "(без ограничения)".into());
    let on = |b: bool| if b { "ON" } else { "off" };
    let provider_label = |p: crate::brain::Provider| match p {
        crate::brain::Provider::Ollama => "ollama (локально / Ollama-cloud)",
        crate::brain::Provider::OpenAi => "openai-совместимый (OpenRouter…)",
    };
    let or_unset = |v: &str| {
        if v.trim().is_empty() {
            "(не задан)".to_string()
        } else {
            v.to_string()
        }
    };
    let fb_key_shown = match &s.fallback.api_key {
        Some(_) => "•••• (задан)".to_string(),
        None => "(не задан)".to_string(),
    };

    let mut lines = vec![
        prefixed("[m] Модель:        ", field_val(SettingsField::Model, s.model.clone())),
        prefixed("[h] Хост/base_url: ", field_val(SettingsField::Host, s.host.clone())),
        prefixed("[k] API-ключ:      ", field_val(SettingsField::ApiKey, key_shown)),
        prefixed("[p] Путь-scope:    ", field_val(SettingsField::Path, path_shown)),
        Line::from(Span::styled(format!("[e] shell:         {}", on(s.allow_shell)), fg)),
        Line::from(Span::styled(
            format!("[d] dangerous:     {}", on(s.allow_dangerous)),
            fg,
        )),
        Line::from(Span::styled(
            format!("[r] провайдер:     {}", provider_label(s.provider)),
            fg,
        )),
        Line::from(""),
        Line::from(Span::styled("── Роутер мозга: local→fallback ──", theme::dim())),
        Line::from(Span::styled(format!("[o] routing:       {}", on(s.routing)), fg)),
        Line::from(Span::styled(
            format!("[b] fb-провайдер:  {}", provider_label(s.fallback.provider)),
            fg,
        )),
        prefixed(
            "[f] fb-хост:       ",
            field_val(SettingsField::FallbackHost, or_unset(&s.fallback.host)),
        ),
        prefixed(
            "[g] fb-модель:     ",
            field_val(SettingsField::FallbackModel, or_unset(&s.fallback.model)),
        ),
        prefixed(
            "[j] fb-ключ:       ",
            field_val(SettingsField::FallbackApiKey, fb_key_shown),
        ),
        Line::from(""),
    ];
    let hint = if app.settings_edit.is_some() {
        "редактирование — Enter: применить · Esc: отмена"
    } else {
        "m/h/k/p/f/g/j — изменить · e/d/r/o/b — переключить · Esc — закрыть"
    };
    lines.push(Line::from(Span::styled(hint, theme::dim())));

    frame.render_widget(Clear, modal);
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(theme::accent())
                    .title(Span::styled(" ▓ Настройки ▓ ", theme::accent())),
            )
            .wrap(Wrap { trim: false }),
        modal,
    );
}

/// Строка «префикс + значение» (значение рендерится отдельно — буфер или текущее).
fn prefixed(prefix: &str, value: Line<'static>) -> Line<'static> {
    let mut spans = vec![Span::styled(
        prefix.to_string(),
        Style::default().fg(theme::FG),
    )];
    spans.extend(value.spans);
    Line::from(spans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::app::{App, Chat, ChatLine, ChatRole, Focus};
    use ratatui::{backend::TestBackend, Terminal};

    fn render(app: &App) -> String {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f, app)).unwrap();
        let buf = terminal.backend().buffer().clone();
        buf.content().iter().map(|c| c.symbol()).collect()
    }

    #[test]
    fn renders_without_panic_on_empty_app() {
        let app = App::new();
        let _ = render(&app); // не паникует
    }

    #[test]
    fn input_shows_reversed_cursor() {
        let mut app = App::new();
        app.input = crate::tui::textinput::TextInput::from("abc");
        app.input.home(); // курсор на 'a'
        let (w, h) = (40u16, 12u16);
        let backend = TestBackend::new(w, h);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();
        let buf = terminal.backend().buffer().clone();
        // курсор ищем ТОЛЬКО в области ввода (нижние 5 строк) — не в статус-баре (он
        // тоже инвертирован и содержит 'a' в "micromanager"/"gemma4").
        let reversed_in_input = buf.content().iter().enumerate().any(|(i, c)| {
            let y = i as u16 / w;
            y >= h - 5 && c.modifier.contains(Modifier::REVERSED) && c.symbol() == "a"
        });
        assert!(reversed_in_input, "ожидалась инвертированная ячейка-курсор на 'a' в поле ввода");
    }

    #[test]
    fn splash_shows_logo_on_empty_chat() {
        let app = App::new(); // чат пуст → сплэш с логотипом
        let screen = render(&app);
        assert!(screen.contains("hands for the machine"));
    }

    #[test]
    fn chats_menu_overlay_lists_and_marks_active() {
        let mut app = App::new();
        app.chats.push(Chat::empty());
        app.active_chat_mut().title = "первый".into(); // title чата 0
        app.active = 0;
        app.chats_cursor = 0;
        app.focus = Focus::Chats;
        let screen = render(&app);
        assert!(screen.contains("Чаты"), "заголовок меню");
        assert!(screen.contains("первый") || screen.contains("Новый чат"), "пункт списка");
    }

    #[test]
    fn share_screen_renders_code_and_peers() {
        let mut app = App::new();
        app.focus = Focus::Share;
        app.share.invite_code = Some("MMCODE42".into());
        app.share.peers = vec!["nodeAAAA".into()];
        let screen = render(&app);
        assert!(screen.contains("MMCODE42"), "должен показать код-приглашение");
        assert!(screen.contains("nodeAAAA"), "должен показать подключённого A");
    }

    #[test]
    fn shows_chat_text() {
        let mut app = App::new();
        app.active_chat_mut().lines.push(ChatLine {
            role: ChatRole::User,
            text: "приветик".into(),
        });
        let screen = render(&app);
        assert!(screen.contains("приветик"));
    }

    #[test]
    fn renders_with_chat_scroll() {
        let mut app = App::new();
        for i in 0..40 {
            app.active_chat_mut().lines.push(ChatLine {
                role: ChatRole::User,
                text: format!("строка {i}"),
            });
        }
        app.active_chat_mut().scroll = 10;
        let _ = render(&app); // не паникует
    }

    // Регрессия: длинные переносящиеся реплики. Со старым (логические строки) кодом
    // total занижался → top упирался в 0 → низ был недостижим. С line_count низ виден.
    #[test]
    fn chat_scroll_reaches_bottom_with_wrapped_lines() {
        let mut app = App::new();
        let long = "слово ".repeat(40); // ~240 симв → каждая реплика переносится на много строк
        for i in 0..10 {
            app.active_chat_mut().lines.push(ChatLine {
                role: ChatRole::Agent,
                text: format!("{long} ZZZ{i}"),
            });
        }
        app.active_chat_mut().scroll = 0; // прилипание к низу
        let screen = render(&app);
        assert!(screen.contains("ZZZ9")); // последняя реплика достижима несмотря на переносы
    }

    #[test]
    fn input_renders_multiline() {
        let mut app = App::new();
        app.input = "первая\nвторая".into();
        let screen = render(&app);
        assert!(screen.contains("первая"));
        assert!(screen.contains("вторая"));
    }

    // Поле ввода авто-прокручивается к низу: текущая (последняя) строка всегда видна,
    // даже если набрано больше, чем влезает в окно ввода (3 строки).
    #[test]
    fn input_scrolls_to_show_latest_line() {
        let mut app = App::new();
        app.input = (0..20)
            .map(|i| format!("строка{i}"))
            .collect::<Vec<_>>()
            .join("\n")
            .into();
        let screen = render(&app);
        assert!(screen.contains("строка19")); // последняя строка ввода видна
    }

    #[test]
    fn help_overlay_lists_keys() {
        let mut app = App::new();
        app.focus = Focus::Help;
        let screen = render(&app);
        assert!(screen.contains("Ctrl-L")); // справка перечисляет горячие клавиши
    }

    #[test]
    fn help_overlay_documents_bang_prefix() {
        let mut app = App::new();
        app.focus = Focus::Help;
        let screen = render(&app);
        // справка объясняет прямые команды без мозга (префикс !)
        assert!(screen.contains("!ls") || screen.contains("! <"));
    }

    #[test]
    fn splash_mentions_bang_prefix() {
        let app = App::new(); // пустой чат → сплэш
        let screen = render(&app);
        assert!(screen.contains('!')); // сплэш подсказывает про прямые команды
    }

    #[test]
    fn status_shows_memory_count() {
        let mut app = App::new();
        app.active_chat_mut().lines.push(ChatLine {
            role: ChatRole::User,
            text: "a".into(),
        });
        app.active_chat_mut().lines.push(ChatLine {
            role: ChatRole::Agent,
            text: "b".into(),
        });
        let screen = render(&app);
        assert!(screen.contains("память:2"));
    }

    #[test]
    fn settings_shows_model_value() {
        let mut app = App::new();
        app.settings.model = "mymodel".into();
        app.focus = Focus::Settings;
        let screen = render(&app);
        assert!(screen.contains("mymodel"));
    }

    #[test]
    fn settings_masks_api_key() {
        let mut app = App::new();
        app.settings.api_key = Some("supersecret".into());
        app.focus = Focus::Settings;
        let screen = render(&app);
        assert!(!screen.contains("supersecret")); // ключ замаскирован
    }

    #[test]
    fn settings_shows_routing_and_masks_fallback_key() {
        let mut app = App::new();
        app.settings.routing = true;
        app.settings.fallback.model = "glm-4.6".into();
        app.settings.fallback.api_key = Some("fbsupersecret".into());
        app.focus = Focus::Settings;
        let screen = render(&app);
        assert!(screen.contains("routing"), "секция роутера видна");
        assert!(screen.contains("glm-4.6"), "модель fallback видна");
        assert!(!screen.contains("fbsupersecret"), "ключ fallback замаскирован");
    }

    #[test]
    fn settings_shows_edit_buffer_when_editing() {
        use crate::tui::app::{Editing, SettingsField};
        let mut app = App::new();
        app.focus = Focus::Settings;
        app.settings_edit = Some(Editing {
            field: SettingsField::Host,
            buffer: "http://cloud".into(),
        });
        let screen = render(&app);
        assert!(screen.contains("http://cloud"));
    }

    #[test]
    fn confirm_modal_shows_prompt() {
        use crate::tui::event::ConfirmRequest;
        use std::sync::mpsc::sync_channel;
        let mut app = App::new();
        let (tx, _rx) = sync_channel::<bool>(1);
        app.pending = Some(ConfirmRequest {
            prompt: "Подтвердить Write: /tmp/x?".into(),
            dangerous: false,
            reply: tx,
            trust: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        });
        app.focus = Focus::Confirm;
        let screen = render(&app);
        assert!(screen.contains("Подтвердить"));
    }

    #[test]
    fn remote_screen_shows_status_grant_tools() {
        let mut app = App::new();
        app.focus = Focus::Remote;
        app.on_event(crate::tui::event::AppEvent::RemoteConnected {
            host: "узел-тест".into(),
            tools: vec!["list_dir".into(), "read_file".into()],
            grant: crate::net::GrantSummary {
                allowed_paths: vec!["/tmp".into()],
                allow_shell: true,
                allow_dangerous: false,
                ttl_secs: Some(300),
            },
            at_unix: 1000,
        });
        let screen = render(&app);
        assert!(screen.contains("узел-тест"), "хост не виден: {}", &screen[..200.min(screen.len())]);
        assert!(screen.contains("list_dir"), "тул не виден");
        assert!(screen.contains("/tmp"), "путь гранта не виден");
        assert!(screen.contains("300") || screen.contains("ttl"), "TTL не виден");
    }

    #[test]
    fn status_bar_shows_remote_indicator_when_connected() {
        let mut app = App::new();
        app.on_event(crate::tui::event::AppEvent::RemoteConnected {
            host: "mynode".into(),
            tools: vec![],
            grant: crate::net::GrantSummary::default(),
            at_unix: 0,
        });
        let screen = render(&app);
        assert!(screen.contains("→B"), "индикатор →B не виден в статус-баре");
    }
}
