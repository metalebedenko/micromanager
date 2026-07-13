# micromanager

**«Руки для LLM»** — лёгкий безопасный кросс-платформенный (Windows / Linux / macOS) execution-endpoint. Один статичный бинарь: безопасно исполняет команды и файловые операции, а интеллект подключается клиентом.

> Принцип: **тонкие руки, сменный мозг.** micromanager — это не ассистент, а исполнительная поверхность под жёстким safety-гейтом. «Мозгом» может быть локальная LLM (Ollama), облачная модель (OpenAI-совместимый API), внешний MCP-клиент или другой человек.

Хребет — **MCP** (Model Context Protocol): micromanager выступает MCP-сервером («руки»), всё остальное — клиенты. Транспорт между машинами — **iroh** (P2P dial-by-key сквозь NAT). Интерфейс — **TUI** на ratatui.

---

## Установка (одна команда)

Готовый статичный бинарь под твою ОС — без Rust и без зависимостей.

**macOS / Linux:**
```bash
curl -fsSL https://raw.githubusercontent.com/metalebedenko/micromanager/main/install.sh | sh
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/metalebedenko/micromanager/main/install.ps1 | iex
```

Скрипт качает бинарь из последнего [релиза](https://github.com/metalebedenko/micromanager/releases/latest) под нужную ОС/архитектуру (macOS arm64/x64, Linux x64, Windows x64), проверяет sha256 и кладёт в `~/.local/bin` (Unix) / `%LOCALAPPDATA%\micromanager\bin` (Windows).

**Из исходников** (любая платформа, нужен [Rust](https://rustup.rs)):
```bash
cargo install --git https://github.com/metalebedenko/micromanager
```

## Команды

```bash
micromanager tui                      # TUI: чат + поток действий + confirm + настройки
micromanager serve                    # MCP-сервер «руки» по stdio (для MCP-клиента)
micromanager agent "<задача>"         # локальный мозг (Ollama) рулит руками естественным языком
micromanager listen [--allow-path …]  # выставить свои «руки» в сеть, выдать код-приглашение
micromanager connect <код>            # подключиться к удалённой машине и вызвать её «руки»
micromanager telegram [--nl]          # управление своим компьютером из Telegram
```

В TUI: `g` — подключиться к удалённой машине по коду, `p` — поделиться своей машиной, `s` — настройки, `?` — справка.

## Удалённое управление

Сценарий «настроить компьютер друга без TeamViewer»: на машине B запускается `listen` (или TUI → `p`), она выдаёт одноразовый код-приглашение. Машина A вводит код (`connect` или TUI → `g`) и получает доступ к «рукам» B. Каждая команда на B проходит **полное вето владельца B** (подтверждение / scope / TTL / hardline). Соединение — прямое P2P по iroh, identity пира криптографически верифицируется.

По умолчанию связка одноразовая. `listen --remember` включает постоянный доступ: B хранит стабильную криптоличность + allowlist спаренных друзей, и друг переподключается без нового кода (`connect --resume`). Отозвать — `forget`.

### MCP API удалённых сессий

`micromanager serve` публикует стабильные, адресуемые по `session_id` инструменты: `session_connect`, `session_status`, `session_journal`, `session_note_append`, `remote_exec`, `operation_status`, `operation_output`, `session_disconnect`. Подключение не меняет список MCP tools.

До версии 1.0 старый relay API удалён с намеренным breaking change:

| Старый tool | Замена |
|---|---|
| `mm_connect` | `session_connect` |
| `mm_remote_tools` | Удалён: список stable tools фиксирован при старте |
| `mm_remote_call` | `remote_exec`, затем `operation_status` / `operation_output` |
| `mm_disconnect` | `session_disconnect` |

## Безопасность

Каждое действие проходит многослойный гейт **до** исполнения:

1. **Anti-bypass-парсер** — разворачивает обёртки-интерпретаторы (`sudo`, `env`, `eval`, `bash -c`, …), бьёт цепочки (`&&`, `|`, `;`, перевод строки), снимает кавычки/escape и извлекает подстановки. Нераспарсиваемое → `Deny` (fail-closed).
2. **Hardline-blocklist** — неперебиваемый список катастрофичных операций (`rm -rf` системных путей, `mkfs`, `dd` на устройство, `format`, `diskpart`, …), *nix и Windows одновременно. Работает по всем сегментам и обёрткам.
3. **Risk-тиры + confirm-гейт** — мутации и команды требуют подтверждения владельца; только read-операции авто-разрешаются.
4. **Path-scope + secret-scoping** — грант ограничивает доступные пути; секрет-подобные файлы (`*.env`, `*.key`, `*secret*`) не отдаются даже на чтение.
5. **Fail-closed audit-log** — каждое решение и результат пишутся в журнал; недоступность журнала для мутации → отказ.

Секреты на диске: iroh-ключ опц. шифруется парольной фразой (`MM_KEY_PASSPHRASE`, argon2id + ChaCha20-Poly1305); файлы состояния — `0600`. API-ключи LLM в конфиге хранятся в открытом виде (для облака предпочтительнее ключ из переменной окружения) и никогда не попадают в логи.

Подробности устройства — [ARCHITECTURE.md](ARCHITECTURE.md).

## Сборка и тесты

```bash
cargo build --release      # → target/release/micromanager
cargo test                 # юнит + интеграционные + регресс-тесты safety
cargo clippy --all-targets
```

## Лицензия

Двойная: [MIT](LICENSE-MIT) или [Apache-2.0](LICENSE-APACHE) — на выбор.
