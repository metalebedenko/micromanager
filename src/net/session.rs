//! Удалённая сессия: владелец B видит поток действий A и ветирует мутации.
//! В режиме listen stdin B свободен (MCP едет по iroh), поэтому confirm на терминале B работает.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use iroh::endpoint::{RecvStream, SendStream};
use rmcp::ServiceExt;

use crate::audit::{Audit, AuditEntry, FileAudit};
use crate::safety::{Action, Confirmer, Policy};
use crate::server::tools::HandsServer;

/// Capability-грант для удалённой сессии: scoped-политика + TTL.
#[derive(Clone, Default)]
pub struct Grant {
    pub policy: Policy,
    pub ttl: Option<Duration>,
}

fn short(label: &str) -> String {
    label.chars().take(12).collect()
}

/// Подтверждение мутаций владельцем B (на его терминале), с пометкой удалённого источника.
/// «Доверие на сессию» (ответ `a`) — чтобы не жать «да» на каждый шаг долгой настройки.
#[derive(Default)]
pub struct RemoteConfirmer {
    pub label: String,
    trusted: std::sync::atomic::AtomicBool,
}

impl RemoteConfirmer {
    pub fn new(label: String) -> Self {
        Self {
            label,
            trusted: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

fn what(action: &Action) -> String {
    action
        .command
        .clone()
        .or_else(|| action.path.as_ref().map(|p| p.to_string_lossy().into_owned()))
        .unwrap_or_default()
}

fn read_line_lower() -> Option<String> {
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return None;
    }
    Some(line.trim().to_ascii_lowercase())
}

impl Confirmer for RemoteConfirmer {
    fn confirm(&self, action: &Action) -> bool {
        use std::io::Write;
        use std::sync::atomic::Ordering;
        if self.trusted.load(Ordering::SeqCst) {
            return true; // доверие на сессию
        }
        eprint!(
            "\n[micromanager] ⚠ УДАЛЁННЫЙ {} запрашивает {:?}: «{}»\n  РАЗРЕШИТЬ? [y]es / [a]ll(на сессию) / [N]o ",
            short(&self.label),
            action.kind,
            what(action)
        );
        let _ = std::io::stderr().flush();
        match read_line_lower() {
            None => false,
            Some(ans) => match ans.as_str() {
                "a" | "all" | "все" | "всё" => {
                    self.trusted.store(true, Ordering::SeqCst);
                    eprintln!("[micromanager] доверие на сессию включено для {}", short(&self.label));
                    true
                }
                "y" | "yes" | "да" => true,
                _ => false,
            },
        }
    }

    fn confirm_dangerous(&self, action: &Action, reason: &str) -> bool {
        use std::io::Write;
        // катастрофичное — всегда отдельный громкий запрос, доверие на сессию НЕ покрывает
        eprint!(
            "\n[micromanager] ‼ УДАЛЁННЫЙ {} запрашивает ОПАСНОЕ ({reason}): {:?} «{}»\n  Это НЕОБРАТИМО. Подтвердить? [yes-точно/N] ",
            short(&self.label),
            action.kind,
            what(action)
        );
        let _ = std::io::stderr().flush();
        matches!(read_line_lower().as_deref(), Some("yes-точно"))
    }
}

/// Журнал, который ещё и стримит действия в терминал владельца B (поверх файла).
pub struct TeeAudit {
    inner: FileAudit,
    label: String,
}

impl TeeAudit {
    pub fn new(inner: FileAudit, label: String) -> Self {
        Self { inner, label }
    }
}

impl Audit for TeeAudit {
    fn record(&self, e: &AuditEntry) -> std::io::Result<()> {
        let verdict = if e.verdict.is_empty() {
            String::new()
        } else {
            format!(" [{}]", e.verdict)
        };
        let tail = if e.result.is_empty() {
            String::new()
        } else {
            format!(" → {}", e.result)
        };
        eprintln!("[поток {}] {} {}{}{}", short(&self.label), e.kind, e.action, verdict, tail);
        // fail-closed зависит от записи в файл — её результат и возвращаем
        self.inner.record(e)
    }
}

/// Куда дублировать отчёты владельцу B в Telegram: sink + его chat_id.
pub type ReportTo = (Arc<dyn crate::tg::ReportSink>, i64);

/// Обслужить удалённую сессию A под грантом: scoped-руки + вето владельца +
/// стрим в его терминал (+ опц. в его Telegram) + TTL.
pub async fn serve_hands(
    recv: RecvStream,
    send: SendStream,
    remote_label: String,
    grant: Grant,
    report: Option<ReportTo>,
) -> Result<()> {
    let confirmer: Arc<dyn Confirmer> = Arc::new(RemoteConfirmer::new(remote_label.clone()));
    let tee = TeeAudit::new(FileAudit::new(crate::audit::default_path()), remote_label);
    let audit: Arc<dyn Audit> = match report {
        Some((sink, chat)) => Arc::new(crate::tg::TelegramReportAudit::new(
            Box::new(tee),
            sink,
            chat,
        )),
        None => Arc::new(tee),
    };
    serve_hands_with(recv, send, String::new(), grant, confirmer, audit).await
}

/// Ядро обслуживания удалённой сессии с ИНЪЕКЦИЕЙ confirmer/audit. Для TUI-монитора
/// («поделиться своим ПК») сюда подаются канальные `ChannelConfirmer`/`ChannelAudit`
/// (поток A и вето идут в панель, не в stdout); headless `serve_hands` подаёт прежние
/// `RemoteConfirmer`(stdin)+`TeeAudit`(eprintln). Логика гейта/вето/TTL — общая.
pub async fn serve_hands_with(
    recv: RecvStream,
    send: SendStream,
    _remote_label: String,
    grant: Grant,
    confirmer: Arc<dyn Confirmer>,
    audit: Arc<dyn Audit>,
) -> Result<()> {
    let server = HandsServer::with(grant.policy, confirmer, audit);
    let fut = async move {
        let service = server.serve((recv, send)).await?;
        service.waiting().await?;
        anyhow::Ok(())
    };
    match grant.ttl {
        Some(d) => match tokio::time::timeout(d, fut).await {
            Ok(r) => r,
            Err(_) => {
                eprintln!("[micromanager] грант истёк (TTL {}s) — сессия закрыта", d.as_secs());
                Ok(())
            }
        },
        None => fut.await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::safety::ActionKind;

    #[test]
    fn tee_audit_writes_to_file_and_preserves_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let good = dir.path().join("a.log");
        let tee = TeeAudit::new(FileAudit::new(&good), "abcdef0123456789".to_string());
        let action = Action {
            kind: ActionKind::Exec,
            path: None,
            command: Some("echo".into()),
        };
        let entry = AuditEntry::decision(&action, &crate::safety::Verdict::Allow);
        tee.record(&entry).unwrap();
        assert!(std::fs::read_to_string(&good).unwrap().contains("Exec"));

        // недоступный путь → record возвращает Err (fail-closed сохранён)
        let bad = dir.path().join("nope").join("b.log");
        let tee_bad = TeeAudit::new(FileAudit::new(&bad), "x".to_string());
        assert!(tee_bad.record(&entry).is_err());
    }

    #[tokio::test]
    async fn serve_hands_with_uses_injected_audit() {
        use crate::audit::{Audit, AuditEntry};
        use crate::net::auth::{client_handshake, server_handshake, Gatekeeper, HandshakeOutcome};
        use crate::net::ALPN;
        use iroh::endpoint::presets;
        use iroh::Endpoint;
        use rmcp::model::CallToolRequestParams;
        use rmcp::ServiceExt;
        use std::sync::Mutex;

        // Recording-audit: складывает kind каждого entry в общий Vec.
        struct RecAudit(Arc<Mutex<Vec<String>>>);
        impl Audit for RecAudit {
            fn record(&self, e: &AuditEntry) -> std::io::Result<()> {
                self.0.lock().unwrap().push(e.kind.clone());
                Ok(())
            }
        }

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("probe.txt"), "x").unwrap();
        let secret = "s";
        let log = Arc::new(Mutex::new(Vec::<String>::new()));
        let log_b = log.clone();

        let b = Endpoint::builder(presets::Minimal)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let b_addr = b.addr();
        let gk = Arc::new(Gatekeeper::new(secret));
        let b_task = tokio::spawn(async move {
            let conn = b.accept().await.unwrap().await.unwrap();
            let remote = conn.remote_id();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            server_handshake(&mut recv, &mut send, &gk, remote, &Default::default())
                .await
                .unwrap();
            let confirmer: Arc<dyn crate::safety::Confirmer> = Arc::new(crate::safety::DenyConfirmer);
            let audit: Arc<dyn Audit> = Arc::new(RecAudit(log_b));
            serve_hands_with(recv, send, format!("{remote}"), Grant::default(), confirmer, audit)
                .await
                .ok();
        });

        let a = Endpoint::bind(presets::Minimal).await.unwrap();
        let conn = a.connect(b_addr, ALPN).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        assert!(matches!(
            client_handshake(&mut send, &mut recv, secret).await.unwrap(),
            HandshakeOutcome::Ok(_)
        ));
        let client = ().serve((recv, send)).await.unwrap();
        let mut param = CallToolRequestParams::new("list_dir");
        param.arguments = serde_json::json!({ "path": dir.path().to_string_lossy() })
            .as_object()
            .cloned();
        let _ = client.peer().call_tool(param).await.unwrap();
        client.cancel().await.ok();
        a.close().await;
        b_task.abort();

        // list_dir (Allow) → инъектированный audit получил хотя бы одну запись.
        assert!(
            !log.lock().unwrap().is_empty(),
            "инъектированный audit должен получить записи"
        );
    }
}
