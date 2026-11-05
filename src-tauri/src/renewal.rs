//! 证书自动续期的后台调度。
//!
//! 设计取舍：
//! - **进程内定时器**：每 6 小时检查一次，启动时立即检查一次。桌面应用退出后不再续期，
//!   这是已知限制（界面有说明），没有注册系统计划任务 —— 那会带来提权与卸载残留问题。
//! - **串行执行**：续期要写 DNS、等传播，并发跑多张只会在同一域名下互相干扰，
//!   而且会把 CA 的频率额度一起打满。
//! - **失败退避**：失败后写回 `last_attempt_at`，12 小时内不再重试（判定在
//!   `qqhu_acme::renewal`，纯逻辑可单测）。

use crate::commands::{acme_store, acme_vault};
use chrono::{DateTime, SecondsFormat, Utc};
use qqhu_acme::renewal::{CHECK_INTERVAL_SECS, LEAD_DAYS};
use qqhu_acme::AcmeCertMeta;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, Manager};

/// 续期进度事件名。
pub const RENEW_EVENT: &str = "acme-renew";

/// 一条续期进度（与手动签发的 `acme-progress` 分开，便于界面着色）。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenewEvent {
    pub id: String,
    pub domain: String,
    pub stage: String,
    pub message: String,
    /// 仅开始与结束时给出
    pub ok: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DueCert {
    pub id: String,
    pub domain: String,
    pub days_remaining: i64,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenewalStatus {
    /// 正在执行续期
    pub checking: bool,
    pub last_check: Option<String>,
    pub next_check: Option<String>,
    /// 凭据存放后端（系统凭据管理器 / 本地文件）
    pub vault_backend: String,
    /// 到期前多少天开始续期
    pub lead_days: i64,
    /// 当前满足续期条件、等待执行的证书
    pub due: Vec<DueCert>,
}

/// 全局调度状态。放在 Tauri 的 manage 里，命令与后台任务共享。
#[derive(Default)]
pub struct RenewalState {
    running: AtomicBool,
    last_check: Mutex<Option<DateTime<Utc>>>,
    next_check: Mutex<Option<DateTime<Utc>>>,
}

impl RenewalState {
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn set_running(&self, value: bool) {
        self.running.store(value, Ordering::SeqCst);
    }

    fn mark_checked(&self, now: DateTime<Utc>) {
        if let Ok(mut slot) = self.last_check.lock() {
            *slot = Some(now);
        }
        if let Ok(mut slot) = self.next_check.lock() {
            *slot = Some(now + chrono::Duration::seconds(CHECK_INTERVAL_SECS as i64));
        }
    }

    fn mark_scheduled(&self, at: DateTime<Utc>) {
        if let Ok(mut slot) = self.next_check.lock() {
            *slot = Some(at);
        }
    }
}

fn iso(t: Option<DateTime<Utc>>) -> Option<String> {
    t.map(|v| v.to_rfc3339_opts(SecondsFormat::Secs, true))
}

/// 计算当前该续期的证书（只判定，不执行）。
pub fn due_certs(now: DateTime<Utc>) -> Vec<AcmeCertMeta> {
    acme_store()
        .list()
        .into_iter()
        .filter(|m| qqhu_acme::renewal::is_due(m, now, LEAD_DAYS))
        .collect()
}

/// 启动后台循环。应用启动时调用一次。
pub fn spawn(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            run_check(&app).await;
            let next = Utc::now() + chrono::Duration::seconds(CHECK_INTERVAL_SECS as i64);
            if let Some(state) = app.try_state::<RenewalState>() {
                state.mark_scheduled(next);
            }
            tokio::time::sleep(std::time::Duration::from_secs(CHECK_INTERVAL_SECS)).await;
        }
    });
}

/// 立即检查一轮。已经开始运行时不重复进入。
pub async fn run_check(app: &AppHandle) {
    let Some(state) = app.try_state::<RenewalState>() else {
        return;
    };
    if state.running.swap(true, Ordering::SeqCst) {
        return;
    }
    // 用 guard 保证任何提前 return 都能复位标志
    struct Guard<'a>(&'a RenewalState);
    impl Drop for Guard<'_> {
        fn drop(&mut self) {
            self.0.set_running(false);
        }
    }
    let _guard = Guard(&state);

    let store = acme_store();
    let vault = acme_vault();
    let now = Utc::now();
    let due = due_certs(now);

    if due.is_empty() {
        state.mark_checked(now);
        let _ = app.emit(RENEW_EVENT, RenewEvent {
            id: String::new(),
            domain: String::new(),
            stage: "idle".into(),
            message: "没有需要续期的证书".into(),
            ok: None,
        });
        return;
    }

    for meta in due {
        let domain = meta.primary_domain.clone();
        let _ = app.emit(RENEW_EVENT, RenewEvent {
            id: meta.id.clone(),
            domain: domain.clone(),
            stage: "start".into(),
            message: format!("{domain} 剩余 {} 天，开始续期", meta.days_remaining),
            ok: None,
        });

        let credentials = match vault.load(&meta.id) {
            Ok(Some(c)) => c,
            Ok(None) => {
                // 开了自动续期却没有凭据：多半是换机或清理过凭据管理器
                fail(&store, &meta, "未找到该证书的 DNS 凭据，请重新填写 AccessKey 后再启用自动续期");
                let _ = app.emit(RENEW_EVENT, RenewEvent {
                    id: meta.id.clone(),
                    domain,
                    stage: "error".into(),
                    message: "缺少 DNS 凭据，已跳过".into(),
                    ok: Some(false),
                });
                continue;
            }
            Err(e) => {
                fail(&store, &meta, &format!("读取凭据失败：{e}"));
                let _ = app.emit(RENEW_EVENT, RenewEvent {
                    id: meta.id.clone(),
                    domain,
                    stage: "error".into(),
                    message: format!("读取凭据失败：{e}"),
                    ok: Some(false),
                });
                continue;
            }
        };

        let id = meta.id.clone();
        let handle = app.clone();
        let cb = move |p: qqhu_acme::issue::IssueProgress| {
            let _ = handle.emit(RENEW_EVENT, RenewEvent {
                id: id.clone(),
                domain: String::new(),
                stage: p.stage,
                message: p.message,
                ok: None,
            });
        };

        match qqhu_acme::issue::renew(&meta, credentials, &store, &cb).await {
            Ok(next) => {
                let _ = app.emit(RENEW_EVENT, RenewEvent {
                    id: next.id.clone(),
                    domain: domain.clone(),
                    stage: "done".into(),
                    message: format!(
                        "{domain} 续期成功，新有效期至 {}",
                        next.not_after.format("%Y-%m-%d")
                    ),
                    ok: Some(true),
                });
            }
            Err(e) => {
                let msg = e.to_string();
                fail(&store, &meta, &msg);
                let _ = app.emit(RENEW_EVENT, RenewEvent {
                    id: meta.id.clone(),
                    domain,
                    stage: "error".into(),
                    message: msg,
                    ok: Some(false),
                });
            }
        }

        state.mark_checked(Utc::now());
    }
    state.mark_checked(Utc::now());
}

/// 记录失败：写回原因与尝试时间，作为退避依据。
fn fail(store: &qqhu_acme::AcmeStore, meta: &AcmeCertMeta, message: &str) {
    let mut m = store.get(&meta.id).unwrap_or_else(|| meta.clone());
    m.last_error = Some(message.to_string());
    m.last_attempt_at = Some(Utc::now());
    let _ = store.update_meta(&m);
}

/// 状态快照，供界面展示。
pub fn status(state: &RenewalState) -> RenewalStatus {
    let now = Utc::now();
    RenewalStatus {
        checking: state.is_running(),
        last_check: iso(state.last_check.lock().ok().and_then(|v| *v)),
        next_check: iso(state.next_check.lock().ok().and_then(|v| *v)),
        vault_backend: acme_vault().backend().to_string(),
        lead_days: LEAD_DAYS,
        due: due_certs(now)
            .into_iter()
            .map(|m| DueCert {
                id: m.id,
                domain: m.primary_domain,
                days_remaining: m.days_remaining,
                last_error: m.last_error,
            })
            .collect(),
    }
}
