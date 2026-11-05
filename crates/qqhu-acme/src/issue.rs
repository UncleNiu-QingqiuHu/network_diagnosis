//! ACME 签发流程编排。
//!
//! 顺序刻意做成「先写全部记录、等一次传播、再逐个 set_ready」：
//! 多域名时逐条「写入 → 等待 → 校验」会把等待时间乘以域名数，
//! 而 DNS 记录之间互不影响，完全可以并行准备。

use crate::dns::{DnsClient, TxtRecord};
use crate::model::{parse_leaf, IssueSpec, ValidIssue};
use crate::store::{split_pem, AcmeStore};
use crate::AcmeError;
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, RetryPolicy,
};
use std::time::{Duration, Instant};

/// 进度事件。界面按 `stage` 归类，`message` 直接展示。
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueProgress {
    pub stage: String,
    pub message: String,
}

/// 单个授权检查的最长等待时间。
const AUTH_TIMEOUT: Duration = Duration::from_secs(180);
/// 签发阶段（finalize → 出证书）的最长等待时间。
const CERT_TIMEOUT: Duration = Duration::from_secs(180);

fn emit(cb: &(dyn Fn(IssueProgress) + Send + Sync), stage: &str, message: impl Into<String>) {
    cb(IssueProgress {
        stage: stage.to_string(),
        message: message.into(),
    });
}

/// 完整的签发流程：写入 DNS → 等待生效 → 完成挑战 → 取证书 → 落盘。
///
/// 无论成功失败，已写入的 TXT 记录都会被清理，避免在域名下留下垃圾记录。
pub async fn issue(
    spec: &IssueSpec,
    store: &AcmeStore,
    on_progress: &(dyn Fn(IssueProgress) + Send + Sync),
) -> Result<crate::model::AcmeCertMeta, AcmeError> {
    let valid = spec.validate().map_err(AcmeError::Invalid)?;
    let client = DnsClient::new(valid.provider, valid.credentials.clone())?;

    let mut records: Vec<TxtRecord> = Vec::new();
    let outcome = run(&valid, &client, store, &mut records, on_progress).await;

    if !records.is_empty() {
        emit(on_progress, "cleanup", "清理验证用 TXT 记录…");
        for record in &records {
            if let Err(e) = client.cleanup(record).await {
                // 清理失败不该让整次签发失败，用户自己删也行
                emit(
                    on_progress,
                    "cleanup",
                    format!("记录 {} 未能自动删除：{e}", record.fqdn),
                );
            }
        }
    }
    outcome
}

async fn run(
    valid: &ValidIssue,
    client: &DnsClient,
    store: &AcmeStore,
    records: &mut Vec<TxtRecord>,
    on_progress: &(dyn Fn(IssueProgress) + Send + Sync),
) -> Result<crate::model::AcmeCertMeta, AcmeError> {
    // ---------------- 1. 账户
    let builder = Account::builder().map_err(AcmeError::from)?;
    let account = match store.load_account(&valid.directory_url) {
        Some(creds) => {
            emit(on_progress, "account", "复用已有 ACME 账户");
            builder.from_credentials(creds).await?
        }
        None => {
            emit(on_progress, "account", "创建新的 ACME 账户");
            let (account, creds) = builder
                .create(
                    &NewAccount {
                        contact: &[],
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    valid.directory_url.clone(),
                    None,
                )
                .await?;
            store.save_account(&valid.directory_url, &creds)?;
            account
        }
    };

    // ---------------- 2. 下单
    emit(
        on_progress,
        "order",
        format!("提交证书订单（{} 个域名）", valid.domains.len()),
    );
    let identifiers: Vec<Identifier> = valid
        .domains
        .iter()
        .map(|d| Identifier::Dns(d.clone()))
        .collect();
    let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;

    // ---------------- 3. 写入全部 TXT
    let mut pending: Vec<String> = Vec::new();
    {
        let mut auths = order.authorizations();
        while let Some(handle) = auths.next().await {
            let mut handle = handle?;
            let state = handle.refresh().await?;
            if state.status == AuthorizationStatus::Valid {
                continue; // 之前已通过（比如域名有未过期的授权缓存）
            }
            // 泛域名的授权标识不带 `*.`，这里统一去掉，避免拼出 `*.` 的记录名
            let base = state.identifier().to_string();
            let base = base.trim_start_matches("*.").to_string();
            let fqdn = format!("_acme-challenge.{base}");

            let value = {
                let challenge = handle.challenge(ChallengeType::Dns01).ok_or_else(|| {
                    AcmeError::Acme(format!(
                        "{base} 的授权中没有 DNS-01 挑战，可能被 CA 禁用或不支持该类型。"
                    ))
                })?;
                challenge.key_authorization().dns_value()
            };

            emit(on_progress, "dns", format!("写入 TXT 记录 {fqdn}"));
            let record = client.present(&fqdn, &value).await?;
            records.push(record);
            pending.push(base);
        }
    }

    if !pending.is_empty() {
        // ---------------- 4. 等传播
        emit(
            on_progress,
            "verify",
            format!("等待 DNS 生效（最多 {} 秒）…", valid.dns_wait_secs),
        );
        let timeout = Duration::from_secs(valid.dns_wait_secs);
        for record in records.iter() {
            let ok = crate::propagate::wait_for_txt(&record.fqdn, &record.value, timeout).await;
            if !ok {
                // 查不到也让流程继续：本地 DoH 的缓存可能比 CA 的视角更旧，
                // CA 侧仍有机会验证成功；失败了会给出明确报错。
                emit(
                    on_progress,
                    "verify",
                    format!("公共 DNS 暂未查到 {}，继续交给 CA 验证", record.fqdn),
                );
            }
        }

        // ---------------- 5. 完成挑战
        //
        // 必须分成「通知」与「轮询」两轮：`ChallengeHandle` 借的是
        // `AuthorizationHandle<'a>` 的整个生命周期，拿到挑战后这个句柄就
        // 不能再用了，没法在原地继续 refresh。
        {
            let mut auths = order.authorizations();
            while let Some(handle) = auths.next().await {
                let mut handle = handle?;
                let state = handle.refresh().await?;
                if state.status == AuthorizationStatus::Valid {
                    continue;
                }
                let mut challenge = handle.challenge(ChallengeType::Dns01).ok_or_else(|| {
                    AcmeError::Acme("授权中没有 DNS-01 挑战。".to_string())
                })?;
                challenge.set_ready().await?;
            }
        }

        // ---------------- 5b. 等待校验结果
        let mut auths = order.authorizations();
        while let Some(handle) = auths.next().await {
            let mut handle = handle?;
            let state = handle.refresh().await?;
            if state.status == AuthorizationStatus::Valid {
                continue;
            }
            let base = state.identifier().to_string();
            let base = base.trim_start_matches("*.").to_string();
            emit(on_progress, "challenge", format!("等待 CA 校验 {base}"));

            let deadline = Instant::now() + AUTH_TIMEOUT;
            loop {
                let state = handle.refresh().await?;
                match state.status {
                    AuthorizationStatus::Valid => break,
                    AuthorizationStatus::Invalid => {
                        return Err(AcmeError::Acme(format!(
                            "{base} 的 DNS 验证失败。常见原因：TXT 记录值不对、\
                             记录写到了错误的域名（注意多级子域）、或 DNS 生效太慢。\
                             可在服务商控制台确认 _acme-challenge.{base} 的值。"
                        )))
                    }
                    _ => {
                        if Instant::now() >= deadline {
                            return Err(AcmeError::Acme(format!(
                                "{base} 的验证在 {} 秒内未完成，请稍后重试。",
                                AUTH_TIMEOUT.as_secs()
                            )));
                        }
                        tokio::time::sleep(Duration::from_secs(3)).await;
                    }
                }
            }
        }
    }

    // ---------------- 6. 签发
    emit(on_progress, "finalize", "生成密钥并向 CA 申请证书");
    let key_pem = order.finalize().await?;
    let chain_pem = order
        .poll_certificate(&RetryPolicy::new().timeout(CERT_TIMEOUT))
        .await?;

    // 返回的是「叶子 + 中间证书」，拆开分别落盘
    let blocks = split_pem(&chain_pem);
    if blocks.is_empty() {
        return Err(AcmeError::Cert("CA 未返回有效证书。".into()));
    }
    let cert_pem = blocks[0].clone();

    let facts = parse_leaf(&cert_pem)?;
    let mut meta = crate::model::AcmeCertMeta {
        id: store.next_id(),
        primary_domain: valid.domains[0].clone(),
        domains: valid.domains.clone(),
        directory: valid.directory_url.clone(),
        staging: valid.directory_url.contains("staging"),
        provider: client.label().to_string(),
        serial: facts.serial,
        fingerprint: facts.fingerprint,
        created_at: chrono::Utc::now(),
        not_before: facts.not_before,
        not_after: facts.not_after,
        days_remaining: (facts.not_after - chrono::Utc::now()).num_days(),
    };
    meta.refresh(chrono::Utc::now());

    emit(on_progress, "save", "保存证书与私钥");
    store.save_cert(&meta, &cert_pem, &key_pem, &blocks.join(""))?;
    emit(on_progress, "done", format!("签发完成，有效期至 {}", meta.not_after.format("%Y-%m-%d")));
    Ok(meta)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DnsCredentials, DnsProviderKind};

    fn spec() -> IssueSpec {
        IssueSpec {
            domains: vec!["example.com".into()],
            provider: DnsProviderKind::Aliyun,
            credentials: DnsCredentials {
                access_key_id: "id".into(),
                access_key_secret: "secret".into(),
            },
            staging: true,
            directory_url: None,
            dns_wait_secs: None,
        }
    }

    #[tokio::test]
    async fn rejects_bad_input_before_touching_network() {
        let store = AcmeStore::new(std::env::temp_dir().join("qqhu-acme-issue-test"));
        let mut bad = spec();
        bad.domains = vec!["not a domain".into()];
        let err = issue(&bad, &store, &|_| {}).await.unwrap_err();
        assert!(err.to_string().contains("非法字符") || err.to_string().contains("域名"));
    }

    #[tokio::test]
    async fn rejects_empty_credentials_before_network() {
        let store = AcmeStore::new(std::env::temp_dir().join("qqhu-acme-issue-test2"));
        let mut bad = spec();
        bad.credentials.access_key_secret = "  ".into();
        let err = issue(&bad, &store, &|_| {}).await.unwrap_err();
        assert!(err.to_string().contains("AccessKey"));
    }
}
