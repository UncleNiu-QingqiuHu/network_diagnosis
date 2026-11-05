//! ACME 签发流程编排。
//!
//! 顺序刻意做成「先写全部记录、等一次传播、再逐个 set_ready」：
//! 多域名时逐条「写入 → 等待 → 校验」会把等待时间乘以域名数，
//! 而 DNS 记录之间互不影响，完全可以并行准备。
//!
//! 首次签发与续期走同一条流程（[`provision`]），区别只在落盘时的元信息：
//! 续期沿用原来的 `id`，这样 Nginx 里写的路径不用改。

use crate::dns::{DnsClient, TxtRecord};
use crate::model::{parse_leaf, CertFacts, DnsCredentials, DnsProviderKind, IssueSpec, ValidIssue};
use crate::store::{split_pem, AcmeStore};
use crate::vault::CredentialVault;
use crate::AcmeError;
use chrono::Utc;
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

type Progress = dyn Fn(IssueProgress) + Send + Sync;

fn emit(cb: &Progress, stage: &str, message: impl Into<String>) {
    cb(IssueProgress {
        stage: stage.to_string(),
        message: message.into(),
    });
}

/// 一次成功签发产出的文件内容。
struct Artifacts {
    cert_pem: String,
    key_pem: String,
    chain_pem: String,
    facts: CertFacts,
}

/// 首次签发：写入 DNS → 等待生效 → 完成挑战 → 取证书 → 落盘。
///
/// 无论成功失败，已写入的 TXT 记录都会被清理，避免在域名下留下垃圾记录。
pub async fn issue(
    spec: &IssueSpec,
    store: &AcmeStore,
    vault: &CredentialVault,
    on_progress: &Progress,
) -> Result<crate::model::AcmeCertMeta, AcmeError> {
    let valid = spec.validate().map_err(AcmeError::Invalid)?;
    let client = DnsClient::new(valid.provider, valid.credentials.clone())?;

    let mut records: Vec<TxtRecord> = Vec::new();
    let outcome = provision(&valid, &client, store, &mut records, on_progress).await;
    cleanup(&client, &records, on_progress).await;
    let art = outcome?;

    let now = Utc::now();
    let mut meta = crate::model::AcmeCertMeta {
        id: store.next_id(),
        primary_domain: valid.domains[0].clone(),
        domains: valid.domains.clone(),
        directory: valid.directory_url.clone(),
        staging: valid.directory_url.contains("staging"),
        provider: client.label().to_string(),
        provider_key: valid.provider.key().to_string(),
        serial: art.facts.serial.clone(),
        fingerprint: art.facts.fingerprint.clone(),
        created_at: now,
        not_before: art.facts.not_before,
        not_after: art.facts.not_after,
        days_remaining: (art.facts.not_after - now).num_days(),
        auto_renew: false,
        renew_count: 0,
        last_attempt_at: None,
        last_error: None,
        renewed_at: None,
    };
    meta.refresh(now);

    // 先存凭据再打开开关：存不进去就明确告知，绝不留下一个「看起来开了但续不了」的开关
    if valid.enable_auto_renew {
        match vault.save(&meta.id, &valid.credentials) {
            Ok(()) => meta.auto_renew = true,
            Err(e) => emit(
                on_progress,
                "save",
                format!("自动续期未启用：凭据未能保存（{e}）"),
            ),
        }
    }

    emit(on_progress, "save", "保存证书与私钥");
    store
        .save_cert(&meta, &art.cert_pem, &art.key_pem, &art.chain_pem)?;
    emit(
        on_progress,
        "done",
        format!("签发完成，有效期至 {}", meta.not_after.format("%Y-%m-%d")),
    );
    Ok(meta)
}

/// 续期：用原 `id` 覆盖文件，域名与目录地址沿用旧证书。
pub async fn renew(
    meta: &crate::model::AcmeCertMeta,
    credentials: DnsCredentials,
    store: &AcmeStore,
    on_progress: &Progress,
) -> Result<crate::model::AcmeCertMeta, AcmeError> {
    let kind = provider_kind_of(meta)?;
    let spec = IssueSpec {
        domains: meta.domains.clone(),
        provider: kind,
        credentials,
        staging: meta.staging,
        directory_url: Some(meta.directory.clone()),
        dns_wait_secs: None,
        // 续期本身不代表要改开关，沿用原状态
        enable_auto_renew: meta.auto_renew,
    };
    let valid = spec.validate().map_err(AcmeError::Invalid)?;
    let client = DnsClient::new(valid.provider, valid.credentials.clone())?;

    let mut records: Vec<TxtRecord> = Vec::new();
    let outcome = provision(&valid, &client, store, &mut records, on_progress).await;
    cleanup(&client, &records, on_progress).await;
    let art = outcome?;

    let now = Utc::now();
    let mut next = crate::model::AcmeCertMeta {
        // 关键：沿用旧 id，部署脚本里的路径保持有效
        id: meta.id.clone(),
        primary_domain: valid.domains[0].clone(),
        domains: valid.domains.clone(),
        directory: valid.directory_url.clone(),
        staging: meta.staging,
        provider: client.label().to_string(),
        provider_key: valid.provider.key().to_string(),
        serial: art.facts.serial.clone(),
        fingerprint: art.facts.fingerprint.clone(),
        created_at: meta.created_at,
        not_before: art.facts.not_before,
        not_after: art.facts.not_after,
        days_remaining: (art.facts.not_after - now).num_days(),
        auto_renew: meta.auto_renew,
        renew_count: meta.renew_count + 1,
        last_attempt_at: Some(now),
        last_error: None,
        renewed_at: Some(now),
    };
    next.refresh(now);

    emit(on_progress, "save", "覆盖证书文件");
    store
        .save_cert(&next, &art.cert_pem, &art.key_pem, &art.chain_pem)?;
    emit(
        on_progress,
        "done",
        format!(
            "续期完成（第 {} 次），新的有效期至 {}",
            next.renew_count,
            next.not_after.format("%Y-%m-%d")
        ),
    );
    Ok(next)
}

/// 元信息里记录的服务商可能是标识，也可能是中文名（旧数据），两种都认。
pub fn provider_kind_of(meta: &crate::model::AcmeCertMeta) -> Result<DnsProviderKind, AcmeError> {
    if !meta.provider_key.is_empty() {
        if let Some(kind) = DnsProviderKind::from_key(&meta.provider_key) {
            return Ok(kind);
        }
    }
    // 兼容早期只存了中文名的数据
    for kind in [DnsProviderKind::Aliyun, DnsProviderKind::Tencent] {
        if kind.label() == meta.provider {
            return Ok(kind);
        }
    }
    Err(AcmeError::Invalid(format!(
        "无法识别证书 {} 的 DNS 服务商（{}），请删除后重新申请。",
        meta.id, meta.provider
    )))
}

/// 清理写入的 TXT 记录，失败只提示不影响结果。
async fn cleanup(client: &DnsClient, records: &[TxtRecord], on_progress: &Progress) {
    if records.is_empty() {
        return;
    }
    emit(on_progress, "cleanup", "清理验证用 TXT 记录…");
    for record in records {
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

/// 真正与 CA 交互的过程，返回证书内容（不落盘）。
async fn provision(
    valid: &ValidIssue,
    client: &DnsClient,
    store: &AcmeStore,
    records: &mut Vec<TxtRecord>,
    on_progress: &Progress,
) -> Result<Artifacts, AcmeError> {
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
                let mut challenge = handle
                    .challenge(ChallengeType::Dns01)
                    .ok_or_else(|| AcmeError::Acme("授权中没有 DNS-01 挑战。".to_string()))?;
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

    Ok(Artifacts {
        cert_pem,
        key_pem,
        chain_pem: blocks.join(""),
        facts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DnsProviderKind;

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
            enable_auto_renew: false,
        }
    }

    fn vault() -> CredentialVault {
        CredentialVault::new(std::env::temp_dir().join("qqhu-acme-issue-vault"))
    }

    #[tokio::test]
    async fn rejects_bad_input_before_touching_network() {
        let store = AcmeStore::new(std::env::temp_dir().join("qqhu-acme-issue-test"));
        let mut bad = spec();
        bad.domains = vec!["not a domain".into()];
        let err = issue(&bad, &store, &vault(), &|_| {}).await.unwrap_err();
        assert!(err.to_string().contains("非法字符") || err.to_string().contains("域名"));
    }

    #[tokio::test]
    async fn rejects_empty_credentials_before_network() {
        let store = AcmeStore::new(std::env::temp_dir().join("qqhu-acme-issue-test2"));
        let mut bad = spec();
        bad.credentials.access_key_secret = "  ".into();
        let err = issue(&bad, &store, &vault(), &|_| {}).await.unwrap_err();
        assert!(err.to_string().contains("AccessKey"));
    }

    #[test]
    fn resolves_provider_from_key_then_label() {
        let mut meta = crate::model::AcmeCertMeta {
            id: "x".into(),
            primary_domain: "a.com".into(),
            domains: vec!["a.com".into()],
            directory: "d".into(),
            staging: false,
            provider: "腾讯云 DNSPod".into(),
            provider_key: "tencent".into(),
            serial: "01".into(),
            fingerprint: "AA".into(),
            created_at: chrono::Utc::now(),
            not_before: chrono::Utc::now(),
            not_after: chrono::Utc::now(),
            days_remaining: 0,
            auto_renew: true,
            renew_count: 0,
            last_attempt_at: None,
            last_error: None,
            renewed_at: None,
        };
        assert_eq!(provider_kind_of(&meta).unwrap(), DnsProviderKind::Tencent);

        // 旧数据只有中文名
        meta.provider_key.clear();
        assert_eq!(provider_kind_of(&meta).unwrap(), DnsProviderKind::Tencent);

        // 都认不出来时必须报错，不能猜一个去写错域名的解析
        meta.provider = "未知服务商".into();
        assert!(provider_kind_of(&meta).is_err());
    }
}
