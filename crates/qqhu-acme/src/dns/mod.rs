//! DNS 服务商适配层：写入 / 清理 `_acme-challenge` TXT 记录。
//!
//! 两家云厂商的签名协议完全不同，但对外只需要两个动作：
//! 写入一条 TXT、删掉这条 TXT。用枚举分发而不是 trait 对象，
//! 是因为这里只有两个实现，枚举更直观也省掉 `async_trait`。

pub mod aliyun;
pub mod tencent;

use crate::model::{DnsCredentials, DnsProviderKind};
use crate::AcmeError;

/// 一条 TXT 记录。
#[derive(Debug, Clone)]
pub struct TxtRecord {
    /// 完整域名，如 `_acme-challenge.example.com`
    pub fqdn: String,
    pub value: String,
    /// 服务商侧的记录 ID，删除时使用
    pub record_id: String,
}

/// 统一的 DNS 客户端。
pub enum DnsClient {
    Aliyun(aliyun::AliyunDns),
    Tencent(tencent::TencentDns),
}

impl DnsClient {
    pub fn new(kind: DnsProviderKind, creds: DnsCredentials) -> Result<Self, AcmeError> {
        let creds = creds.normalized().map_err(AcmeError::Invalid)?;
        Ok(match kind {
            DnsProviderKind::Aliyun => Self::Aliyun(aliyun::AliyunDns::new(creds)),
            DnsProviderKind::Tencent => Self::Tencent(tencent::TencentDns::new(creds)),
        })
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Aliyun(_) => DnsProviderKind::Aliyun.label(),
            Self::Tencent(_) => DnsProviderKind::Tencent.label(),
        }
    }

    /// 账号下所有可管理的域名（区域）。
    pub async fn list_zones(&self) -> Result<Vec<String>, AcmeError> {
        match self {
            Self::Aliyun(c) => c.list_zones().await,
            Self::Tencent(c) => c.list_zones().await,
        }
    }

    async fn add_txt(&self, zone: &str, rr: &str, value: &str) -> Result<String, AcmeError> {
        match self {
            Self::Aliyun(c) => c.add_txt(zone, rr, value).await,
            Self::Tencent(c) => c.add_txt(zone, rr, value).await,
        }
    }

    async fn find_txt(&self, zone: &str, rr: &str) -> Result<Vec<(String, String)>, AcmeError> {
        match self {
            Self::Aliyun(c) => c.find_txt(zone, rr).await,
            Self::Tencent(c) => c.find_txt(zone, rr).await,
        }
    }

    async fn delete_record(&self, zone: &str, record_id: &str) -> Result<(), AcmeError> {
        match self {
            Self::Aliyun(c) => c.delete_record(record_id).await,
            Self::Tencent(c) => c.delete_record(zone, record_id).await,
        }
    }

    /// 写入验证用 TXT 记录，返回可用于清理的记录信息。
    pub async fn present(&self, fqdn: &str, value: &str) -> Result<TxtRecord, AcmeError> {
        let zones = self.list_zones().await?;
        let (zone, rr) = split_fqdn(fqdn, &zones).ok_or_else(|| {
            let sample = zones.iter().take(5).cloned().collect::<Vec<_>>().join("、");
            AcmeError::Dns(format!(
                "在{}账号下找不到 {fqdn} 所属的域名。请确认该域名已托管在此账号，\
                 且 AccessKey 有 DNS 解析权限。账号内可见域名：{}",
                self.label(),
                if sample.is_empty() {
                    "（无）".to_string()
                } else {
                    sample
                }
            ))
        })?;

        let record_id = self.add_txt(&zone, &rr, value).await?;
        Ok(TxtRecord {
            fqdn: fqdn.to_string(),
            value: value.to_string(),
            record_id,
        })
    }

    /// 清理验证记录。失败只算警告，不阻断签发流程。
    pub async fn cleanup(&self, record: &TxtRecord) -> Result<(), AcmeError> {
        let zones = self.list_zones().await?;
        let Some((zone, _)) = split_fqdn(&record.fqdn, &zones) else {
            return Ok(());
        };
        // 优先按记录 ID 删；ID 不可用时退回按值匹配
        if self.delete_record(&zone, &record.record_id).await.is_ok() {
            return Ok(());
        }
        let rr = rr_of(&record.fqdn, &zone);
        for (id, value) in self.find_txt(&zone, &rr).await? {
            if value == record.value {
                self.delete_record(&zone, &id).await?;
            }
        }
        Ok(())
    }
}

/// 在候选区域里找出最长匹配的域名，并算出相对记录名。
///
/// 例：`_acme-challenge.a.example.com` + 区域 `["example.com", "a.example.com"]`
/// → `("a.example.com", "_acme-challenge")`。
///
/// 取最长匹配是必须的：同时托管 `example.com` 与 `a.example.com` 时，
/// 记录写到父域下不会生效。
pub fn split_fqdn(fqdn: &str, zones: &[String]) -> Option<(String, String)> {
    let fqdn = fqdn.trim_end_matches('.').to_ascii_lowercase();
    let best = zones
        .iter()
        .map(|z| z.trim_end_matches('.').to_ascii_lowercase())
        .filter(|z| !z.is_empty() && (fqdn == *z || fqdn.ends_with(&format!(".{z}"))))
        .max_by_key(|z| z.len())?;

    if fqdn == best {
        // 区域顶点：TXT 记录名留空，服务商侧一般写作 "@"
        return Some((best, "@".to_string()));
    }
    Some((best.clone(), rr_of(&fqdn, &best)))
}

/// 从完整域名中截出相对记录名。
pub fn rr_of(fqdn: &str, zone: &str) -> String {
    let fqdn = fqdn.trim_end_matches('.');
    let zone = zone.trim_end_matches('.');
    match fqdn.strip_suffix(&format!(".{zone}")) {
        Some(prefix) if !prefix.is_empty() => prefix.to_string(),
        _ => "@".to_string(),
    }
}

/// 阿里云 RPC 签名的百分号编码。
///
/// 规则：`A-Z a-z 0-9 - _ . ~` 原样保留，空格编码为 `%20`（不是 `+`），
/// 其余字符一律 `%XX` 大写。与 `application/x-www-form-urlencoded` 的
/// 默认写法（空格→`+`）不同，混用会导致签名校验失败。
pub fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zones(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn splits_subdomain_record() {
        let z = zones(&["example.com"]);
        let (zone, rr) = split_fqdn("_acme-challenge.example.com", &z).unwrap();
        assert_eq!(zone, "example.com");
        assert_eq!(rr, "_acme-challenge");
    }

    #[test]
    fn splits_multi_level_record() {
        let z = zones(&["example.com"]);
        let (_, rr) = split_fqdn("_acme-challenge.www.example.com", &z).unwrap();
        assert_eq!(rr, "_acme-challenge.www");
    }

    #[test]
    fn prefers_longest_zone() {
        let z = zones(&["example.com", "a.example.com"]);
        let (zone, rr) = split_fqdn("_acme-challenge.a.example.com", &z).unwrap();
        assert_eq!(zone, "a.example.com");
        assert_eq!(rr, "_acme-challenge");
    }

    #[test]
    fn ignores_partial_suffix_match() {
        // notexample.com 不能被 example.com 匹配掉
        let z = zones(&["example.com"]);
        assert!(split_fqdn("_acme-challenge.notexample.com", &z).is_none());
    }

    #[test]
    fn apex_record_uses_at_sign() {
        let z = zones(&["example.com"]);
        let (_, rr) = split_fqdn("example.com", &z).unwrap();
        assert_eq!(rr, "@");
    }

    #[test]
    fn trailing_dots_are_tolerated() {
        let z = zones(&["example.com."]);
        let (zone, rr) = split_fqdn("_acme-challenge.example.com.", &z).unwrap();
        assert_eq!(zone, "example.com");
        assert_eq!(rr, "_acme-challenge");
    }

    #[test]
    fn percent_encoding_matches_aliyun_rules() {
        assert_eq!(percent_encode("a b"), "a%20b");
        assert_eq!(percent_encode("a+b"), "a%2Bb");
        assert_eq!(percent_encode("a*b~-_.c"), "a%2Ab~-_.c");
        assert_eq!(percent_encode("/"), "%2F");
        assert_eq!(percent_encode("中"), "%E4%B8%AD");
    }

    /// 手动联调：用真实 AccessKey 验证服务商对接是否可用。
    ///
    /// ```text
    /// QQHU_ACME_PROVIDER=aliyun QQHU_ACME_AK=xxx QQHU_ACME_SK=yyy \
    ///   cargo test -p qqhu-acme live_provider -- --ignored --nocapture
    /// ```
    #[tokio::test]
    #[ignore = "需要真实 AccessKey，手动运行"]
    async fn live_provider_smoke() {
        let kind = std::env::var("QQHU_ACME_PROVIDER").unwrap_or_else(|_| "aliyun".into());
        let Some(kind) = DnsProviderKind::from_key(&kind) else {
            eprintln!("未知的 QQHU_ACME_PROVIDER：{kind}，应为 aliyun 或 tencent");
            return;
        };
        let creds = DnsCredentials {
            access_key_id: std::env::var("QQHU_ACME_AK").unwrap_or_default(),
            access_key_secret: std::env::var("QQHU_ACME_SK").unwrap_or_default(),
        };
        let client = DnsClient::new(kind, creds).unwrap();
        match client.list_zones().await {
            Ok(zones) => eprintln!("[{}] 可见域名 {} 个：{:?}", client.label(), zones.len(), zones),
            Err(e) => eprintln!("[{}] 失败：{e}", client.label()),
        }
    }

    #[test]
    fn rejects_empty_credentials() {
        let creds = DnsCredentials {
            access_key_id: "".into(),
            access_key_secret: "x".into(),
        };
        assert!(DnsClient::new(DnsProviderKind::Aliyun, creds).is_err());
    }
}
