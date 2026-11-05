//! 私有 CA 与证书的数据模型、输入校验。
//!
//! 这一层不含 IO、不碰 rcgen，全部是纯逻辑，因此可以完整单测。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// 支持的密钥算法。
///
/// 目前只有 ring 后端能生成的算法：ECDSA P-256 与 Ed25519。
/// RSA 需要 aws-lc-rs 后端（编译依赖 cmake / nasm），暂未启用；
/// 若目标设备只认 RSA，需要后续单独加。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KeyAlgorithm {
    EcdsaP256,
    Ed25519,
}

impl Default for KeyAlgorithm {
    fn default() -> Self {
        Self::EcdsaP256
    }
}

impl KeyAlgorithm {
    pub fn label(self) -> &'static str {
        match self {
            KeyAlgorithm::EcdsaP256 => "ECDSA P-256",
            KeyAlgorithm::Ed25519 => "Ed25519",
        }
    }

    /// 前端下拉框用。
    pub fn as_str(self) -> &'static str {
        match self {
            KeyAlgorithm::EcdsaP256 => "ecdsaP256",
            KeyAlgorithm::Ed25519 => "ed25519",
        }
    }
}

/// 证书用途，决定 Extended Key Usage。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CertUsage {
    /// TLS 服务器证书
    Server,
    /// 客户端证书（双向 TLS、802.1X）
    Client,
    /// 两者兼可
    Both,
}

impl Default for CertUsage {
    fn default() -> Self {
        Self::Server
    }
}

impl CertUsage {
    pub fn label(self) -> &'static str {
        match self {
            CertUsage::Server => "服务器",
            CertUsage::Client => "客户端",
            CertUsage::Both => "服务器 + 客户端",
        }
    }
}

/// 新建 CA 的输入。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaSpec {
    /// 必填，如「青丘湖内部根 CA」
    pub common_name: String,
    pub organization: Option<String>,
    pub organizational_unit: Option<String>,
    /// 两位国家代码，如 CN
    pub country: Option<String>,
    pub state: Option<String>,
    pub locality: Option<String>,
    /// 有效期（天），默认 3650
    pub validity_days: Option<u32>,
    #[serde(default)]
    pub key_algorithm: KeyAlgorithm,
}

/// 签发站点证书的输入。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertSpec {
    pub ca_id: String,
    pub common_name: String,
    /// DNS 名或 IP，可多条；为空时自动使用 CN
    #[serde(default)]
    pub sans: Vec<String>,
    pub validity_days: Option<u32>,
    #[serde(default)]
    pub key_algorithm: KeyAlgorithm,
    #[serde(default)]
    pub usage: CertUsage,
}

/// CA 元信息，落盘为 `meta.json`。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaMeta {
    pub id: String,
    pub common_name: String,
    /// 完整 DN 字符串
    pub subject: String,
    pub serial: String,
    /// SHA-256 指纹，冒号分隔大写十六进制
    pub fingerprint: String,
    pub key_algorithm: String,
    pub created_at: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    /// 距到期天数，列表读取时刷新
    #[serde(default)]
    pub days_remaining: i64,
    /// 已签发的证书数量，列表读取时刷新
    #[serde(default)]
    pub issued_count: usize,
}

/// 已签发证书的元信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertMeta {
    pub id: String,
    pub ca_id: String,
    pub common_name: String,
    pub sans: Vec<String>,
    pub serial: String,
    pub fingerprint: String,
    pub key_algorithm: String,
    pub usage: String,
    pub created_at: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    #[serde(default)]
    pub days_remaining: i64,
}

impl CaMeta {
    /// 按当前时间刷新剩余天数，避免 meta.json 里存的时间戳过期。
    pub fn refresh(&mut self, now: DateTime<Utc>) {
        self.days_remaining = (self.not_after - now).num_days();
    }
}

impl CertMeta {
    pub fn refresh(&mut self, now: DateTime<Utc>) {
        self.days_remaining = (self.not_after - now).num_days();
    }
}

/// CA 有效期的默认值与上限。
pub const DEFAULT_CA_DAYS: u32 = 3650;
pub const MAX_CA_DAYS: u32 = 7300;
/// 站点证书默认 397 天（跟随主流浏览器对 TLS 证书的最长有效期趋势）。
pub const DEFAULT_LEAF_DAYS: u32 = 397;
pub const MAX_LEAF_DAYS: u32 = 825;

/// 校验 CA 输入，返回归一化后的有效期。
pub fn validate_ca(spec: &CaSpec) -> Result<u32, String> {
    validate_common_name(&spec.common_name)?;
    if let Some(c) = &spec.country {
        let c = c.trim();
        if !c.is_empty() && (c.chars().count() != 2 || !c.chars().all(|ch| ch.is_ascii_alphabetic())) {
            return Err("国家代码必须是两位字母（如 CN）。".to_string());
        }
    }
    let days = spec.validity_days.unwrap_or(DEFAULT_CA_DAYS);
    if !(1..=MAX_CA_DAYS).contains(&days) {
        return Err(format!("CA 有效期须在 1–{MAX_CA_DAYS} 天之间。"));
    }
    Ok(days)
}

/// 校验证书输入，返回（归一化 SAN、有效期）。
pub fn validate_cert(spec: &CertSpec) -> Result<(Vec<String>, u32), String> {
    validate_common_name(&spec.common_name)?;

    let mut sans = normalize_sans(&spec.sans)?;
    if sans.is_empty() {
        // 没填 SAN 时用 CN，这是最符合直觉的行为
        let cn = spec.common_name.trim();
        if !cn.is_empty() {
            sans.push(cn.to_ascii_lowercase());
        }
    }
    if sans.is_empty() {
        return Err("请至少填写一个域名或 IP。".to_string());
    }
    if sans.len() > 32 {
        return Err("SAN 最多 32 条。".to_string());
    }

    let days = spec.validity_days.unwrap_or(DEFAULT_LEAF_DAYS);
    if !(1..=MAX_LEAF_DAYS).contains(&days) {
        return Err(format!("证书有效期须在 1–{MAX_LEAF_DAYS} 天之间。"));
    }
    Ok((sans, days))
}

pub fn validate_common_name(cn: &str) -> Result<(), String> {
    let cn = cn.trim();
    if cn.is_empty() {
        return Err("名称（CN）不能为空。".to_string());
    }
    if cn.chars().count() > 64 {
        return Err("名称（CN）不能超过 64 个字符。".to_string());
    }
    if cn.chars().any(|c| c.is_control()) {
        return Err("名称（CN）不能包含控制字符。".to_string());
    }
    Ok(())
}

/// 归一化 SAN：去空、去重、域名小写、IP 保留原样。
///
/// 非法项直接报错而不是静默丢弃 —— 用户以为签了 `*.corp.local` 结果证书里没有，
/// 排查成本远高于当场提示。
pub fn normalize_sans(input: &[String]) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for raw in input {
        let item = raw.trim();
        if item.is_empty() {
            continue;
        }
        let normalized = if let Ok(ip) = item.parse::<IpAddr>() {
            ip.to_string()
        } else {
            let d = item.trim_end_matches('.').to_ascii_lowercase();
            validate_dns_name(&d)?;
            d
        };
        if !out.contains(&normalized) {
            out.push(normalized);
        }
    }
    Ok(out)
}

/// 校验 DNS 名（含通配符）。
fn validate_dns_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 253 {
        return Err(format!("域名长度非法：{name}"));
    }
    let body = name.strip_prefix("*.").unwrap_or(name);
    if body.is_empty() {
        return Err("通配符后必须跟域名，如 *.corp.local。".to_string());
    }
    // 通配符只允许出现在最左一级
    if body.contains('*') {
        return Err(format!("通配符只能出现在最左侧一级：{name}"));
    }
    for label in body.split('.') {
        if label.is_empty() {
            return Err(format!("域名中出现连续的点：{name}"));
        }
        if label.len() > 63 {
            return Err(format!("域名分段超过 63 个字符：{name}"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!("域名分段不能以连字符开头或结尾：{name}"));
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(format!("域名包含非法字符：{name}"));
        }
    }
    // 纯数字的「域名」多半是想填 IP 却写错了
    if body.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Err(format!("{name} 看起来是 IP 地址，但格式无效。"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(cn: &str, sans: &[&str]) -> CertSpec {
        CertSpec {
            ca_id: "ca1".into(),
            common_name: cn.into(),
            sans: sans.iter().map(|s| s.to_string()).collect(),
            validity_days: None,
            key_algorithm: KeyAlgorithm::EcdsaP256,
            usage: CertUsage::Server,
        }
    }

    #[test]
    fn accepts_normal_domains_and_ips() {
        let s = spec("web.corp.local", &["web.corp.local", "192.168.1.10", "*.corp.local"]);
        let (sans, days) = validate_cert(&s).unwrap();
        assert_eq!(sans, vec!["web.corp.local", "192.168.1.10", "*.corp.local"]);
        assert_eq!(days, DEFAULT_LEAF_DAYS);
    }

    #[test]
    fn normalizes_case_and_dedupes() {
        let s = spec("web", &["Web.Corp.Local.", "web.corp.local"]);
        let (sans, _) = validate_cert(&s).unwrap();
        assert_eq!(sans, vec!["web.corp.local"]);
    }

    #[test]
    fn falls_back_to_cn_when_sans_empty() {
        let s = spec("mail.corp.local", &[]);
        let (sans, _) = validate_cert(&s).unwrap();
        assert_eq!(sans, vec!["mail.corp.local"]);
    }

    #[test]
    fn rejects_bad_dns_names() {
        for bad in ["a..b", "-a.com", "a-.com", "a b.com", "*.*.com", "999.999.999.999"] {
            let s = spec("x", &[bad]);
            assert!(validate_cert(&s).is_err(), "应当拒绝：{bad}");
        }
    }

    #[test]
    fn blank_san_entries_are_ignored() {
        // 界面上多打一个逗号不该导致签发失败
        let s = spec("web", &["", "  ", "web.corp.local"]);
        let (sans, _) = validate_cert(&s).unwrap();
        assert_eq!(sans, vec!["web.corp.local"]);
    }

    #[test]
    fn rejects_empty_cn() {
        let mut s = spec("web", &["web"]);
        s.common_name = "  ".into();
        assert!(validate_cert(&s).is_err());
    }

    #[test]
    fn validates_validity_range() {
        let mut s = spec("web", &["web"]);
        s.validity_days = Some(0);
        assert!(validate_cert(&s).is_err());
        s.validity_days = Some(MAX_LEAF_DAYS + 1);
        assert!(validate_cert(&s).is_err());
        s.validity_days = Some(30);
        assert_eq!(validate_cert(&s).unwrap().1, 30);
    }

    #[test]
    fn validates_country_code() {
        let mut c = CaSpec {
            common_name: "Test CA".into(),
            organization: None,
            organizational_unit: None,
            country: Some("CHN".into()),
            state: None,
            locality: None,
            validity_days: None,
            key_algorithm: KeyAlgorithm::default(),
        };
        assert!(validate_ca(&c).is_err());
        c.country = Some("cn".into());
        assert!(validate_ca(&c).is_ok());
        assert_eq!(validate_ca(&c).unwrap(), DEFAULT_CA_DAYS);
    }

    #[test]
    fn wildcard_only_leftmost() {
        assert!(validate_dns_name("*.corp.local").is_ok());
        assert!(validate_dns_name("a.*.local").is_err());
    }
}
