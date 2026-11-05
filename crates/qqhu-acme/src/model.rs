//! 输入模型与校验（纯逻辑，无网络、无 IO，便于单测）。

use serde::{Deserialize, Serialize};

/// 单个证书可包含的域名数量上限：Let's Encrypt 限制为 100。
pub const MAX_DOMAINS: usize = 100;

/// DNS 记录写入后的等待时间下限（秒）。
///
/// 记录刚写入时权威 DNS 可能尚未生效，Let's Encrypt 首次校验就查不到 TXT。
pub const MIN_DNS_WAIT_SECS: u64 = 5;
/// 等待时间上限，避免界面填出离谱的值把任务挂住。
pub const MAX_DNS_WAIT_SECS: u64 = 300;
/// 默认等待时间。
pub const DEFAULT_DNS_WAIT_SECS: u64 = 20;

/// DNS 服务商。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DnsProviderKind {
    /// 阿里云 DNS（云解析 DNS）
    Aliyun,
    /// 腾讯云 DNSPod
    Tencent,
}

impl DnsProviderKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Aliyun => "阿里云 DNS",
            Self::Tencent => "腾讯云 DNSPod",
        }
    }

    pub fn from_key(key: &str) -> Option<Self> {
        match key {
            "aliyun" => Some(Self::Aliyun),
            "tencent" => Some(Self::Tencent),
            _ => None,
        }
    }

    pub fn key(&self) -> &'static str {
        match self {
            Self::Aliyun => "aliyun",
            Self::Tencent => "tencent",
        }
    }
}

/// 访问凭据。
///
/// `Serialize` 是为了落盘到账户文件；**不要**把凭据写进日志或报告。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsCredentials {
    pub access_key_id: String,
    pub access_key_secret: String,
}

impl DnsCredentials {
    /// 校验凭据非空，并顺手去掉首尾空白（复制粘贴时最常见的错误）。
    pub fn normalized(&self) -> Result<Self, String> {
        let id = self.access_key_id.trim();
        let secret = self.access_key_secret.trim();
        if id.is_empty() {
            return Err("AccessKey ID 不能为空。".into());
        }
        if secret.is_empty() {
            return Err("AccessKey Secret 不能为空。".into());
        }
        Ok(Self {
            access_key_id: id.to_string(),
            access_key_secret: secret.to_string(),
        })
    }
}

/// 签发请求。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueSpec {
    /// 主域名放第一个，其余作为 SAN
    pub domains: Vec<String>,
    pub provider: DnsProviderKind,
    pub credentials: DnsCredentials,
    /// 使用 Let's Encrypt 测试环境（不占用正式额度，签出的证书不受信任）
    #[serde(default)]
    pub staging: bool,
    /// 自定义 ACME 目录地址（留空则用 Let's Encrypt）
    #[serde(default)]
    pub directory_url: Option<String>,
    /// 写入 TXT 后的等待秒数
    #[serde(default)]
    pub dns_wait_secs: Option<u64>,
    /// 启用自动续期：把 DNS 凭据存入系统凭据管理器，到期前 30 天自动重签
    #[serde(default)]
    pub enable_auto_renew: bool,
}

/// 规范化后的请求。
#[derive(Debug, Clone)]
pub struct ValidIssue {
    /// 完整域名列表，第一个为主域名；已小写、去重、排序稳定
    pub domains: Vec<String>,
    /// 去掉泛域名前缀后的基础域名（用于定位 DNS 区域）
    pub base_domains: Vec<String>,
    pub provider: DnsProviderKind,
    pub credentials: DnsCredentials,
    pub directory_url: String,
    pub dns_wait_secs: u64,
    pub enable_auto_renew: bool,
}

impl IssueSpec {
    /// 校验并规范化。
    pub fn validate(&self) -> Result<ValidIssue, String> {
        let domains = normalize_domains(&self.domains)?;
        let credentials = self.credentials.normalized()?;

        let directory_url = match self.directory_url.as_deref().map(str::trim) {
            Some(u) if !u.is_empty() => {
                let u = u.trim_end_matches('/').to_string();
                if !u.starts_with("https://") {
                    return Err("ACME 目录地址必须以 https:// 开头。".into());
                }
                u
            }
            _ => {
                if self.staging {
                    "https://acme-staging-v02.api.letsencrypt.org/directory".to_string()
                } else {
                    "https://acme-v02.api.letsencrypt.org/directory".to_string()
                }
            }
        };

        let wait = self.dns_wait_secs.unwrap_or(DEFAULT_DNS_WAIT_SECS);
        if !(MIN_DNS_WAIT_SECS..=MAX_DNS_WAIT_SECS).contains(&wait) {
            return Err(format!(
                "DNS 等待时间需在 {MIN_DNS_WAIT_SECS}–{MAX_DNS_WAIT_SECS} 秒之间。"
            ));
        }

        let base_domains = domains
            .iter()
            .map(|d| d.trim_start_matches("*.").to_string())
            .collect();

        Ok(ValidIssue {
            domains,
            base_domains,
            provider: self.provider,
            credentials,
            directory_url,
            dns_wait_secs: wait,
            enable_auto_renew: self.enable_auto_renew,
        })
    }
}

/// 域名规范化：小写、去空白、去重、校验字符集与泛域名写法。
///
/// 也接受用户直接粘贴 `https://example.com/path`，只取主机名部分。
pub fn normalize_domains(input: &[String]) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for raw in input {
        let mut s = raw.trim().to_ascii_lowercase();
        if s.is_empty() {
            continue;
        }
        // 容忍整条 URL
        if let Some(rest) = s
            .strip_prefix("https://")
            .or_else(|| s.strip_prefix("http://"))
        {
            s = rest
                .split(['/', '?', '#'])
                .next()
                .unwrap_or_default()
                .to_string();
        }
        // 去端口
        if let Some((host, port)) = s.rsplit_once(':') {
            if !host.contains(':') && port.chars().all(|c| c.is_ascii_digit()) {
                s = host.to_string();
            }
        }
        s = s.trim_end_matches('.').to_string();

        if s.is_empty() {
            continue;
        }
        if s.starts_with("*.") {
            let rest = &s[2..];
            if rest.is_empty() || rest.contains('*') {
                return Err(format!("泛域名写法不正确：{raw}"));
            }
            validate_hostname(rest).map_err(|e| format!("{raw}：{e}"))?;
        } else {
            validate_hostname(&s).map_err(|e| format!("{raw}：{e}"))?;
        }
        if !out.contains(&s) {
            out.push(s);
        }
    }

    if out.is_empty() {
        return Err("请至少填写一个域名。".into());
    }
    if out.len() > MAX_DOMAINS {
        return Err(format!(
            "一个证书最多包含 {MAX_DOMAINS} 个域名，当前 {} 个。",
            out.len()
        ));
    }
    Ok(out)
}

/// 只校验主机名字符集与基本形态；不做 DNS 解析。
fn validate_hostname(host: &str) -> Result<(), String> {
    if host.len() > 253 {
        return Err("域名过长。".into());
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return Err("域名至少需要两段，例如 example.com。".into());
    }
    for label in labels.iter() {
        if label.is_empty() {
            return Err("域名中有连续的点。".into());
        }
        if label.len() > 63 {
            return Err(format!("域名段过长：{label}"));
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(format!("域名含非法字符：{label}"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!("域名段不能以连字符开头或结尾：{label}"));
        }
    }
    // 纯数字的最后一段视为 IP，ACME 的 DNS-01 无法为 IP 签发
    if labels
        .last()
        .map(|l| l.chars().all(|c| c.is_ascii_digit()))
        .unwrap_or(false)
    {
        return Err("DNS-01 无法为 IP 地址签发证书，请填写域名。".into());
    }
    Ok(())
}

/// 从证书 DER 里取出的关键事实。
#[derive(Debug, Clone)]
pub struct CertFacts {
    /// 大写的序列号
    pub serial: String,
    /// SHA-256 指纹，`AA:BB:…` 形式
    pub fingerprint: String,
    pub not_before: chrono::DateTime<chrono::Utc>,
    pub not_after: chrono::DateTime<chrono::Utc>,
}

/// 解析 PEM 证书（取第一张，即服务端证书）。
pub fn parse_leaf(pem: &str) -> Result<CertFacts, crate::AcmeError> {
    use x509_parser::prelude::FromDer;

    let der = crate::store::pem_to_der(pem)?;
    let (_, cert) = x509_parser::prelude::X509Certificate::from_der(&der)
        .map_err(|e| crate::AcmeError::Cert(format!("证书解析失败：{e}")))?;

    let digest = ring::digest::digest(&ring::digest::SHA256, &der);
    let fingerprint = hex::encode_upper(digest.as_ref())
        .as_bytes()
        .chunks(2)
        .map(|c| String::from_utf8_lossy(c).to_string())
        .collect::<Vec<_>>()
        .join(":");

    let to_utc = |t: time::OffsetDateTime| {
        chrono::DateTime::from_timestamp(t.unix_timestamp(), 0).unwrap_or_else(chrono::Utc::now)
    };

    Ok(CertFacts {
        serial: cert
            .raw_serial()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>(),
        fingerprint,
        not_before: to_utc(cert.validity().not_before.to_datetime()),
        not_after: to_utc(cert.validity().not_after.to_datetime()),
    })
}

/// 已签发证书的元信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcmeCertMeta {
    pub id: String,
    /// 主域名
    pub primary_domain: String,
    /// 全部域名（含泛域名）
    pub domains: Vec<String>,
    /// ACME 目录地址
    pub directory: String,
    /// 是否测试环境（staging 签出的证书浏览器不信任）
    pub staging: bool,
    /// 服务商可读名
    pub provider: String,
    pub serial: String,
    pub fingerprint: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub not_before: chrono::DateTime<chrono::Utc>,
    pub not_after: chrono::DateTime<chrono::Utc>,
    pub days_remaining: i64,

    /// 是否启用自动续期
    #[serde(default)]
    pub auto_renew: bool,
    /// 服务商标识（aliyun / tencent），续期时用来还原请求
    #[serde(default)]
    pub provider_key: String,
    /// 已自动续期次数
    #[serde(default)]
    pub renew_count: u32,
    /// 最近一次续期尝试时间（无论成败都记，用于失败退避）
    #[serde(default)]
    pub last_attempt_at: Option<chrono::DateTime<chrono::Utc>>,
    /// 最近一次续期失败原因；成功后清空
    #[serde(default)]
    pub last_error: Option<String>,
    /// 最近一次续期成功时间
    #[serde(default)]
    pub renewed_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl AcmeCertMeta {
    /// 刷新剩余天数：证书不会因为时间流逝而改变，但剩余天数是相对的。
    pub fn refresh(&mut self, now: chrono::DateTime<chrono::Utc>) {
        self.days_remaining = (self.not_after - now).num_days();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(domains: &[&str]) -> IssueSpec {
        IssueSpec {
            domains: domains.iter().map(|s| s.to_string()).collect(),
            provider: DnsProviderKind::Aliyun,
            credentials: DnsCredentials {
                access_key_id: "  id  ".into(),
                access_key_secret: " secret ".into(),
            },
            staging: false,
            directory_url: None,
            dns_wait_secs: None,
            enable_auto_renew: false,
        }
    }

    #[test]
    fn normalizes_urls_ports_and_case() {
        let v = spec(&["HTTPS://Example.COM:8443/path?q=1", "example.com."])
            .validate()
            .unwrap();
        assert_eq!(v.domains, vec!["example.com"]);
    }

    #[test]
    fn trims_credentials() {
        let v = spec(&["example.com"]).validate().unwrap();
        assert_eq!(v.credentials.access_key_id, "id");
        assert_eq!(v.credentials.access_key_secret, "secret");
    }

    #[test]
    fn wildcard_is_kept_for_order_but_stripped_for_dns() {
        let v = spec(&["*.example.com", "example.com"]).validate().unwrap();
        assert_eq!(v.domains, vec!["*.example.com", "example.com"]);
        assert_eq!(v.base_domains, vec!["example.com", "example.com"]);
    }

    #[test]
    fn rejects_ip_and_bad_chars() {
        assert!(spec(&["192.168.1.1"]).validate().is_err());
        assert!(spec(&["a_b.com"]).validate().is_err());
        assert!(spec(&["-bad.com"]).validate().is_err());
        assert!(spec(&["a..b.com"]).validate().is_err());
        assert!(spec(&["*.*.example.com"]).validate().is_err());
        assert!(spec(&["localhost"]).validate().is_err());
    }

    #[test]
    fn rejects_empty_domain_list() {
        assert!(spec(&["", "  "]).validate().is_err());
    }

    #[test]
    fn staging_switches_directory() {
        let mut s = spec(&["example.com"]);
        assert!(s.validate().unwrap().directory_url.contains("acme-v02"));
        s.staging = true;
        assert!(s.validate().unwrap().directory_url.contains("staging"));
    }

    #[test]
    fn custom_directory_must_be_https() {
        let mut s = spec(&["example.com"]);
        s.directory_url = Some("http://acme.local/directory".into());
        assert!(s.validate().is_err());
        s.directory_url = Some("https://acme.local/directory".into());
        assert_eq!(
            s.validate().unwrap().directory_url,
            "https://acme.local/directory"
        );
    }

    #[test]
    fn dns_wait_is_bounded() {
        let mut s = spec(&["example.com"]);
        s.dns_wait_secs = Some(1);
        assert!(s.validate().is_err());
        s.dns_wait_secs = Some(600);
        assert!(s.validate().is_err());
        s.dns_wait_secs = Some(30);
        assert_eq!(s.validate().unwrap().dns_wait_secs, 30);
    }

    #[test]
    fn provider_keys_round_trip() {
        for k in ["aliyun", "tencent"] {
            let p = DnsProviderKind::from_key(k).unwrap();
            assert_eq!(p.key(), k);
        }
        assert!(DnsProviderKind::from_key("cloudflare").is_none());
    }

    #[test]
    fn days_remaining_refreshes() {
        let now = chrono::Utc::now();
        let mut meta = AcmeCertMeta {
            id: "x".into(),
            primary_domain: "example.com".into(),
            domains: vec!["example.com".into()],
            directory: "d".into(),
            staging: false,
            provider: "测试".into(),
            serial: "01".into(),
            fingerprint: "AA".into(),
            created_at: now,
            not_before: now,
            not_after: now + chrono::Duration::days(90),
            days_remaining: 0,
            auto_renew: false,
            provider_key: "aliyun".into(),
            renew_count: 0,
            last_attempt_at: None,
            last_error: None,
            renewed_at: None,
        };
        meta.refresh(now);
        assert_eq!(meta.days_remaining, 90);
    }

    #[test]
    fn parses_leaf_facts() {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["a.example.com".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();

        let facts = parse_leaf(&cert.pem()).unwrap();
        assert!(!facts.serial.is_empty());
        // SHA-256 指纹是 32 字节，用冒号分隔后共有 31 个冒号
        assert_eq!(facts.fingerprint.matches(':').count(), 31);
        assert!(facts.not_after > facts.not_before);
        assert!(parse_leaf("这不是 PEM").is_err());
    }
}
