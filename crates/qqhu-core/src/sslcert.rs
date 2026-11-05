//! SSL/TLS 证书模型与判定逻辑。
//!
//! 只做**纯计算**：有效期分级、主机名匹配、自签名识别。
//! 真正的 TLS 握手与证书解析在 `qqhu-probe` 里，因此这里可以完整单测。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// 证书有效期状态。前端据此着色：有效 / 即将过期（黄）/ 已过期（红）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CertStatus {
    Valid,
    ExpiringSoon,
    Expired,
    NotYetValid,
}

/// 距到期不足该天数即提示「即将过期」。
pub const EXPIRING_SOON_DAYS: i64 = 30;

/// 单张证书的信息。链上的每张证书共用同一结构。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertInfo {
    /// `CN=example.com, O=Example Inc` 这类可读摘要
    pub subject: String,
    pub issuer: String,
    pub common_name: Option<String>,
    pub serial: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub status: CertStatus,
    /// 距到期天数；已过期为负
    pub days_remaining: i64,
    pub sans: Vec<String>,
    /// 签名算法，如 `sha256WithRSAEncryption`
    pub signature_algorithm: String,
    /// 公钥算法，如 `rsaEncryption` / `id-ecPublicKey`
    pub key_algorithm: String,
    pub key_bits: Option<u32>,
    pub is_ca: bool,
    /// 主体与签发者相同（自签名，常见于私有 CA 或自签站点）
    pub self_signed: bool,
    /// SHA-256 指纹，冒号分隔大写十六进制
    pub sha256_fingerprint: String,
    /// 是否为服务器证书（链上第一张）
    pub is_leaf: bool,
}

/// 按给定时间刷新状态与剩余天数。
pub fn assess(cert: &mut CertInfo, now: DateTime<Utc>) {
    let days = (cert.not_after - now).num_days();
    cert.days_remaining = days;
    cert.status = if now < cert.not_before {
        CertStatus::NotYetValid
    } else if now > cert.not_after {
        CertStatus::Expired
    } else if days <= EXPIRING_SOON_DAYS {
        CertStatus::ExpiringSoon
    } else {
        CertStatus::Valid
    };
}

/// 一次检查的完整结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SslCheckReport {
    pub host: String,
    pub port: u16,
    pub checked_at: DateTime<Utc>,
    /// 实际连上的 IP，便于排查 DNS 解析到哪台机器
    pub remote_ip: String,
    /// 协商出的 TLS 版本，如 `TLSv1.3`
    pub tls_version: String,
    pub cipher_suite: String,
    /// 链上证书，`chain[0]` 为服务器证书
    pub chain: Vec<CertInfo>,
    pub hostname_matched: bool,
    /// 系统根证书校验是否通过
    pub trusted: bool,
    /// 校验失败原因（`trusted == false` 时非空）
    pub trust_error: Option<String>,
    pub duration_ms: u64,
    pub warnings: Vec<String>,
}

/// 主机名与证书是否匹配。
///
/// 规则按 RFC 6125：优先看 SAN 里的 DNS 名与 IP，SAN 为空时才回退到 CN
/// （现代 CA 已不签发仅含 CN 的证书，但内网自签证书仍常见）。
pub fn hostname_matches(host: &str, sans: &[String], common_name: Option<&str>) -> bool {
    let host = normalize_host(host);
    if host.is_empty() {
        return false;
    }

    let candidates: Vec<String> = if sans.is_empty() {
        common_name.into_iter().map(|s| s.to_string()).collect()
    } else {
        sans.to_vec()
    };

    candidates.iter().any(|pattern| single_match(&host, pattern))
}

fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn single_match(host: &str, pattern: &str) -> bool {
    let p = normalize_host(pattern);
    if p.is_empty() {
        return false;
    }
    if !p.contains('*') {
        return p == host;
    }
    // 通配符只允许出现在最左一段：`*.example.com` 匹配 `a.example.com`，
    // 不匹配 `a.b.example.com`，也不匹配裸域 `example.com`
    let Some(rest) = p.strip_prefix("*.") else {
        return false;
    };
    match host.strip_suffix(rest) {
        Some(label) => {
            !label.is_empty() && label.ends_with('.') && !label.trim_end_matches('.').contains('.')
        }
        None => false,
    }
}

/// 汇总一组可读的告警，供界面直接展示。
pub fn build_warnings(report: &SslCheckReport) -> Vec<String> {
    let mut w = Vec::new();

    if !report.trusted {
        if let Some(e) = &report.trust_error {
            w.push(format!("证书链校验未通过：{e}"));
        }
    }
    if !report.hostname_matched {
        w.push(format!("证书不包含主机名 {}，浏览器会报「证书名称不匹配」。", report.host));
    }
    if let Some(leaf) = report.chain.first() {
        match leaf.status {
            CertStatus::Expired => w.push(format!(
                "服务器证书已于 {} 过期。",
                leaf.not_after.format("%Y-%m-%d %H:%M UTC")
            )),
            CertStatus::NotYetValid => w.push(format!(
                "服务器证书尚未生效（生效时间 {}），请检查系统时间或部署配置。",
                leaf.not_before.format("%Y-%m-%d %H:%M UTC")
            )),
            CertStatus::ExpiringSoon => w.push(format!(
                "服务器证书将在 {} 天后过期（{}），请及时续期。",
                leaf.days_remaining,
                leaf.not_after.format("%Y-%m-%d")
            )),
            CertStatus::Valid => {}
        }
        if leaf.self_signed {
            w.push("服务器证书为自签名证书，公开客户端不会信任。".to_string());
        }
        if let Some(bits) = leaf.key_bits {
            if leaf.key_algorithm.contains("rsa") && bits < 2048 {
                w.push(format!("RSA 密钥仅 {bits} 位，低于 2048 位基线要求。"));
            }
        }
        if leaf.signature_algorithm.to_ascii_lowercase().contains("sha1") {
            w.push("证书使用 SHA-1 签名，已被主流浏览器判定为不安全。".to_string());
        }
    }

    if report.tls_version.starts_with("TLSv1.0") || report.tls_version.starts_with("TLSv1.1") {
        w.push(format!("协商到的 {} 已废弃，应升级到 TLS 1.2 及以上。", report.tls_version));
    }

    // 链上其余证书也检查有效期：中间证书过期同样会导致握手失败
    for (i, c) in report.chain.iter().enumerate().skip(1) {
        if c.status == CertStatus::Expired {
            w.push(format!("链上第 {} 张证书（{}）已过期。", i + 1, c.subject));
        }
    }

    w
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn cert(not_before: DateTime<Utc>, not_after: DateTime<Utc>) -> CertInfo {
        CertInfo {
            subject: "CN=example.com".into(),
            issuer: "CN=Test CA".into(),
            common_name: Some("example.com".into()),
            serial: "01".into(),
            not_before,
            not_after,
            status: CertStatus::Valid,
            days_remaining: 0,
            sans: vec!["example.com".into()],
            signature_algorithm: "sha256WithRSAEncryption".into(),
            key_algorithm: "rsaEncryption".into(),
            key_bits: Some(2048),
            is_ca: false,
            self_signed: false,
            sha256_fingerprint: String::new(),
            is_leaf: true,
        }
    }

    #[test]
    fn assess_marks_expired_and_expiring() {
        let now = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();

        let mut ok = cert(now - chrono::Duration::days(10), now + chrono::Duration::days(200));
        assess(&mut ok, now);
        assert_eq!(ok.status, CertStatus::Valid);
        assert_eq!(ok.days_remaining, 200);

        let mut soon = cert(now - chrono::Duration::days(10), now + chrono::Duration::days(7));
        assess(&mut soon, now);
        assert_eq!(soon.status, CertStatus::ExpiringSoon);

        let mut expired = cert(now - chrono::Duration::days(400), now - chrono::Duration::days(3));
        assess(&mut expired, now);
        assert_eq!(expired.status, CertStatus::Expired);
        assert!(expired.days_remaining < 0);

        let mut future = cert(now + chrono::Duration::days(5), now + chrono::Duration::days(400));
        assess(&mut future, now);
        assert_eq!(future.status, CertStatus::NotYetValid);
    }

    #[test]
    fn hostname_exact_and_wildcard() {
        assert!(hostname_matches("example.com", &["example.com".into()], None));
        assert!(hostname_matches("EXAMPLE.com.", &["example.com".into()], None));
        assert!(hostname_matches("www.example.com", &["*.example.com".into()], None));
        // 通配符不跨级
        assert!(!hostname_matches("a.b.example.com", &["*.example.com".into()], None));
        // 通配符不匹配裸域
        assert!(!hostname_matches("example.com", &["*.example.com".into()], None));
        assert!(!hostname_matches("example.org", &["example.com".into()], None));
    }

    #[test]
    fn hostname_falls_back_to_cn_when_no_san() {
        assert!(hostname_matches("mail.corp.local", &[], Some("mail.corp.local")));
        assert!(!hostname_matches("mail.corp.local", &[], Some("other.corp.local")));
    }

    #[test]
    fn hostname_matches_ip_san() {
        assert!(hostname_matches("192.168.60.10", &["192.168.60.10".into()], None));
        assert!(!hostname_matches("192.168.60.11", &["192.168.60.10".into()], None));
    }

    #[test]
    fn warns_on_mismatch_and_expiry() {
        let now = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
        let mut leaf = cert(now - chrono::Duration::days(400), now - chrono::Duration::days(1));
        assess(&mut leaf, now);
        leaf.self_signed = true;

        let report = SslCheckReport {
            host: "example.com".into(),
            port: 443,
            checked_at: now,
            remote_ip: "1.2.3.4".into(),
            tls_version: "TLSv1.2".into(),
            cipher_suite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".into(),
            chain: vec![leaf],
            hostname_matched: false,
            trusted: false,
            trust_error: Some("unknown issuer".into()),
            duration_ms: 12,
            warnings: Vec::new(),
        };

        let w = build_warnings(&report);
        assert!(w.iter().any(|s| s.contains("过期")));
        assert!(w.iter().any(|s| s.contains("主机名")));
        assert!(w.iter().any(|s| s.contains("自签名")));
        assert!(w.iter().any(|s| s.contains("校验未通过")));
    }
}
