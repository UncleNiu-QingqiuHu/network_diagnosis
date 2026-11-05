//! 青丘湖网络工作台 —— ACME 证书签发。
//!
//! 走 Let's Encrypt 的 **DNS-01** 验证：不需要公网可达的 80/443 端口，
//! 内网机器也能给公网域名签证书，还能签泛域名。
//!
//! 分层：
//! - [`model`]：输入校验（纯逻辑）
//! - [`dns`]：DNS 服务商适配（阿里云 / 腾讯云），写入与清理 `_acme-challenge` TXT
//! - [`propagate`]：用 DoH 确认 TXT 已生效，减少「刚写完就去验证」的失败
//! - [`store`]：目录布局与元信息
//! - [`issue`]：ACME 协议流程编排
//!
//! 账户密钥与证书私钥以明文 PEM/JSON 存放在 `<安装目录>/pki/acme/`，
//! 与私有 CA 保持一致（沿用同一套约定）。

pub mod dns;
pub mod issue;
pub mod model;
pub mod propagate;
pub mod renewal;
pub mod store;
pub mod vault;

pub use model::{
    AcmeCertMeta, DnsCredentials, DnsProviderKind, IssueSpec, ValidIssue, DEFAULT_DNS_WAIT_SECS,
    MAX_DOMAINS,
};
pub use store::AcmeStore;
pub use vault::CredentialVault;

#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    #[error("{0}")]
    Invalid(String),

    #[error("{0}")]
    Dns(String),

    #[error("ACME 服务交互失败：{0}")]
    Acme(String),

    #[error("文件操作失败：{0}")]
    Io(String),

    #[error("证书解析失败：{0}")]
    Cert(String),
}

impl From<instant_acme::Error> for AcmeError {
    fn from(e: instant_acme::Error) -> Self {
        AcmeError::Acme(friendly_acme_error(&e))
    }
}

/// 把 ACME 的英文错误翻成能指导操作的中文。
///
/// Let's Encrypt 的报错经常被原样抛给用户，多数人看到 `unauthorized` 无从下手，
/// 这里对最常见的几类补上可操作的建议。
fn friendly_acme_error(e: &instant_acme::Error) -> String {
    let raw = e.to_string();
    let lower = raw.to_ascii_lowercase();
    if lower.contains("unauthorized") || (lower.contains("invalid") && lower.contains("challenge")) {
        return format!(
            "{raw}（验证失败：通常是 TXT 记录尚未生效或写到了错误的域名。\
             可调大「DNS 等待时间」，或在服务商控制台确认 _acme-challenge 记录已存在）"
        );
    }
    if lower.contains("rejectedidentifier") || lower.contains("forbidden by policy") {
        return format!(
            "{raw}（CA 拒绝为该域名签发：可能是保留域名（如 example.com）、\
             尚未在公网注册的域名，或该后缀不被支持。请换成自己真实拥有的域名）"
        );
    }
    if lower.contains("too many") || lower.contains("rate") {
        return format!("{raw}（触发服务商频率限制，请稍后重试，或先用测试环境跑通流程）");
    }
    if lower.contains("timeout") || lower.contains("timed out") {
        return format!("{raw}（等待超时，多半是 DNS 尚未生效）");
    }
    raw
}

use std::sync::OnceLock;

/// 全局复用的 HTTP 客户端。
///
/// 每次签发都新建 client 会重复做 TLS 初始化，连接池也无法复用。
pub fn http_client() -> reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            // reqwest 选用的是「不自带加密后端」的构建，必须显式安装 ring provider。
            // 安装失败说明别处已经装过（同进程只能有一个），忽略即可。
            let _ = rustls::crypto::ring::default_provider().install_default();
            reqwest::Client::builder()
                .user_agent(concat!("qqhu-acme/", env!("CARGO_PKG_VERSION")))
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default()
        })
        .clone()
}
