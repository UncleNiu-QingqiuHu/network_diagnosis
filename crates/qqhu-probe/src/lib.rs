//! 青丘湖网络工作台 —— 原生探针层。
//!
//! 设计目标：**不依赖任何外部可执行文件，也不要求管理员权限**。
//!
//! - ICMP 走非特权 socket（实测 Windows 非管理员可创建 raw ICMP socket 并完成远端探测）
//! - TCP 探测直接用 `tokio::net::TcpStream` 建连并计时，取代旧版 `tcping.exe`
//!
//! 三平台行为一致，不解析本地化命令行输出。

use std::net::IpAddr;

pub mod diagnose;
pub mod dns;
pub mod ping;
pub mod tcp;

pub use diagnose::{run_diagnosis, DiagContext, DiagOptions};
pub use ping::{ping_host, PingOptions};
pub use tcp::{probe_port, probe_ports, TcpProbeOptions};

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("目标解析失败：{0}")]
    Resolve(String),

    #[error("创建 ICMP 客户端失败：{0}")]
    IcmpClient(String),

    #[error("ICMP 探测失败：{0}")]
    Icmp(String),

    #[error("目标地址无效：{0}")]
    InvalidTarget(String),
}

/// 解析目标为具体 IP。
///
/// 已是 IP 字面量时直接返回；否则做一次 DNS 解析，按 `prefer_ipv6` 选择地址族，
/// 无对应族时回退到任意可用地址。
pub async fn resolve_target(target: &str, prefer_ipv6: bool) -> Result<IpAddr, ProbeError> {
    let t = target.trim();
    if t.is_empty() {
        return Err(ProbeError::InvalidTarget(target.to_string()));
    }
    if let Ok(ip) = t.parse::<IpAddr>() {
        return Ok(ip);
    }
    let iter = tokio::net::lookup_host((t, 0))
        .await
        .map_err(|e| ProbeError::Resolve(format!("{t}: {e}")))?;

    let addrs: Vec<IpAddr> = iter.map(|s| s.ip()).collect();
    let picked = if prefer_ipv6 {
        addrs.iter().find(|a| a.is_ipv6()).or_else(|| addrs.first())
    } else {
        addrs.iter().find(|a| a.is_ipv4()).or_else(|| addrs.first())
    };
    picked.copied().ok_or_else(|| ProbeError::Resolve(format!("{t}: 无可用地址")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn parse_ip_literal() {
        let ip = resolve_target("127.0.0.1", false).await.unwrap();
        assert!(ip.is_ipv4());
        let ip6 = resolve_target("::1", true).await.unwrap();
        assert!(ip6.is_ipv6());
    }

    #[tokio::test]
    async fn reject_empty() {
        assert!(resolve_target("  ", false).await.is_err());
    }
}
