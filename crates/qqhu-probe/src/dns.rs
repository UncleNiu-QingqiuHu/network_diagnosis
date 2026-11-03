//! DNS 解析探针。
//!
//! v1 走系统解析器（`getaddrinfo`），足够判断「域名是否可解析」与解析时延。
//! 指定 DNS 服务器的对比探测后续用 `hickory-resolver` 实现。

use qqhu_core::DnsAnswer;
use std::net::IpAddr;
use std::time::Instant;

/// 解析主机名，记录耗时与全部地址。失败不返回 Result，而是写进 `DnsAnswer.error`，
/// 这样报告里能保留「解析失败」这一事实，而不是整轮诊断中断。
pub async fn resolve(host: &str) -> DnsAnswer {
    let started = Instant::now();
    let t = host.trim();

    if t.is_empty() {
        return DnsAnswer {
            family: "ipv4".into(),
            addresses: Vec::new(),
            elapsed_ms: 0.0,
            error: Some("目标为空".into()),
        };
    }

    // IP 字面量无需解析，直接回填
    if let Ok(ip) = t.parse::<IpAddr>() {
        return DnsAnswer {
            family: if ip.is_ipv6() { "ipv6".into() } else { "ipv4".into() },
            addresses: vec![ip.to_string()],
            elapsed_ms: 0.0,
            error: None,
        };
    }

    match tokio::net::lookup_host((t, 0)).await {
        Ok(iter) => {
            let mut addrs: Vec<String> = Vec::new();
            for sock in iter {
                let s = sock.ip().to_string();
                if !addrs.contains(&s) {
                    addrs.push(s);
                }
            }
            let elapsed = started.elapsed().as_secs_f64() * 1000.0;
            if addrs.is_empty() {
                DnsAnswer {
                    family: "ipv4".into(),
                    addresses: Vec::new(),
                    elapsed_ms: (elapsed * 10.0).round() / 10.0,
                    error: Some("未返回任何地址".into()),
                }
            } else {
                let has_v4 = addrs.iter().any(|a| !a.contains(':'));
                DnsAnswer {
                    family: if has_v4 { "ipv4".into() } else { "ipv6".into() },
                    addresses: addrs,
                    elapsed_ms: (elapsed * 10.0).round() / 10.0,
                    error: None,
                }
            }
        }
        Err(e) => DnsAnswer {
            family: "ipv4".into(),
            addresses: Vec::new(),
            elapsed_ms: (started.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0,
            error: Some(e.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ip_literal_short_circuits() {
        let a = resolve("10.1.2.3").await;
        assert!(a.error.is_none());
        assert_eq!(a.addresses, vec!["10.1.2.3"]);
        assert_eq!(a.elapsed_ms, 0.0);
    }

    #[tokio::test]
    async fn empty_target_reports_error() {
        let a = resolve("   ").await;
        assert!(a.error.is_some());
    }

    #[tokio::test]
    async fn localhost_resolves() {
        let a = resolve("localhost").await;
        assert!(a.error.is_none(), "localhost 应可解析");
        assert!(!a.addresses.is_empty());
    }
}
