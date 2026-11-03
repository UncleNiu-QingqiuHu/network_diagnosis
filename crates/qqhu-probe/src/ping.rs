//! ICMP 连通性探测。
//!
//! 基于 `surge-ping` 的非特权 ICMP socket，输出 [`PingStats`] 供报告与界面同源消费。

use crate::{resolve_target, ProbeError};
use qqhu_core::{PingSample, PingStats};
use std::net::IpAddr;
use std::time::Duration;
use surge_ping::{Client, Config, PingIdentifier, PingSequence, ICMP};
use tokio::time::sleep;

#[derive(Debug, Clone)]
pub struct PingOptions {
    /// 发包数量
    pub count: u32,
    /// 相邻两包间隔
    pub interval: Duration,
    /// 单包等待超时
    pub timeout: Duration,
    /// ICMP 负载字节数
    pub payload_len: usize,
    pub prefer_ipv6: bool,
}

impl Default for PingOptions {
    fn default() -> Self {
        Self {
            count: 4,
            interval: Duration::from_millis(300),
            timeout: Duration::from_secs(2),
            payload_len: 32,
            prefer_ipv6: false,
        }
    }
}

/// 对目标做 ICMP 探测。
///
/// DNS 解析失败会返回错误；单包超时不算错误，计入 `lost`。
/// 只有「连 ICMP 客户端都建不起来」才整体失败，便于上层区分降级原因。
pub async fn ping_host(target: &str, opts: &PingOptions) -> Result<PingStats, ProbeError> {
    let addr = resolve_target(target, opts.prefer_ipv6).await?;
    ping_addr(addr, target, opts).await
}

pub async fn ping_addr(addr: IpAddr, label: &str, opts: &PingOptions) -> Result<PingStats, ProbeError> {
    let kind = if addr.is_ipv6() { ICMP::V6 } else { ICMP::V4 };
    let config = Config::builder().kind(kind).build();
    let client = Client::new(&config).map_err(|e| ProbeError::IcmpClient(e.to_string()))?;

    // 用进程号作标识，避免与其他 ping 工具的回包串号
    let ident = PingIdentifier(std::process::id() as u16);
    let mut pinger = client.pinger(addr, ident).await;
    pinger.timeout(opts.timeout);

    let payload = vec![0u8; opts.payload_len.max(8)];
    let mut samples: Vec<PingSample> = Vec::with_capacity(opts.count as usize);
    let mut rtts: Vec<f64> = Vec::new();
    let mut received: u32 = 0;

    for seq in 0..opts.count {
        if seq > 0 {
            sleep(opts.interval).await;
        }
        let mut sample = PingSample {
            seq,
            rtt_ms: None,
            ttl: None,
        };
        match pinger.ping(PingSequence(seq as u16), &payload).await {
            Ok((_pkt, rtt)) => {
                let ms = rtt.as_secs_f64() * 1000.0;
                received += 1;
                rtts.push(ms);
                sample.rtt_ms = Some(round1(ms));
            }
            Err(e) => {
                tracing::debug!(target = %addr, seq, "ICMP 包失败: {e}");
            }
        }
        samples.push(sample);
    }

    let attempted = opts.count;
    Ok(PingStats {
        target: label.to_string(),
        attempted,
        received,
        lost: attempted.saturating_sub(received),
        min_ms: rtts.iter().cloned().reduce(f64::min).map(round1),
        max_ms: rtts.iter().cloned().reduce(f64::max).map(round1),
        avg_ms: if rtts.is_empty() {
            None
        } else {
            Some(round1(rtts.iter().sum::<f64>() / rtts.len() as f64))
        },
        rtts_ms: rtts.into_iter().map(round1).collect(),
        samples,
        raw_stdout: String::new(),
    })
}

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn loopback_always_replies() {
        let opts = PingOptions {
            count: 3,
            interval: Duration::from_millis(50),
            timeout: Duration::from_secs(2),
            ..Default::default()
        };
        let stats = ping_host("127.0.0.1", &opts).await.expect("回环探测应成功");
        assert_eq!(stats.attempted, 3);
        assert_eq!(stats.received, 3, "回环必须全部有回应");
        assert_eq!(stats.lost, 0);
        assert!(stats.avg_ms.is_some());
        assert_eq!(stats.samples.len(), 3);
    }

    #[tokio::test]
    async fn unresolvable_target_reports_error() {
        let opts = PingOptions {
            count: 1,
            ..Default::default()
        };
        let r = ping_host("this-host-should-not-exist.invalid", &opts).await;
        assert!(r.is_err());
    }
}
