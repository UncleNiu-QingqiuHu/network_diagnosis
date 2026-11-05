//! 路径追踪（Traceroute）模型。
//!
//! 只承载数据结构与展示用推导，ICMP 收发在 `qqhu-probe` 里。

use serde::{Deserialize, Serialize};

/// 单跳结果。`addr` 为空表示该跳全超时（显示为 `*`）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceHop {
    pub ttl: u8,
    /// 该跳应答的路由器地址；全超时为 `None`
    pub addr: Option<String>,
    /// 最小往返时延（毫秒），有应答才有值
    pub rtt_ms: Option<f64>,
    /// 是否已到达目标
    pub reached: bool,
    /// 备注：如「目标未响应 ICMP」
    pub note: Option<String>,
}

impl TraceHop {
    pub fn timed_out(ttl: u8) -> Self {
        Self {
            ttl,
            addr: None,
            rtt_ms: None,
            reached: false,
            note: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceReport {
    pub target: String,
    pub resolved_ip: String,
    pub hops: Vec<TraceHop>,
    /// 是否走到了目标（而非被 max_hops 截断）
    pub completed: bool,
    pub cancelled: bool,
    pub duration_ms: u64,
    pub warnings: Vec<String>,
}

impl TraceReport {
    /// 有应答的跳数，用于统计条。
    pub fn responded_hops(&self) -> usize {
        self.hops.iter().filter(|h| h.addr.is_some()).count()
    }

    /// 路径上出现超过一次的地址 —— 常见于负载均衡或路由环路。
    pub fn repeated_addrs(&self) -> Vec<(String, usize)> {
        let mut seen: Vec<(String, usize)> = Vec::new();
        for h in &self.hops {
            let Some(a) = &h.addr else { continue };
            match seen.iter_mut().find(|(k, _)| k == a) {
                Some((_, n)) => *n += 1,
                None => seen.push((a.clone(), 1)),
            }
        }
        seen.into_iter().filter(|(_, n)| *n > 1).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hop(ttl: u8, addr: Option<&str>) -> TraceHop {
        TraceHop {
            ttl,
            addr: addr.map(|s| s.to_string()),
            rtt_ms: addr.map(|_| 1.0),
            reached: false,
            note: None,
        }
    }

    #[test]
    fn counts_only_answered_hops() {
        let r = TraceReport {
            target: "example.com".into(),
            resolved_ip: "93.184.216.34".into(),
            hops: vec![hop(1, Some("192.168.1.1")), hop(2, None), hop(3, Some("10.0.0.1"))],
            completed: false,
            cancelled: false,
            duration_ms: 100,
            warnings: vec![],
        };
        assert_eq!(r.responded_hops(), 2);
    }

    #[test]
    fn detects_repeated_addresses() {
        let r = TraceReport {
            target: "a".into(),
            resolved_ip: "1.1.1.1".into(),
            hops: vec![
                hop(1, Some("10.0.0.1")),
                hop(2, Some("10.0.0.2")),
                hop(3, Some("10.0.0.1")),
            ],
            completed: false,
            cancelled: false,
            duration_ms: 1,
            warnings: vec![],
        };
        assert_eq!(r.repeated_addrs(), vec![("10.0.0.1".to_string(), 2)]);
    }
}
