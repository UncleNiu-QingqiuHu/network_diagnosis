//! IP 扫描：扫描范围的解析与结果模型。
//!
//! 本模块**只做纯计算**，不发包 —— 实际探测在 `qqhu-probe::ipscan`。
//! 拆开的原因：范围解析容易出错（/31、/32、跨段区间、短横线简写），
//! 放在零依赖层可以用单测把边界钉死，不必真的去扫网。

use crate::error::{CoreError, CoreResult};
use crate::subnet::parse_ipv4;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// 单次扫描地址数上限。
///
/// 取 4096 的理由：/20 是 4094 个地址，已覆盖常见的企业单层网段；
/// 再大则扫描时长（乘上超时与并发）和界面表格都不再有实用价值，
/// 应该改用 nmaap 之类的专用工具。
pub const MAX_SCAN_HOSTS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ScanScopeKind {
    /// CIDR 写法，如 `192.168.1.0/24`
    Cidr,
    /// 区间写法，如 `192.168.1.10-192.168.1.50`
    Range,
    /// 单个地址
    Single,
}

/// 解析后的扫描范围（闭区间 `start..=end`）。
#[derive(Debug, Clone)]
pub struct ScanScope {
    pub kind: ScanScopeKind,
    pub start: u32,
    pub end: u32,
    /// 给人看的范围描述，直接进报告与界面
    pub desc: String,
}

impl ScanScope {
    pub fn len(&self) -> usize {
        (self.end - self.start + 1) as usize
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    /// 按升序展开为地址列表。
    pub fn hosts(&self) -> Vec<Ipv4Addr> {
        (self.start..=self.end).map(Ipv4Addr::from).collect()
    }
}

/// 解析扫描输入。
///
/// 支持的写法：
/// - `192.168.1.0/24` —— CIDR，自动排除网络地址与广播地址
/// - `192.168.1.10-192.168.1.50` —— 闭区间
/// - `192.168.1.10-50` —— 右端短横线简写（同网段）
/// - `192.168.1.10` —— 单个地址
pub fn parse_scan_scope(input: &str, max_hosts: usize) -> CoreResult<ScanScope> {
    let s = input.trim();
    if s.is_empty() {
        return Err(CoreError::InvalidInput("请填写扫描范围".into()));
    }

    let scope = if let Some((addr, prefix)) = s.split_once('/') {
        parse_cidr(addr.trim(), prefix.trim())?
    } else if let Some((a, b)) = s.split_once('-') {
        parse_range(a.trim(), b.trim())?
    } else {
        let ip = parse_ipv4(s)?;
        ScanScope {
            kind: ScanScopeKind::Single,
            start: u32::from(ip),
            end: u32::from(ip),
            desc: ip.to_string(),
        }
    };

    if scope.len() > max_hosts {
        return Err(CoreError::InvalidInput(format!(
            "范围包含 {} 个地址，超过单次上限 {max_hosts}；请缩小网段后分批扫描",
            scope.len()
        )));
    }
    if scope.end < scope.start {
        return Err(CoreError::InvalidInput("区间起点大于终点".into()));
    }
    Ok(scope)
}

fn parse_cidr(addr: &str, prefix: &str) -> CoreResult<ScanScope> {
    let ip = parse_ipv4(addr)?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| CoreError::InvalidInput(format!("无效的前缀长度：{prefix}")))?;
    if prefix > 32 {
        return Err(CoreError::InvalidInput(format!("前缀长度超出范围：/{prefix}")));
    }

    let ip_u = u32::from(ip);
    let mask: u32 = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    let network = ip_u & mask;
    let broadcast = network | !mask;

    // /31 是点对点链路，两个地址都可用；/32 是单个主机。
    // 这与 IPv4 的现代语义一致，也与子网计算模块保持统一。
    let (start, end) = match prefix {
        32 => (ip_u, ip_u),
        31 => (network, broadcast),
        _ => (network + 1, broadcast.saturating_sub(1)),
    };

    let kind = if prefix == 32 { ScanScopeKind::Single } else { ScanScopeKind::Cidr };
    let desc = format!(
        "{}/{} · {} 个可用地址",
        Ipv4Addr::from(network),
        prefix,
        end - start + 1
    );

    Ok(ScanScope {
        kind,
        start,
        end,
        desc,
    })
}

fn parse_range(a: &str, b: &str) -> CoreResult<ScanScope> {
    let start = parse_ipv4(a)?;

    // 右端允许短写：`192.168.1.10-50` 的含义是末位换成 50
    let end = if let Ok(ip) = parse_ipv4(b) {
        ip
    } else {
        let last: u8 = b
            .parse()
            .map_err(|_| CoreError::InvalidInput(format!("无效的区间终点：{b}")))?;
        let o = start.octets();
        Ipv4Addr::new(o[0], o[1], o[2], last)
    };

    let (start_u, end_u) = (u32::from(start), u32::from(end));
    if end_u < start_u {
        return Err(CoreError::InvalidInput(format!(
            "区间起点 {start} 大于终点 {end}"
        )));
    }

    Ok(ScanScope {
        kind: ScanScopeKind::Range,
        start: start_u,
        end: end_u,
        desc: format!("{start} - {end} · {} 个地址", end_u - start_u + 1),
    })
}

/// 单个地址的判定方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProbeMethod {
    /// ICMP 回声有响应
    Icmp,
    /// ICMP 无响应，但 TCP 端口建连成功
    Tcp,
    /// 两种方式均无响应
    None,
}

impl ProbeMethod {
    pub fn zh(self) -> &'static str {
        match self {
            ProbeMethod::Icmp => "ICMP",
            ProbeMethod::Tcp => "TCP",
            ProbeMethod::None => "无响应",
        }
    }
}

/// 单个地址的扫描结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpScanHost {
    pub ip: String,
    pub alive: bool,
    pub method: ProbeMethod,
    /// 最小 RTT；TCP 兜底命中时为建连耗时
    pub rtt_ms: Option<f64>,
    /// ICMP 丢包率（0.0 ~ 100.0）
    pub loss_percent: f64,
    /// TCP 兜底命中的端口
    pub open_port: Option<u16>,
}

/// 扫描参数快照，便于复现与写进报告。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpScanParams {
    pub count: u32,
    pub timeout_ms: u64,
    pub concurrency: usize,
    pub tcp_fallback_ports: Vec<u16>,
}

/// 一次扫描的完整结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpScanReport {
    pub input: String,
    pub scope_desc: String,
    pub started_at: String,
    pub duration_ms: u64,
    pub total: usize,
    pub alive_count: usize,
    pub hosts: Vec<IpScanHost>,
    /// 用户中途取消时为 true，此时 hosts 只包含已扫到的部分
    pub cancelled: bool,
    pub params: IpScanParams,
    /// 扫描过程中的降级说明（如 ICMP 不可用、本次仅走 TCP）
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl IpScanReport {
    pub fn alive_hosts(&self) -> impl Iterator<Item = &IpScanHost> {
        self.hosts.iter().filter(|h| h.alive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(input: &str) -> ScanScope {
        parse_scan_scope(input, MAX_SCAN_HOSTS).expect("应能解析")
    }

    #[test]
    fn cidr_24_excludes_network_and_broadcast() {
        let s = scope("192.168.1.0/24");
        assert_eq!(s.kind, ScanScopeKind::Cidr);
        assert_eq!(s.len(), 254, "/24 应有 254 个可用地址");
        let hosts = s.hosts();
        assert_eq!(hosts[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(hosts[253], Ipv4Addr::new(192, 168, 1, 254));
    }

    #[test]
    fn cidr_normalizes_to_network_address() {
        // 输入的是主机地址而非网络地址，也要正确归位
        let s = scope("192.168.1.77/24");
        assert_eq!(s.hosts()[0], Ipv4Addr::new(192, 168, 1, 1));
        assert!(s.desc.starts_with("192.168.1.0/24"));
    }

    #[test]
    fn cidr_30_has_two_usable() {
        let s = scope("10.0.0.0/30");
        assert_eq!(s.len(), 2);
        assert_eq!(s.hosts(), vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)]);
    }

    #[test]
    fn cidr_31_keeps_both_ends() {
        let s = scope("10.0.0.0/31");
        assert_eq!(s.len(), 2, "/31 点对点链路两端都可用");
    }

    #[test]
    fn cidr_32_is_single_host() {
        let s = scope("10.0.0.7/32");
        assert_eq!(s.kind, ScanScopeKind::Single);
        assert_eq!(s.len(), 1);
        assert_eq!(s.hosts()[0], Ipv4Addr::new(10, 0, 0, 7));
    }

    #[test]
    fn full_range_written_out() {
        let s = scope("192.168.1.10-192.168.1.20");
        assert_eq!(s.kind, ScanScopeKind::Range);
        assert_eq!(s.len(), 11);
        assert_eq!(s.hosts()[0], Ipv4Addr::new(192, 168, 1, 10));
    }

    #[test]
    fn short_range_uses_last_octet_of_start() {
        let s = scope("192.168.1.10-50");
        assert_eq!(s.len(), 41);
        assert_eq!(s.hosts()[0], Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(s.hosts()[40], Ipv4Addr::new(192, 168, 1, 50));
    }

    #[test]
    fn single_ip() {
        let s = scope("172.16.5.9");
        assert_eq!(s.kind, ScanScopeKind::Single);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn spaces_are_tolerated() {
        let s = scope("  192.168.1.0 / 24  ");
        assert_eq!(s.len(), 254);
    }

    #[test]
    fn rejects_too_large_scope() {
        let e = parse_scan_scope("10.0.0.0/8", MAX_SCAN_HOSTS);
        assert!(e.is_err());
        assert!(e.unwrap_err().to_string().contains("超过单次上限"));
    }

    #[test]
    fn rejects_reversed_range() {
        assert!(parse_scan_scope("192.168.1.50-192.168.1.10", MAX_SCAN_HOSTS).is_err());
        assert!(parse_scan_scope("192.168.1.50-10", MAX_SCAN_HOSTS).is_err());
    }

    #[test]
    fn rejects_garbage() {
        for bad in ["", "  ", "abc", "192.168.1.0/33", "192.168.1.0/abc", "1.2.3.4-xyz"] {
            assert!(
                parse_scan_scope(bad, MAX_SCAN_HOSTS).is_err(),
                "{bad:?} 应被拒绝"
            );
        }
    }

    #[test]
    fn respect_custom_limit() {
        assert!(parse_scan_scope("192.168.1.0/24", 100).is_err());
        assert!(parse_scan_scope("192.168.1.0/24", 254).is_ok());
    }
}
