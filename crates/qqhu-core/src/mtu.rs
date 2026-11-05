//! 路径 MTU 探测模型。
//!
//! 探测本身在 `qqhu-probe`：发带 DF 标志的 ICMP Echo，二分查找最大可通尺寸。

use serde::{Deserialize, Serialize};

/// IPv4 头(20) + ICMP 头(8)。
pub const IPV4_ICMP_OVERHEAD: u32 = 28;
/// 以太网 MTU 基线。
pub const DEFAULT_MTU: u32 = 1500;
/// IPv4 主机必须支持的载荷下限（RFC 1063 / 576 字节总长）。
pub const MIN_MTU: u32 = 576;
/// 常见巨型帧上限。
pub const MAX_MTU: u32 = 9000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MtuProbe {
    /// 本次探测的 MTU 候选值（= ICMP 载荷 + 28）
    pub mtu: u32,
    pub passed: bool,
    /// 路由器回报的下一跳 MTU（ICMP 3/4）
    pub next_hop_mtu: Option<u32>,
    pub rtt_ms: Option<f64>,
    /// `ok` / `too-big` / `timeout` / `send-error`
    pub outcome: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MtuReport {
    pub target: String,
    pub resolved_ip: String,
    /// 推断出的路径 MTU
    pub path_mtu: u32,
    pub probes: Vec<MtuProbe>,
    /// 有探测超时，结论可能受丢包影响
    pub uncertain: bool,
    pub duration_ms: u64,
    pub warnings: Vec<String>,
    /// 一句话结论，后端生成以保证与判定逻辑同源
    pub summary: String,
}

impl MtuReport {
    /// 与以太网基线对比的一句话结论。
    pub fn summary_of(path_mtu: u32) -> String {
        match path_mtu.cmp(&DEFAULT_MTU) {
            std::cmp::Ordering::Equal => "路径 MTU 为标准以太网 1500，无需调整。".to_string(),
            std::cmp::Ordering::Less => format!(
                "路径 MTU 低于 1500（{}），通常是 PPPoE / VPN / 隧道封装所致，\
                 建议把相关接口 MTU 调至该值以消除大包丢失。",
                path_mtu
            ),
            std::cmp::Ordering::Greater => format!(
                "路径 MTU 大于 1500（{}），链路支持巨型帧。",
                path_mtu
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(mtu: u32) -> MtuReport {
        MtuReport {
            target: "example.com".into(),
            resolved_ip: "1.2.3.4".into(),
            path_mtu: mtu,
            probes: vec![],
            uncertain: false,
            duration_ms: 10,
            warnings: vec![],
            summary: MtuReport::summary_of(mtu),
        }
    }

    #[test]
    fn summary_distinguishes_below_and_above_baseline() {
        assert!(report(1500).summary.contains("标准"));
        assert!(report(1400).summary.contains("PPPoE"));
        assert!(report(9000).summary.contains("巨型帧"));
    }

    #[test]
    fn constants_match_ipv4_semantics() {
        assert_eq!(DEFAULT_MTU - IPV4_ICMP_OVERHEAD, 1472);
    }
}
