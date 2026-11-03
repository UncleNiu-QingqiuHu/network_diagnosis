//! IPv4 子网计算 —— 与旧版 `subnet_calc.py` 逐项对齐。
//!
//! 不引入 `ipnet` 等外部依赖，直接用 `u32` 位运算实现，
//! 保证在 Windows / macOS / Linux 上结果完全一致，且便于穷举单测。

use crate::error::{CoreError, CoreResult};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::str::FromStr;

/// 100.64.0.0/10 —— (网络基址, /10 掩码)
const RFC6598: (u32, u32) = (0x6440_0000, 0xFFC0_0000);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SubnetCalcResult {
    pub input_interface: String,
    pub network_cidr: String,
    pub network_address: String,
    pub broadcast_address: String,
    pub netmask: String,
    pub wildcard_mask: String,
    pub prefix_len: u8,
    pub total_addresses: u64,
    pub usable_hosts: u64,
    pub first_host: String,
    pub last_host: String,
    pub scope_note: String,
    pub host_role_note: String,
}

// ---------------------------------------------------------------- 基础运算

pub fn parse_ipv4(s: &str) -> CoreResult<Ipv4Addr> {
    Ipv4Addr::from_str(s.trim()).map_err(|_| CoreError::InvalidIpv4(s.trim().to_string()))
}

pub fn prefix_to_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

/// 点分掩码 → 前缀长度；非连续掩码（如 255.0.255.0）按旧版行为报错。
pub fn mask_to_prefix(mask: Ipv4Addr) -> CoreResult<u8> {
    let m = u32::from(mask);
    let inv = !m;
    // 连续 1 序列 ⟺ (inv + 1) & inv == 0
    if inv & inv.wrapping_add(1) != 0 {
        return Err(CoreError::InvalidNetmask(mask.to_string()));
    }
    Ok(m.count_ones() as u8)
}

pub fn network_of(ip: Ipv4Addr, prefix: u8) -> u32 {
    u32::from(ip) & prefix_to_mask(prefix)
}

pub fn broadcast_of(network: u32, prefix: u8) -> u32 {
    network | !prefix_to_mask(prefix)
}

pub fn usable_host_count(prefix: u8) -> u64 {
    match prefix {
        32 => 1,
        31 => 2,
        _ => (1u64 << (32 - prefix)).saturating_sub(2),
    }
}

fn first_last_host(network: u32, prefix: u8) -> (u32, u32) {
    match prefix {
        32 => (network, network),
        31 => (network, broadcast_of(network, prefix)),
        _ => (network.wrapping_add(1), broadcast_of(network, prefix).wrapping_sub(1)),
    }
}

fn addr(u: u32) -> String {
    Ipv4Addr::from(u).to_string()
}

// ---------------------------------------------------------------- 语义标注

/// 本网段网络地址所属 IPv4 分类（运维可读摘要），判定顺序与旧版一致。
pub fn ipv4_network_scope_zh(network: u32) -> &'static str {
    let first_octet = (network >> 24) as u8;

    if first_octet == 127 {
        return "环回（127.0.0.0/8）";
    }
    if network & 0xFFFF_0000 == 0xA9FE_0000 {
        return "链路本地（169.254.0.0/16）";
    }
    if network & 0xF000_0000 == 0xE000_0000 {
        return "组播";
    }
    // 0.0.0.0/8、192.0.0.0/24、240.0.0.0/4
    if first_octet == 0
        || network & 0xFFFF_FF00 == 0xC000_0000
        || network & 0xF000_0000 == 0xF000_0000
    {
        return "保留地址";
    }
    if network & RFC6598.1 == RFC6598.0 {
        return "运营商共享地址空间（RFC 6598，常见 CGNAT，100.64.0.0/10）";
    }
    if first_octet == 10 || network & 0xFFF0_0000 == 0xAC10_0000 || network & 0xFFFF_0000 == 0xC0A8_0000 {
        return "私有单播（RFC 1918）";
    }
    "全局单播（公网）"
}

/// 输入 IP 相对本网的角色说明。
pub fn ipv4_host_role_zh(ip: u32, network: u32, prefix: u8) -> &'static str {
    match prefix {
        32 => return "/32 单主机前缀",
        31 => return "/31 点对点段内地址（RFC 3021）",
        _ => {}
    }
    if ip == network {
        return "网络地址（通常不可分配给主机）";
    }
    if ip == broadcast_of(network, prefix) {
        return "定向广播地址（通常不可分配给主机）";
    }
    if ip > network && ip < broadcast_of(network, prefix) {
        return "可用主机地址";
    }
    "不在本网可用主机集合内（请检查输入）"
}

// ---------------------------------------------------------------- 对外 API

/// 根据主机 IPv4 与前缀长度或点分掩码计算所属网络。
///
/// 掩码与前缀若同时提供，优先采用点分掩码（与旧版一致）。
pub fn calc_subnet(
    ip_part: &str,
    prefix_len: Option<u8>,
    netmask_dotted: Option<&str>,
) -> CoreResult<SubnetCalcResult> {
    let ip = parse_ipv4(ip_part)?;

    let prefix = match netmask_dotted.map(str::trim).filter(|s| !s.is_empty()) {
        Some(m) => mask_to_prefix(parse_ipv4(m)?)?,
        None => prefix_len.ok_or(CoreError::MissingPrefix)?,
    };
    if prefix > 32 {
        return Err(CoreError::InvalidPrefix(prefix as i64));
    }

    let ip_u = u32::from(ip);
    let network = network_of(ip, prefix);
    let broadcast = broadcast_of(network, prefix);
    let (first, last) = first_last_host(network, prefix);

    Ok(SubnetCalcResult {
        input_interface: format!("{}/{}", ip, prefix),
        network_cidr: format!("{}/{}", addr(network), prefix),
        network_address: addr(network),
        broadcast_address: addr(broadcast),
        netmask: addr(prefix_to_mask(prefix)),
        wildcard_mask: addr(!prefix_to_mask(prefix)),
        prefix_len: prefix,
        total_addresses: 1u64 << (32 - prefix),
        usable_hosts: usable_host_count(prefix),
        first_host: addr(first),
        last_host: addr(last),
        scope_note: ipv4_network_scope_zh(network).to_string(),
        host_role_note: ipv4_host_role_zh(ip_u, network, prefix).to_string(),
    })
}

/// 解析 `192.168.1.10/24` 或 `192.168.1.10/255.255.255.0`。
pub fn calc_from_cidr_combo(combo: &str) -> CoreResult<SubnetCalcResult> {
    let s = combo.trim();
    let (ip_s, suffix) = s.split_once('/').ok_or(CoreError::BadCidrCombo)?;
    let ip = parse_ipv4(ip_s)?;

    let prefix = if suffix.contains('.') {
        mask_to_prefix(parse_ipv4(suffix)?)?
    } else {
        suffix
            .parse::<u8>()
            .map_err(|_| CoreError::InvalidPrefix(0))?
    };
    calc_subnet(&ip.to_string(), Some(prefix), None)
}

/// 将父网等长划分为 `child_prefix` 长度的子网列表（最多列出 `max_list` 条）。
pub fn subdivide_ipv4_equal_children(parent_spec: &str, child_prefix: u8, max_list: usize) -> CoreResult<String> {
    let s = parent_spec.trim();
    if s.is_empty() {
        return Err(CoreError::InvalidParentCidr("请填写父网 CIDR。".into()));
    }
    let (ip_s, suffix) = s.split_once('/').ok_or(CoreError::BadCidrCombo)?;
    let ip = parse_ipv4(ip_s)?;
    let parent_prefix = if suffix.contains('.') {
        mask_to_prefix(parse_ipv4(suffix)?)?
    } else {
        suffix.parse::<u8>().map_err(|_| CoreError::InvalidParentCidr(s.to_string()))?
    };

    if child_prefix > 32 {
        return Err(CoreError::InvalidPrefix(child_prefix as i64));
    }
    if child_prefix <= parent_prefix {
        return Err(CoreError::ChildPrefixTooSmall(parent_prefix));
    }

    let network = network_of(ip, parent_prefix);
    let step = 1u64 << (32 - child_prefix);
    let total = 1u64 << (child_prefix - parent_prefix);
    let cap = max_list.max(1) as u64;
    let shown = total.min(cap);

    let mut out = String::new();
    out.push_str("=== 等长子网划分 ===\n\n");
    out.push_str(&format!("父网：{}/{}\n", addr(network), parent_prefix));
    out.push_str(&format!("划至前缀：/{}\n", child_prefix));
    out.push_str(&format!("子网数量：{}\n\n", total));

    for i in 0..shown {
        let sub = network as u64 + i * step;
        out.push_str(&format!("{:>4}. {}/{}\n", i + 1, addr(sub as u32), child_prefix));
    }
    if total > shown {
        out.push_str(&format!("... 省略其余 {} 条（共 {} 个子网）\n", total - shown, total));
    }
    out.push('\n');
    Ok(out)
}

// ---------------------------------------------------------------- 单测

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slash24_basic() {
        let r = calc_subnet("192.168.1.10", Some(24), None).unwrap();
        assert_eq!(r.network_cidr, "192.168.1.0/24");
        assert_eq!(r.broadcast_address, "192.168.1.255");
        assert_eq!(r.netmask, "255.255.255.0");
        assert_eq!(r.wildcard_mask, "0.0.0.255");
        assert_eq!(r.total_addresses, 256);
        assert_eq!(r.usable_hosts, 254);
        assert_eq!(r.first_host, "192.168.1.1");
        assert_eq!(r.last_host, "192.168.1.254");
        assert_eq!(r.scope_note, "私有单播（RFC 1918）");
        assert_eq!(r.host_role_note, "可用主机地址");
    }

    #[test]
    fn network_and_broadcast_roles() {
        assert_eq!(
            calc_subnet("10.0.0.0", Some(8), None).unwrap().host_role_note,
            "网络地址（通常不可分配给主机）"
        );
        assert_eq!(
            calc_subnet("10.255.255.255", Some(8), None).unwrap().host_role_note,
            "定向广播地址（通常不可分配给主机）"
        );
    }

    #[test]
    fn slash31_and_32() {
        let r31 = calc_subnet("10.0.0.1", Some(31), None).unwrap();
        assert_eq!(r31.usable_hosts, 2);
        assert_eq!(r31.first_host, "10.0.0.0");
        assert_eq!(r31.last_host, "10.0.0.1");

        let r32 = calc_subnet("10.0.0.1", Some(32), None).unwrap();
        assert_eq!(r32.usable_hosts, 1);
        assert_eq!(r32.first_host, "10.0.0.1");
        assert_eq!(r32.host_role_note, "/32 单主机前缀");
    }

    #[test]
    fn dotted_netmask_preferred() {
        let r = calc_subnet("172.16.5.9", Some(8), Some("255.255.0.0")).unwrap();
        assert_eq!(r.prefix_len, 16);
        assert_eq!(r.network_cidr, "172.16.0.0/16");
    }

    #[test]
    fn rejects_non_contiguous_mask() {
        assert!(calc_subnet("10.0.0.1", None, Some("255.0.255.0")).is_err());
    }

    #[test]
    fn scope_classification() {
        assert_eq!(calc_subnet("127.0.0.1", Some(8), None).unwrap().scope_note, "环回（127.0.0.0/8）");
        assert_eq!(
            calc_subnet("169.254.3.4", Some(16), None).unwrap().scope_note,
            "链路本地（169.254.0.0/16）"
        );
        assert_eq!(
            calc_subnet("100.64.1.1", Some(10), None).unwrap().scope_note,
            "运营商共享地址空间（RFC 6598，常见 CGNAT，100.64.0.0/10）"
        );
        assert_eq!(calc_subnet("8.8.8.8", Some(24), None).unwrap().scope_note, "全局单播（公网）");
    }

    #[test]
    fn combo_form() {
        let a = calc_from_cidr_combo("192.168.1.10/24").unwrap();
        let b = calc_from_cidr_combo("192.168.1.10/255.255.255.0").unwrap();
        assert_eq!(a, b);
        assert!(calc_from_cidr_combo("192.168.1.10").is_err());
    }

    #[test]
    fn subdivide_counts() {
        let text = subdivide_ipv4_equal_children("192.168.1.0/24", 26, 64).unwrap();
        assert!(text.contains("子网数量：4"));
        assert!(text.contains("192.168.1.0/26"));
        assert!(text.contains("192.168.1.192/26"));

        let capped = subdivide_ipv4_equal_children("10.0.0.0/8", 16, 3).unwrap();
        assert!(capped.contains("省略其余"));
    }

    #[test]
    fn subdivide_rejects_smaller_child() {
        assert!(subdivide_ipv4_equal_children("10.0.0.0/24", 16, 64).is_err());
    }
}
