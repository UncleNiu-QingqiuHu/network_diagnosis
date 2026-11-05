//! 本机网络接口枚举与默认网关。
//!
//! 目的：IP/MAC 扫描不再硬编码 `192.168.1.0/24`，而是按本机真实接口推断网段。
//!
//! 三平台实现：
//! - **Windows**：`GetAdaptersAddresses` 枚举适配器，`GetIpForwardTable2` 取默认路由
//! - **Linux**：`getifaddrs` 枚举，`/proc/net/route` 取默认路由
//! - **macOS**：`getifaddrs` 枚举，`sysctl(NET_RT_DUMP)` 取默认路由
//!
//! 与 ARP 采集一致：**不解析本地化的命令行输出**。

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// 一个本机 IPv4 接口快照。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetInterface {
    /// 接口名：Windows 为「以太网」这类友好名，Unix 为 `eth0` / `en0`
    pub name: String,
    /// 接口描述，Unix 与 name 相同
    pub description: String,
    pub ip: Ipv4Addr,
    /// 前缀长度，即掩码中 1 的个数
    pub prefix_len: u8,
    /// 物理地址（小写冒号格式）；非以太网接口为 `None`
    pub mac: Option<String>,
    pub is_up: bool,
    pub is_loopback: bool,
    /// 是否为对该接口的默认路由出口
    pub has_gateway: bool,
}

impl NetInterface {
    /// 该接口的网段，形如 `192.168.60.0/24`。
    pub fn scope(&self) -> String {
        scope_of(self.ip, self.prefix_len)
    }
}

/// 把 `ip/prefix` 归一为网络地址写法。
///
/// 前缀不在 1..=32 时按 /24 处理，避免出现 `0.0.0.0/0` 这种无法扫描的范围。
pub fn scope_of(ip: Ipv4Addr, prefix_len: u8) -> String {
    let prefix = if (1..=32).contains(&prefix_len) { prefix_len } else { 24 };
    let mask: u32 = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    let net = Ipv4Addr::from(u32::from(ip) & mask);
    format!("{net}/{prefix}")
}

/// 从接口列表推断建议扫描范围。
///
/// 优先级：
/// 1. 默认路由出口所在接口
/// 2. 第一个已启用、非环回、非链路本地（169.254/16）的接口
///
/// 扫描一个 /24 是最常见的诉求，因此当前缀过窄（>30）或过宽（<8，比如误报 /0）时，
/// 收敛到该地址所在的 /24，避免扫出无意义的海量目标。
pub fn suggest_scope(ifs: &[NetInterface]) -> Option<String> {
    let pick = ifs
        .iter()
        .find(|i| i.has_gateway && usable(i))
        .or_else(|| ifs.iter().find(|i| usable(i)))?;

    let prefix = if (8..=30).contains(&pick.prefix_len) {
        pick.prefix_len
    } else {
        24
    };
    Some(scope_of(pick.ip, prefix))
}

fn usable(i: &NetInterface) -> bool {
    i.is_up
        && !i.is_loopback
        && !i.ip.is_loopback()
        && !i.ip.is_link_local()
        && i.ip != Ipv4Addr::UNSPECIFIED
}

/// 读取本机全部 IPv4 接口，按「有网关优先、网段小的优先」排序，便于前端直接取首项。
pub fn local_interfaces() -> Result<Vec<NetInterface>, String> {
    let mut list = platform_interfaces()?;
    list.retain(|i| i.ip != Ipv4Addr::UNSPECIFIED);

    // 稳定排序：有网关的在前，其次已启用，最后按 IP 升序
    list.sort_by_key(|i| (!i.has_gateway, !i.is_up, i.is_loopback, u32::from(i.ip)));
    Ok(list)
}

/// 默认网关地址（仅 IPv4）。
pub fn default_gateway() -> Option<Ipv4Addr> {
    platform_default_gateway()
}

/// 一步拿到建议网段；接口枚举失败或无可用接口时返回 `None`。
pub fn suggested_scope() -> Option<String> {
    let list = local_interfaces().ok()?;
    suggest_scope(&list)
}

fn platform_interfaces() -> Result<Vec<NetInterface>, String> {
    #[cfg(windows)]
    {
        windows_impl::interfaces()
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        unix_impl::interfaces()
    }
}

fn platform_default_gateway() -> Option<Ipv4Addr> {
    #[cfg(windows)]
    {
        windows_impl::default_gateway()
    }
    #[cfg(target_os = "linux")]
    {
        unix_impl::linux_default_gateway()
    }
    #[cfg(target_os = "macos")]
    {
        unix_impl::macos_default_gateway()
    }
}

/// 把接口列表里「有网关」的标记补上。
fn mark_gateway(list: &mut [NetInterface], gateway: Option<Ipv4Addr>) {
    if let Some(gw) = gateway {
        for i in list.iter_mut() {
            let mask = if i.prefix_len == 0 || i.prefix_len > 32 {
                0
            } else {
                u32::MAX << (32 - i.prefix_len)
            };
            i.has_gateway = (u32::from(gw) & mask) == (u32::from(i.ip) & mask);
        }
    }
}

// ---------------------------------------------------------------- Windows

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use qqhu_core::macscan::normalize_mac;
    use windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetAdaptersAddresses, GetIpForwardTable2, GAA_FLAG_INCLUDE_PREFIX,
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
        MIB_IPFORWARD_TABLE2,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_UNSPEC, SOCKADDR_IN};

    const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;

    pub fn interfaces() -> Result<Vec<NetInterface>, String> {
        let flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
        let mut size: u32 = 16 * 1024;
        let mut buf = vec![0u8; size as usize];

        // 第一次调用拿实际所需长度（ERROR_BUFFER_OVERFLOW 是预期路径，不是错误）
        let mut rc = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                flags,
                std::ptr::null(),
                buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut size,
            )
        };
        if rc == ERROR_BUFFER_OVERFLOW {
            buf.resize(size as usize, 0);
            rc = unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC as u32,
                    flags,
                    std::ptr::null(),
                    buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                    &mut size,
                )
            };
        }
        if rc != 0 {
            return Err(format!("GetAdaptersAddresses 失败（错误码 {rc}）"));
        }

        let gateway = default_gateway();
        let mut out = Vec::new();

        unsafe {
            let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
            while !cur.is_null() {
                let a = &*cur;

                // 每个适配器可能有多个单播地址（含 IPv6），只保留 IPv4
                let mut uni = a.FirstUnicastAddress;
                while !uni.is_null() {
                    let u = &*uni;
                    if let Some((ip, prefix)) = read_unicast_v4(&u.Address, u.OnLinkPrefixLength) {
                        out.push(NetInterface {
                            name: wide(a.FriendlyName),
                            description: wide(a.Description),
                            ip,
                            prefix_len: prefix,
                            mac: mac_of(a),
                            is_up: a.OperStatus == IfOperStatusUp,
                            is_loopback: a.IfType == IF_TYPE_SOFTWARE_LOOPBACK
                                || ip.is_loopback(),
                            has_gateway: false,
                        });
                    }
                    uni = u.Next;
                }

                cur = a.Next;
            }
        }

        mark_gateway(&mut out, gateway);
        Ok(out)
    }

    unsafe fn read_unicast_v4(
        addr: &windows_sys::Win32::Networking::WinSock::SOCKET_ADDRESS,
        prefix: u8,
    ) -> Option<(Ipv4Addr, u8)> {
        if addr.lpSockaddr.is_null() {
            return None;
        }
        let sa = &*(addr.lpSockaddr as *const SOCKADDR_IN);
        if sa.sin_family != AF_INET {
            return None;
        }
        let ip = Ipv4Addr::from(u32::from_be(sa.sin_addr.S_un.S_addr));
        Some((ip, prefix))
    }

    fn mac_of(a: &IP_ADAPTER_ADDRESSES_LH) -> Option<String> {
        if a.PhysicalAddressLength != 6 {
            return None;
        }
        normalize_mac(&format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            a.PhysicalAddress[0],
            a.PhysicalAddress[1],
            a.PhysicalAddress[2],
            a.PhysicalAddress[3],
            a.PhysicalAddress[4],
            a.PhysicalAddress[5]
        ))
    }

    fn wide(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        unsafe {
            while *p.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
        }
    }

    pub fn default_gateway() -> Option<Ipv4Addr> {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        // SAFETY: 空指针让 API 分配，成功后用 FreeMibTable 释放
        let rc = unsafe { GetIpForwardTable2(AF_INET as u16, &mut table) };
        if rc != 0 || table.is_null() {
            return None;
        }

        let mut best: Option<(u32, Ipv4Addr)> = None;
        unsafe {
            let n = (*table).NumEntries as usize;
            let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), n);
            for row in rows {
                // 默认路由：目的前缀长度 0
                if row.DestinationPrefix.PrefixLength != 0 {
                    continue;
                }
                if row.NextHop.si_family != AF_INET {
                    continue;
                }
                let hop = Ipv4Addr::from(u32::from_be(row.NextHop.Ipv4.sin_addr.S_un.S_addr));
                if hop.is_unspecified() {
                    continue;
                }
                let metric = row.Metric;
                if best.map_or(true, |(m, _)| metric < m) {
                    best = Some((metric, hop));
                }
            }
            FreeMibTable(table as *const core::ffi::c_void);
        }

        best.map(|(_, ip)| ip)
    }
}

// ---------------------------------------------------------------- Unix

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix_impl {
    use super::*;

    pub fn interfaces() -> Result<Vec<NetInterface>, String> {
        use libc::{c_char, ifaddrs};

        let mut head: *mut ifaddrs = std::ptr::null_mut();
        if unsafe { libc::getifaddrs(&mut head) } != 0 {
            return Err(format!("getifaddrs 失败：{}", std::io::Error::last_os_error()));
        }

        // 先按名字收集：IPv4 地址与链路层地址在 ifaddrs 里是两条独立记录
        let mut v4: Vec<NetInterface> = Vec::new();
        let mut macs: Vec<(String, String)> = Vec::new();

        unsafe {
            let mut cur = head;
            while !cur.is_null() {
                let it = &*cur;
                let name = cstr(it.ifa_name as *const c_char);
                let flags = it.ifa_flags;
                let up = flags & libc::IFF_UP as u32 != 0;
                let loopback = flags & libc::IFF_LOOPBACK as u32 != 0;

                if !it.ifa_addr.is_null() {
                    let family = (*it.ifa_addr).sa_family as i32;
                    if family == libc::AF_INET {
                        if let Some(ip) = read_v4(it.ifa_addr) {
                            let prefix = read_prefix(it.ifa_netmask);
                            v4.push(NetInterface {
                                name: name.clone(),
                                description: name.clone(),
                                ip,
                                prefix_len: prefix,
                                mac: None,
                                is_up: up,
                                is_loopback: loopback || ip.is_loopback(),
                                has_gateway: false,
                            });
                        }
                    } else if let Some(m) = read_mac(it.ifa_addr, family) {
                        macs.push((name, m));
                    }
                }

                cur = it.ifa_next;
            }
            libc::freeifaddrs(head);
        }

        for i in v4.iter_mut() {
            i.mac = macs.iter().find(|(n, _)| *n == i.name).map(|(_, m)| m.clone());
        }

        let gateway = super::platform_default_gateway();
        mark_gateway(&mut v4, gateway);
        Ok(v4)
    }

    unsafe fn read_v4(addr: *const libc::sockaddr) -> Option<Ipv4Addr> {
        let sin = &*(addr as *const libc::sockaddr_in);
        Some(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)))
    }

    unsafe fn read_prefix(mask: *const libc::sockaddr) -> u8 {
        if mask.is_null() {
            return 24;
        }
        let sin = &*(mask as *const libc::sockaddr_in);
        let bits = u32::from_be(sin.sin_addr.s_addr).count_ones();
        if bits == 0 {
            24
        } else {
            bits as u8
        }
    }

    /// 取链路层地址。Linux 用 `sockaddr_ll`，macOS 用 `sockaddr_dl`，
    /// 两者的常量与结构体互不存在，因此按目标平台分别编译。
    unsafe fn read_mac(addr: *const libc::sockaddr, family: i32) -> Option<String> {
        #[cfg(target_os = "linux")]
        let bytes: &[u8] = {
            if family != libc::AF_PACKET {
                return None;
            }
            let ll = &*(addr as *const libc::sockaddr_ll);
            if ll.sll_halen as usize != 6 {
                return None;
            }
            &ll.sll_addr[..6]
        };

        #[cfg(target_os = "macos")]
        let bytes: &[u8] = {
            if family != libc::AF_LINK {
                return None;
            }
            let dl = &*(addr as *const libc::sockaddr_dl);
            if dl.sdl_alen as usize != 6 {
                return None;
            }
            let base = dl.sdl_data.as_ptr() as *const u8;
            let off = dl.sdl_nlen as usize;
            std::slice::from_raw_parts(base.add(off), 6)
        };

        let _ = family;

        let s = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        );
        if s == "00:00:00:00:00:00" {
            None
        } else {
            Some(s)
        }
    }

    fn cstr(p: *const libc::c_char) -> String {
        if p.is_null() {
            return String::new();
        }
        unsafe { std::ffi::CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }

    /// `/proc/net/route`：Destination 与 Gateway 是 16 进制小端序。
    pub fn linux_default_gateway() -> Option<Ipv4Addr> {
        let text = std::fs::read_to_string("/proc/net/route").ok()?;
        parse_proc_net_route(&text)
    }

    pub fn parse_proc_net_route(text: &str) -> Option<Ipv4Addr> {
        for line in text.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 4 {
                continue;
            }
            let dest = u32::from_str_radix(cols[1], 16).unwrap_or(u32::MAX);
            let gw = u32::from_str_radix(cols[2], 16).unwrap_or(0);
            let flags = u32::from_str_radix(cols[3], 16).unwrap_or(0);
            // RTF_UP(0x1) | RTF_GATEWAY(0x2)，且目的为默认路由
            if dest == 0 && flags & 0x3 == 0x3 && gw != 0 {
                return Some(Ipv4Addr::from(gw.swap_bytes()));
            }
        }
        None
    }

    /// macOS：遍历路由表转储，找目的为 0.0.0.0 且带 RTF_GATEWAY 的项。
    pub fn macos_default_gateway() -> Option<Ipv4Addr> {
        use libc::{c_int, c_void};

        let mut mib = [
            libc::CTL_NET as c_int,
            libc::PF_ROUTE as c_int,
            0,
            0,
            libc::NET_RT_DUMP as c_int,
            0,
        ];
        let mut len: libc::size_t = 0;
        if unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        } != 0
        {
            return None;
        }
        if len == 0 {
            return None;
        }

        let mut buf = vec![0u8; len];
        if unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                buf.as_mut_ptr() as *mut c_void,
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        } != 0
        {
            return None;
        }
        buf.truncate(len as usize);

        parse_route_default(&buf)
    }

    fn parse_route_default(buf: &[u8]) -> Option<Ipv4Addr> {
        use libc::{rt_msghdr, sockaddr_in};

        let hdr_size = std::mem::size_of::<rt_msghdr>();
        let mut off = 0usize;

        while off + hdr_size <= buf.len() {
            let hdr: rt_msghdr =
                unsafe { std::ptr::read_unaligned(buf[off..].as_ptr() as *const rt_msghdr) };
            let msglen = hdr.rtm_msglen as usize;
            if msglen < hdr_size || off + msglen > buf.len() {
                break;
            }

            let is_default = hdr.rtm_flags & libc::RTF_GATEWAY != 0
                // RTF_UP
                && hdr.rtm_flags & libc::RTF_UP != 0;

            if is_default {
                // 目标为默认路由时，RTA_DST 通常不存在；网关是第二个地址
                let gw_off = off + hdr_size;
                if gw_off + std::mem::size_of::<sockaddr_in>() <= off + msglen {
                    let sa: sockaddr_in =
                        unsafe { std::ptr::read_unaligned(buf[gw_off..].as_ptr() as *const sockaddr_in) };
                    if sa.sin_family as i32 == libc::AF_INET {
                        let ip = Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
                        if !ip.is_unspecified() && !ip.is_loopback() {
                            return Some(ip);
                        }
                    }
                }
            }

            off += msglen;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, ip: &str, prefix: u8, gw: bool, up: bool, lo: bool) -> NetInterface {
        NetInterface {
            name: name.into(),
            description: name.into(),
            ip: ip.parse().unwrap(),
            prefix_len: prefix,
            mac: None,
            is_up: up,
            is_loopback: lo,
            has_gateway: gw,
        }
    }

    #[test]
    fn scope_normalizes_to_network_address() {
        assert_eq!(scope_of("192.168.60.37".parse().unwrap(), 24), "192.168.60.0/24");
        assert_eq!(scope_of("10.20.30.40".parse().unwrap(), 22), "10.20.28.0/22");
        assert_eq!(scope_of("172.16.5.9".parse().unwrap(), 16), "172.16.0.0/16");
    }

    #[test]
    fn scope_falls_back_to_24_on_bad_prefix() {
        // /0 与 /33 都无法扫描，收敛到 /24
        assert_eq!(scope_of("192.168.1.9".parse().unwrap(), 0), "192.168.1.0/24");
        assert_eq!(scope_of("192.168.1.9".parse().unwrap(), 33), "192.168.1.0/24");
    }

    #[test]
    fn suggests_gateway_interface_first() {
        let list = [
            iface("VMware", "192.168.220.1", 24, false, true, false),
            iface("以太网", "10.0.5.23", 24, true, true, false),
        ];
        assert_eq!(suggest_scope(&list).as_deref(), Some("10.0.5.0/24"));
    }

    #[test]
    fn skips_loopback_and_link_local() {
        let list = [
            iface("lo", "127.0.0.1", 8, false, true, true),
            iface("以太网", "169.254.3.4", 16, false, true, false),
            iface("WLAN", "192.168.1.44", 24, false, true, false),
        ];
        assert_eq!(suggest_scope(&list).as_deref(), Some("192.168.1.0/24"));
    }

    #[test]
    fn returns_none_without_usable_interface() {
        let list = [iface("lo", "127.0.0.1", 8, false, true, true)];
        assert_eq!(suggest_scope(&list), None);
    }

    #[test]
    fn narrow_prefix_is_widened() {
        // 点对点 /32 没有可扫的邻居，回落到 /24
        let list = [iface("ppp0", "203.0.113.7", 32, true, true, false)];
        assert_eq!(suggest_scope(&list).as_deref(), Some("203.0.113.0/24"));
    }

    #[test]
    fn reads_linux_proc_net_route() {
        let text = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
";
        let gw = unix_impl_parse(text);
        assert_eq!(gw.map(|g| g.to_string()).as_deref(), Some("192.168.1.1"));
    }

    /// 复用 Linux 解析逻辑，让 Windows 开发机也能验证该格式。
    fn unix_impl_parse(text: &str) -> Option<Ipv4Addr> {
        for line in text.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 4 {
                continue;
            }
            let dest = u32::from_str_radix(cols[1], 16).unwrap_or(u32::MAX);
            let gw = u32::from_str_radix(cols[2], 16).unwrap_or(0);
            let flags = u32::from_str_radix(cols[3], 16).unwrap_or(0);
            if dest == 0 && flags & 0x3 == 0x3 && gw != 0 {
                return Some(Ipv4Addr::from(gw.swap_bytes()));
            }
        }
        None
    }

    /// 真实环境：允许失败（沙箱/无网络），但不许 panic。
    #[test]
    fn local_probe_is_infallible() {
        if let Ok(list) = local_interfaces() {
            for i in &list {
                assert!(i.prefix_len <= 32, "前缀长度越界：{}", i.prefix_len);
                assert!(!i.scope().is_empty());
                // 仅在 --nocapture 时可见，用于人工核对真实网卡数据
                eprintln!(
                    "[netif] {} ip={}/{} mac={:?} up={} gw={} → {}",
                    i.name,
                    i.ip,
                    i.prefix_len,
                    i.mac,
                    i.is_up,
                    i.has_gateway,
                    i.scope()
                );
            }
            eprintln!("[netif] gateway={:?} scope={:?}", default_gateway(), suggested_scope());
        }
        let _ = default_gateway();
        let _ = suggested_scope();
    }
}
