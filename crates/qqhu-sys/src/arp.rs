//! ARP 邻居表采集。
//!
//! 三平台各自的实现：
//! - **Windows**：`GetIpNetTable2`（IP Helper API），直接拿结构化邻居表
//! - **Linux**：内核导出的 `/proc/net/arp`
//! - **macOS**：`sysctl(NET_RT_FLAGS)` 遍历路由表取 `RTF_LLINFO` 项
//!
//! 共同点：**不解析本地化的命令行输出**。Linux 的解析函数抽成公共纯函数，
//! 因此可以在任何平台上单测（含 Windows 上验证 Linux 格式）。

use qqhu_core::macscan::{is_broadcast, is_zero, normalize_mac, ArpState};

/// 一条平台无关的 ARP 邻居记录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpRecord {
    pub ip: String,
    /// 已归一为小写冒号格式；无法解析时保留原始写法
    pub mac: String,
    /// 接口友好名，取不到时为空串
    pub interface: String,
    pub state: ArpState,
}

/// 读取当前平台的 ARP 邻居表。
///
/// 出口统一做一次清洗：丢弃 MAC 为广播或全零的条目。
/// 内核会为每个子网的定向广播地址（如 /27 的 `.63`）建 ARP 条目，
/// 它们 MAC 都是 `ff:ff:ff:ff:ff:ff`，对「IP / MAC 对照」纯属噪声。
pub fn read_arp_table() -> Result<Vec<ArpRecord>, String> {
    let raw = platform_read()?;
    Ok(raw
        .into_iter()
        .filter(|r| !is_broadcast(&r.mac) && !is_zero(&r.mac))
        .collect())
}

fn platform_read() -> Result<Vec<ArpRecord>, String> {
    #[cfg(windows)]
    {
        windows_impl::read()
    }
    #[cfg(target_os = "linux")]
    {
        linux_impl::read()
    }
    #[cfg(target_os = "macos")]
    {
        macos_impl::read()
    }
}

/// 解析 `/proc/net/arp` 的内容。
///
/// 格式（内核固定，不随语言变化）：
/// ```text
/// IP address       HW type     Flags       HW address            Mask     Device
/// 192.168.60.62    0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
/// ```
/// `Flags` 位：`0x2` 表示条目不完整（ATF_INCOMPLETE）、`0x4` 表示永久（ATF_PERM）。
/// 不完整条目（无有效 MAC）会被过滤掉。
pub fn parse_proc_net_arp(text: &str) -> Vec<ArpRecord> {
    let mut out = Vec::new();

    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }
        let ip = cols[0];
        if ip.parse::<std::net::Ipv4Addr>().is_err() {
            continue;
        }
        let flags = u32::from_str_radix(cols[2].trim_start_matches("0x"), 16).unwrap_or(0);
        let raw_mac = cols[3];
        let interface = cols.get(5).copied().unwrap_or("").to_string();

        // 0x0 即 ATF_INCOMPLETE：发了请求但没有应答，MAC 全零，不值得展示
        let complete = flags & 0x2 != 0;
        let mac = normalize_mac(raw_mac);
        if !complete || mac.is_none() {
            continue;
        }
        let mac = mac.unwrap();
        if mac == "00:00:00:00:00:00" {
            continue;
        }

        let state = if flags & 0x4 != 0 {
            ArpState::Permanent
        } else {
            ArpState::Reachable
        };

        out.push(ArpRecord {
            ip: ip.to_string(),
            mac,
            interface,
            state,
        });
    }

    out
}

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToAlias, FreeMibTable, GetIpNetTable2,
        MIB_IPNET_TABLE2,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows_sys::Win32::Networking::WinSock::{
        NlnsIncomplete, NlnsPermanent, NlnsReachable, NlnsStale, AF_INET,
    };

    pub fn read() -> Result<Vec<ArpRecord>, String> {
        let mut table: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();

        // SAFETY: 传空指针让 API 分配；成功后必须用 FreeMibTable 释放
        let rc = unsafe { GetIpNetTable2(AF_INET as u16, &mut table) };
        if rc != 0 || table.is_null() {
            return Err(format!("GetIpNetTable2 失败（错误码 {rc}）"));
        }

        let mut out = Vec::new();
        unsafe {
            let n = (*table).NumEntries as usize;
            // Table 在声明里是 [MIB_IPNET_ROW2; 1]，实际是长度 NumEntries 的变长数组
            let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), n);

            for row in rows {
                let family = row.Address.si_family;
                if family != AF_INET as u16 {
                    continue;
                }

                // sin_addr.S_addr 是网络字节序
                let raw = row.Address.Ipv4.sin_addr.S_un.S_addr;
                let ip = std::net::Ipv4Addr::from(u32::from_be(raw)).to_string();

                let len = (row.PhysicalAddressLength as usize).min(32);
                if len != 6 {
                    continue; // 非以太网地址（如隧道接口的 8 字节地址）不展示
                }
                let mac = normalize_mac(&format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    row.PhysicalAddress[0],
                    row.PhysicalAddress[1],
                    row.PhysicalAddress[2],
                    row.PhysicalAddress[3],
                    row.PhysicalAddress[4],
                    row.PhysicalAddress[5]
                ));
                let mac = match mac {
                    Some(m) if m != "00:00:00:00:00:00" => m,
                    _ => continue, // 不完整条目，MAC 全零
                };

                let state = match row.State {
                    s if s == NlnsReachable => ArpState::Reachable,
                    s if s == NlnsStale => ArpState::Stale,
                    s if s == NlnsPermanent => ArpState::Permanent,
                    s if s == NlnsIncomplete => ArpState::Incomplete,
                    _ => ArpState::Other,
                };

                out.push(ArpRecord {
                    ip,
                    mac,
                    interface: interface_alias(row.InterfaceIndex),
                    state,
                });
            }

            FreeMibTable(table as *const core::ffi::c_void);
        }

        // 按 IP 升序，让界面与导出结果稳定
        out.sort_by_key(|r| {
            r.ip.parse::<std::net::Ipv4Addr>()
                .map(u32::from)
                .unwrap_or(u32::MAX)
        });
        Ok(out)
    }

    /// 接口索引 → 友好名（如「以太网」）。失败时返回索引字符串。
    fn interface_alias(index: u32) -> String {
        unsafe {
            let mut luid = NET_LUID_LH::default();
            if ConvertInterfaceIndexToLuid(index, &mut luid) != 0 {
                return index.to_string();
            }
            let mut buf = [0u16; 128];
            if ConvertInterfaceLuidToAlias(&luid, buf.as_mut_ptr(), buf.len()) != 0 {
                return index.to_string();
            }
            let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
            let name = String::from_utf16_lossy(&buf[..end]);
            if name.is_empty() {
                index.to_string()
            } else {
                name
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;

    pub fn read() -> Result<Vec<ArpRecord>, String> {
        let text = std::fs::read_to_string("/proc/net/arp")
            .map_err(|e| format!("读取 /proc/net/arp 失败：{e}"))?;
        Ok(parse_proc_net_arp(&text))
    }
}

#[cfg(target_os = "macos")]
mod macos_impl {
    use super::*;

    /// 通过 `sysctl(NET_RT_FLAGS)` 读路由表，只取带链路层地址（RTF_LLINFO）的项。
    ///
    /// 注意：本实现**未在 macOS 真机上验证过**（开发环境是 Windows）。
    /// 逻辑参照 `netstat -an` 的内核数据来源，结构定义来自 libc 的 apple 模块。
    pub fn read() -> Result<Vec<ArpRecord>, String> {
        use libc::{c_int, c_void};

        let mut mib = [
            libc::CTL_NET as c_int,
            libc::PF_ROUTE as c_int,
            0,
            0,
            libc::NET_RT_FLAGS as c_int,
            libc::RTF_LLINFO,
        ];

        // 先问长度，再分配，避免缓冲区不够时拿到截断数据
        let mut len: libc::size_t = 0;
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            return Err(format!("sysctl(NET_RT_FLAGS) 取长度失败：{}", std::io::Error::last_os_error()));
        }
        if len == 0 {
            return Ok(Vec::new());
        }

        let mut buf = vec![0u8; len];
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                buf.as_mut_ptr() as *mut c_void,
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            return Err(format!("sysctl(NET_RT_FLAGS) 读数据失败：{}", std::io::Error::last_os_error()));
        }
        buf.truncate(len as usize);

        Ok(parse_route_dump(&buf))
    }

    /// 解析路由表转储。
    ///
    /// 每条记录是 `rt_msghdr` + 若干个 `sockaddr`（顺序由 `rtm_addrs` 位图决定：
    /// 目标、网关、掩码……）。对 `RTF_LLINFO` 项，目标是 `sockaddr_in`（含 IP），
    /// 网关是 `sockaddr_dl`（含 MAC）。
    fn parse_route_dump(buf: &[u8]) -> Vec<ArpRecord> {
        use libc::{rt_msghdr, sockaddr_dl, sockaddr_in, RTAX_DST, RTAX_GATEWAY, RTA_GATEWAY, RTF_LLINFO};

        const RTA_DST: c_int = 1;
        let hdr_size = std::mem::size_of::<rt_msghdr>();
        let mut out = Vec::new();
        let mut off = 0usize;

        while off + hdr_size <= buf.len() {
            // SAFETY: off + hdr_size 已检查在界内；rt_msghdr 是 POD
            let hdr: rt_msghdr = unsafe { std::ptr::read_unaligned(buf[off..].as_ptr() as *const rt_msghdr) };
            let msglen = hdr.rtm_msglen as usize;
            if msglen < hdr_size || off + msglen > buf.len() {
                break;
            }

            if hdr.rtm_flags & RTF_LLINFO != 0 {
                let base = off + hdr_size;
                let end = off + msglen;

                let mut addrs: Vec<&[u8]> = Vec::new();
                let mut p = base;
                // rtm_addrs 是位图，低位优先依次对应 DST/GATEWAY/NETMASK/...
                for bit in 0..RTAX_GATEWAY + 1 {
                    if hdr.rtm_addrs & (1 << bit) == 0 {
                        continue;
                    }
                    if p + 2 > end {
                        break;
                    }
                    let slen = buf[p] as usize;
                    if slen < 2 || p + slen > end {
                        break;
                    }
                    addrs.push(&buf[p..p + slen]);
                    // sockaddr 按 sizeof(long) 对齐后推进
                    let step = if slen % 4 == 0 { slen } else { slen + (4 - slen % 4) };
                    p += step;
                }

                let ip = if hdr.rtm_addrs & RTA_DST != 0 && !addrs.is_empty() {
                    read_sockaddr_in_ip(addrs[0])
                } else {
                    None
                };
                let mac = if hdr.rtm_addrs & RTA_GATEWAY != 0 && addrs.len() > 1 {
                    read_sockaddr_dl_mac(addrs[1])
                } else {
                    None
                };

                if let (Some(ip), Some(mac)) = (ip, mac) {
                    out.push(ArpRecord {
                        ip,
                        mac,
                        interface: interface_name(addrs.get(1).copied(), hdr.rtm_index as usize),
                        state: ArpState::Reachable,
                    });
                }
                // 明确引用被用到的常量，避免不同 libc 版本里重命名导致未使用告警
                let _ = (RTA_GATEWAY, sockaddr_in::default, sockaddr_dl::default);
            }

            off += msglen;
        }

        out.sort_by_key(|r| r.ip.parse::<std::net::Ipv4Addr>().map(u32::from).unwrap_or(u32::MAX));
        out
    }

    fn read_sockaddr_in_ip(raw: &[u8]) -> Option<String> {
        use libc::sockaddr_in;
        if raw.len() < std::mem::size_of::<sockaddr_in>() {
            return None;
        }
        // SAFETY: 长度已检查，sockaddr_in 是 POD
        let sa: sockaddr_in = unsafe { std::ptr::read_unaligned(raw.as_ptr() as *const sockaddr_in) };
        if sa.sin_family as c_int != libc::AF_INET {
            return None;
        }
        let ip = std::net::Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
        Some(ip.to_string())
    }

    fn read_sockaddr_dl_mac(raw: &[u8]) -> Option<String> {
        use libc::sockaddr_dl;
        let hdr = std::mem::size_of::<sockaddr_dl>();
        if raw.len() < hdr {
            return None;
        }
        // SAFETY: 长度已检查，sockaddr_dl 是 POD
        let dl: sockaddr_dl = unsafe { std::ptr::read_unaligned(raw.as_ptr() as *const sockaddr_dl) };
        if dl.sdl_family as c_int != libc::AF_LINK || dl.sdl_alen as usize != 6 {
            return None;
        }
        // sdl_data 是柔性数组：前 sdl_nlen 字节是接口名，其后 sdl_alen 字节是 MAC
        let data_off = hdr - dl.sdl_data.len();
        let mac_off = data_off + dl.sdl_nlen as usize;
        if mac_off + 6 > raw.len() {
            return None;
        }
        let b = &raw[mac_off..mac_off + 6];
        normalize_mac(&format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        ))
    }

    fn interface_name(gateway: Option<&[u8]>, index: usize) -> String {
        use libc::sockaddr_dl;
        let raw = match gateway {
            Some(r) => r,
            None => return index.to_string(),
        };
        let hdr = std::mem::size_of::<sockaddr_dl>();
        if raw.len() < hdr {
            return index.to_string();
        }
        let dl: sockaddr_dl = unsafe { std::ptr::read_unaligned(raw.as_ptr() as *const sockaddr_dl) };
        let data_off = hdr - dl.sdl_data.len();
        let nlen = dl.sdl_nlen as usize;
        if nlen == 0 || data_off + nlen > raw.len() {
            return index.to_string();
        }
        String::from_utf8_lossy(&raw[data_off..data_off + nlen]).to_string()
    }

    use libc::c_int;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_proc_net_arp_skips_incomplete_and_header() {
        let text = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.60.62    0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
192.168.60.99    0x1         0x0         00:00:00:00:00:00     *        eth0
192.168.60.7     0x1         0x6         11:22:33:44:55:66     *        eth0
";
        let rs = parse_proc_net_arp(text);
        assert_eq!(rs.len(), 2, "表头与不完整条目都应被过滤");

        assert_eq!(rs[0].ip, "192.168.60.62");
        assert_eq!(rs[0].mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(rs[0].interface, "eth0");
        assert_eq!(rs[0].state, ArpState::Reachable);

        // 0x6 = ATF_PERM | ATF_COM
        assert_eq!(rs[1].state, ArpState::Permanent);
    }

    #[test]
    fn parse_proc_net_arp_tolerates_odd_input() {
        assert!(parse_proc_net_arp("").is_empty());
        assert!(parse_proc_net_arp("garbage\n").is_empty());
        assert!(parse_proc_net_arp("1.2.3.4 0x1 0x2\n").is_empty(), "列数不足应跳过");
    }

    /// 真实环境读取：任何平台都应能返回（允许为空表），不应 panic。
    #[test]
    fn read_arp_table_does_not_panic() {
        match read_arp_table() {
            Ok(rows) => {
                for r in &rows {
                    assert!(!r.ip.is_empty());
                    assert!(r.mac.contains(':'), "MAC 应已归一化：{}", r.mac);
                }
            }
            Err(e) => {
                // Windows 上 GetIpNetTable2 在极少数受限环境会失败，
                // 这里只要求错误信息可读，不强制成功
                assert!(!e.is_empty());
            }
        }
    }
}
