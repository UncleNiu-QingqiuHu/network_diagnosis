//! MAC 扫描：ARP 邻居模型与 OUI 厂商库。
//!
//! 纯数据结构 + 纯查表，不做 IO、不碰平台 API。
//! 各平台的 ARP 采集在 `qqhu-sys`，编排在 `qqhu-probe::macscan`。
//!
//! 关于厂商库的取舍：完整的 IEEE OUI 列表约 3 万条（1.5 MB），
//! 内置进来会撑大安装包且大部分条目用不上。这里只内置**确信无疑**的常见前缀，
//! 未命中一律显示「未知」——宁可留空，也不能给出错误归属。
//! 需要全量数据时，把 IEEE 的 `oui.csv` 放到 `config/oui.csv` 即可加载扩展。

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;

/// ARP 条目状态。各平台的原始枚举不同，这里归一到排障时有意义的几种。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ArpState {
    /// 可达（近期确认过）
    Reachable,
    /// 陈旧（曾经存在，需要重新确认）
    Stale,
    /// 静态绑定
    Permanent,
    /// 不完整（有请求但未收到应答）
    Incomplete,
    /// 其它
    Other,
}

impl ArpState {
    pub fn zh(self) -> &'static str {
        match self {
            ArpState::Reachable => "可达",
            ArpState::Stale => "陈旧",
            ArpState::Permanent => "静态",
            ArpState::Incomplete => "不完整",
            ArpState::Other => "其它",
        }
    }
}

/// 一条 ARP 邻居记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArpEntry {
    pub ip: String,
    /// 统一格式化为小写冒号分隔：`aa:bb:cc:dd:ee:ff`
    pub mac: String,
    /// OUI 厂商；未命中为空串
    pub vendor: String,
    /// 接口友好名，取不到时为索引数字
    pub interface: String,
    pub state: ArpState,
    /// 是否为本地管理地址（手机随机化 MAC 的典型特征）
    pub randomized: bool,
    /// 主动探测结果：`None` 表示本次未探测
    pub alive: Option<bool>,
}

/// 一次 MAC 扫描的完整结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MacScanReport {
    pub collected_at: String,
    /// 读取到的 ARP 条目数（含后续被过滤掉的）
    pub raw_count: usize,
    pub entries: Vec<ArpEntry>,
    /// 主动探测阶段探测的地址数；仅读表时为 0
    pub probed: usize,
    /// 主动探测阶段发现的存活数
    pub probed_alive: usize,
    pub warnings: Vec<String>,
}

impl MacScanReport {
    pub fn known_vendor_count(&self) -> usize {
        self.entries.iter().filter(|e| !e.vendor.is_empty()).count()
    }
}

// ---------------------------------------------------------------- OUI 厂商库

/// OUI 厂商库。键为 6 位大写十六进制前缀。
#[derive(Debug, Clone, Default)]
pub struct OuiDb {
    map: HashMap<String, String>,
}

impl OuiDb {
    /// 内置精简库。
    ///
    /// 只收录虚拟化平台、常见网络设备与固件厂商 —— 这些在排障时辨识价值最高，
    /// 且前缀是稳定公开的。手机与 PC 的 OUI 变动频繁，不做无把握的猜测。
    pub fn builtin() -> Self {
        static CACHE: OnceLock<OuiDb> = OnceLock::new();
        CACHE.get_or_init(OuiDb::build_builtin).clone()
    }

    fn build_builtin() -> Self {
        // 只收录前缀确定无疑的厂商。表短是刻意的：
        // 错误的厂商归属会让排障走错方向，比「未知」有害得多。
        // 未收录的一律显示「未知」，需要更全的库时加载 config/oui.csv。
        const TABLE: &[(&str, &str)] = &[
            // 虚拟化与容器：排障时最容易被误判成真实主机的一类
            ("000C29", "VMware"),
            ("005056", "VMware"),
            ("000569", "VMware"),
            ("080027", "Oracle VirtualBox"),
            ("0A0027", "VirtualBox Host-Only"),
            ("00155D", "Microsoft Hyper-V"),
            ("00163E", "Xen"),
            ("001C42", "Parallels"),
            ("525400", "QEMU/KVM"),
            ("0242AC", "Docker"),
            // 网络设备
            ("00000C", "Cisco"),
            ("00E0FC", "Huawei"),
            ("00259E", "Huawei"),
            // 终端与嵌入式
            ("000393", "Apple"),
            ("8C8590", "Apple"),
            ("F01898", "Apple"),
            ("001B21", "Intel"),
            ("B827EB", "Raspberry Pi"),
            ("DCA632", "Raspberry Pi"),
            ("50C7BF", "TP-Link"),
            ("001A11", "Google"),
            ("F4F5D8", "Google"),
        ];

        let mut map = HashMap::with_capacity(TABLE.len());
        for (prefix, name) in TABLE {
            let key = prefix.replace([' ', ':'], "").to_uppercase();
            if key.len() == 6 {
                map.insert(key, (*name).to_string());
            }
        }
        OuiDb { map }
    }

    /// 从 CSV 文本加载扩展库。
    ///
    /// 兼容两种格式：`前缀,厂商` 与 IEEE 官方 `oui.csv`（首行有表头，
    /// 第一列为 Registry、第二列为 `AABBCC`、第三列为组织名）。
    /// 返回解析出的条目数；无法识别的行静默跳过，不因一行脏数据整体失败。
    pub fn from_csv(text: &str) -> (Self, usize) {
        let mut map = HashMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let cols: Vec<&str> = line.split(',').collect();
            if cols.len() < 2 {
                continue;
            }

            // IEEE 格式：Registry,Assignment,Organization Name,...
            let (prefix, name) = if cols.len() >= 3 && cols[0].eq_ignore_ascii_case("ma-l") {
                (cols[1], cols[2])
            } else if cols.len() >= 3 && cols[1].trim().len() == 6 {
                (cols[1], cols[2])
            } else {
                (cols[0], cols[1])
            };

            let key = prefix.replace([' ', ':', '-'], "").to_uppercase();
            if key.len() != 6 || !key.chars().all(|c| c.is_ascii_hexdigit()) {
                continue; // 表头或脏数据
            }
            let name = name.trim().trim_matches('"');
            if name.is_empty() {
                continue;
            }
            map.insert(key, name.to_string());
        }
        let n = map.len();
        (OuiDb { map }, n)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// 合并另一个库；同名前缀以 `other` 为准（外部库可覆盖内置条目）。
    pub fn extend(&mut self, other: OuiDb) {
        self.map.extend(other.map);
    }

    /// MAC 的 OUI 前缀（前 3 字节，大写无分隔），用于在厂商未知时给用户自查线索。
    pub fn oui_prefix(mac: &str) -> Option<String> {
        let norm = normalize_mac(mac)?;
        Some(norm[..8].replace(':', "").to_uppercase())
    }

    /// 按 MAC 查厂商。查不到返回 `None`。
    pub fn lookup(&self, mac: &str) -> Option<&str> {
        let norm = normalize_mac(mac)?;
        let key = norm.replace(':', "").to_uppercase();
        if key.len() < 6 {
            return None;
        }
        self.map.get(&key[..6]).map(|s| s.as_str())
    }
}

/// 把各种写法的 MAC 归一为小写冒号格式。
///
/// 接受 `aa:bb:cc:dd:ee:ff`、`AA-BB-CC-DD-EE-FF`、`aabb.ccdd.eeff`、`aabbccddeeff`。
/// 只处理 6 字节的以太网地址；其它长度返回 `None`（例如某些隧道的 8 字节地址）。
pub fn normalize_mac(input: &str) -> Option<String> {
    let hex: String = input
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_lowercase();

    if hex.len() != 12 {
        return None;
    }
    let pairs: Vec<&str> = (0..12).step_by(2).map(|i| &hex[i..i + 2]).collect();
    Some(pairs.join(":"))
}

/// 是否为本地管理地址（第一字节的 bit 1）。
///
/// 手机与部分系统默认开启 MAC 随机化，这类地址的 OUI 没有厂商含义，
/// 直接按 OUI 归属会得出错误结论，因此单独标注。
/// 广播地址（全 `ff`）的第一字节也命中该位，但它是广播而非随机化，需排除。
pub fn is_locally_administered(mac: &str) -> bool {
    let norm = match normalize_mac(mac) {
        Some(n) => n,
        None => return false,
    };
    if norm == "ff:ff:ff:ff:ff:ff" {
        return false;
    }
    let first = u8::from_str_radix(&norm[..2], 16).unwrap_or(0);
    first & 0b0000_0010 != 0
}

/// 是否为全 `ff` 的广播地址。
pub fn is_broadcast(mac: &str) -> bool {
    normalize_mac(mac).map(|m| m == "ff:ff:ff:ff:ff:ff").unwrap_or(false)
}

/// 是否为全零地址（未填写的占位）。
pub fn is_zero(mac: &str) -> bool {
    normalize_mac(mac)
        .map(|m| m == "00:00:00:00:00:00")
        .unwrap_or(false)
}

/// 该 IP 是否值得出现在「IP / MAC 对照」里。
///
/// ARP 表里混有大量非主机条目：组播组的映射（224/4）、广播、`0.0.0.0`。
/// 把它们列出来只会淹没真正有用的邻居，所以在采集后就过滤掉。
pub fn is_arp_displayable(ip: &str) -> bool {
    let ip: std::net::Ipv4Addr = match ip.parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    let o = ip.octets();

    // 0.0.0.0/8 表示「本网络」，不是某个具体主机
    if o[0] == 0 {
        return false;
    }
    // 224.0.0.0/4 组播（含 239.x）
    if (224..=239).contains(&o[0]) {
        return false;
    }
    // 255.255.255.255 广播
    if ip == std::net::Ipv4Addr::BROADCAST {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_accepts_common_formats() {
        let expect = "aa:bb:cc:dd:ee:ff";
        for input in [
            "aa:bb:cc:dd:ee:ff",
            "AA:BB:CC:DD:EE:FF",
            "aa-bb-cc-dd-ee-ff",
            "aabb.ccdd.eeff",
            "aabbccddeeff",
            " AA:BB:CC:DD:EE:FF ",
        ] {
            assert_eq!(normalize_mac(input).as_deref(), Some(expect), "输入 {input}");
        }
    }

    #[test]
    fn normalize_rejects_bad_length() {
        assert!(normalize_mac("aa:bb:cc").is_none());
        assert!(normalize_mac("").is_none());
        assert!(normalize_mac("aa:bb:cc:dd:ee:ff:00:11").is_none());
    }

    #[test]
    fn builtin_lookup_hits_known_vendors() {
        let db = OuiDb::builtin();
        assert_eq!(db.lookup("00:0c:29:11:22:33"), Some("VMware"));
        assert_eq!(db.lookup("08-00-27-ab-cd-ef"), Some("Oracle VirtualBox"));
        assert_eq!(db.lookup("00155d001122"), Some("Microsoft Hyper-V"));
    }

    #[test]
    fn builtin_lookup_misses_raise_no_guess() {
        let db = OuiDb::builtin();
        // 未收录的前缀必须返回 None，而不是猜一个
        assert!(db.lookup("02:00:00:00:00:01").is_none());
    }

    #[test]
    fn locally_administered_detection() {
        // 52:54:00 是 QEMU 的 OUI，但 52 第一字节 bit1 置位 → 本地管理
        assert!(is_locally_administered("52:54:00:12:34:56"));
        // 00 开头 bit1 为 0 → 全局唯一
        assert!(!is_locally_administered("00:0c:29:12:34:56"));
        // 02 是典型的随机化地址
        assert!(is_locally_administered("02:11:22:33:44:55"));
        // 广播地址同样命中 bit1，但它是广播不是随机化
        assert!(!is_locally_administered("ff:ff:ff:ff:ff:ff"));
    }

    #[test]
    fn broadcast_and_zero() {
        assert!(is_broadcast("ff:ff:ff:ff:ff:ff"));
        assert!(!is_broadcast("00:0c:29:00:00:01"));
        assert!(is_zero("00:00:00:00:00:00"));
    }

    #[test]
    fn arp_display_filter_excludes_non_hosts() {
        // 正常主机
        assert!(is_arp_displayable("192.168.60.62"));
        assert!(is_arp_displayable("10.0.0.1"));
        // 组播组映射
        assert!(!is_arp_displayable("224.0.0.22"));
        assert!(!is_arp_displayable("239.255.255.250"));
        // 广播与本网络
        assert!(!is_arp_displayable("255.255.255.255"));
        assert!(!is_arp_displayable("0.0.0.0"));
        // 垃圾输入
        assert!(!is_arp_displayable("not-an-ip"));
        assert!(!is_arp_displayable(""));
        // 链路本地保留（可能是真实邻居，不排除）
        assert!(is_arp_displayable("169.254.1.1"));
    }

    #[test]
    fn oui_prefix_extraction() {
        assert_eq!(OuiDb::oui_prefix("00:0c:29:aa:bb:cc").as_deref(), Some("000C29"));
        assert_eq!(OuiDb::oui_prefix("08-00-27-11-22-33").as_deref(), Some("080027"));
        assert!(OuiDb::oui_prefix("garbage").is_none());
    }

    #[test]
    fn csv_parsing_handles_both_formats() {        let simple = "000C29,VMware Inc\n080027,VirtualBox\nbad-line\n";
        let (db, n) = OuiDb::from_csv(simple);
        assert_eq!(n, 2);
        assert_eq!(db.lookup("00:0c:29:aa:bb:cc"), Some("VMware Inc"));

        let ieee = "Registry,Assignment,Organization Name,Organization Address\n\
                    MA-L,000C29,VMware, Inc.,3401 Hillview Ave\n\
                    MA-L,001122,Cimsys Inc,Somewhere\n";
        let (db2, n2) = OuiDb::from_csv(ieee);
        assert_eq!(n2, 2);
        assert_eq!(db2.lookup("00:11:22:33:44:55"), Some("Cimsys Inc"));
    }
}
