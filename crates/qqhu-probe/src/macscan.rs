//! MAC 扫描编排。
//!
//! 单读 ARP 表只能看到「最近通信过」的邻居，往往是残缺的。
//! 因此提供一条组合路径：**先主动探活触发内核的 ARP 解析，再读表**。
//! ICMP 走二层，目标同网段时内核必须先解析 MAC 才能发包，
//! 探活完成后邻居表自然是满的，且不需要管理员权限。
//!
//! 以 ARP 表为准而不是以探活结果为准：没有 MAC 的地址对「IP/MAC 对照」毫无意义，
//! 探活结果只用来给表里的条目补一个在线状态。

use crate::ipscan::{scan_scope, IpScanOptions, ScanProgress};
use qqhu_core::{
    is_arp_displayable, is_locally_administered, ArpEntry, MacScanReport, OuiDb, ScanScope,
};
use qqhu_sys::read_arp_table;
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct MacScanOptions {
    /// 主动探测范围；`None` 表示只读本机 ARP 表
    pub probe_scope: Option<ScanScope>,
    /// 主动探测的输入原文，仅用于报告记录
    pub probe_input: String,
    pub ip_scan: IpScanOptions,
}

impl Default for MacScanOptions {
    fn default() -> Self {
        Self {
            probe_scope: None,
            probe_input: String::new(),
            ip_scan: IpScanOptions {
                count: 1,
                timeout: Duration::from_millis(600),
                interval: Duration::from_millis(80),
                concurrency: 64,
                tcp_fallback_ports: Vec::new(),
                tcp_timeout: Duration::from_millis(600),
            },
        }
    }
}

/// 进度回调载荷。`total == 0` 表示该阶段没有确定的总量。
#[derive(Debug, Clone)]
pub struct MacScanProgress {
    pub message: String,
    pub done: usize,
    pub total: usize,
}

/// 执行一次 MAC 扫描。
pub async fn run_mac_scan(
    opts: &MacScanOptions,
    oui: &OuiDb,
    cancel: Arc<AtomicBool>,
    on_progress: impl Fn(MacScanProgress) + Send + Sync + 'static,
) -> Result<MacScanReport, String> {
    let emit = Arc::new(on_progress);
    let collected_at = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let mut warnings = Vec::new();

    let mut alive_map: HashMap<String, bool> = HashMap::new();
    let mut probed = 0usize;
    let mut probed_alive = 0usize;

    if let Some(scope) = &opts.probe_scope {
        let input = if opts.probe_input.trim().is_empty() {
            scope.desc.clone()
        } else {
            opts.probe_input.clone()
        };

        let emit_scan = emit.clone();
        let scan_result = scan_scope(
            &input,
            scope,
            &opts.ip_scan,
            cancel.clone(),
            move |p: ScanProgress| {
                emit_scan(MacScanProgress {
                    message: format!("正在探测 {}", p.current),
                    done: p.done,
                    total: p.total,
                });
            },
        )
        .await
        .map_err(|e| e.to_string())?;

        probed = scan_result.total;
        probed_alive = scan_result.alive_count;
        if scan_result.cancelled {
            warnings.push("主动探测被取消，本次邻居表可能不完整。".into());
        }
        for h in &scan_result.hosts {
            alive_map.insert(h.ip.clone(), h.alive);
        }

        // 给内核一点时间把 ARP 条目从「确认中」推进到可用状态。
        // 实测局域网里回包到达即已入表，这里只是兜底。
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    emit(MacScanProgress {
        message: "正在读取 ARP 邻居表…".into(),
        done: 0,
        total: 0,
    });

    let records = read_arp_table()?;
    let raw_count = records.len();

    let mut entries: Vec<ArpEntry> = records
        .into_iter()
        .filter(|r| is_arp_displayable(&r.ip))
        .map(|r| {
            let vendor = oui.lookup(&r.mac).unwrap_or_default().to_string();
            // 本地管理位通常意味着随机化 MAC，OUI 因此没有厂商含义。
            // 但若厂商已知（如 Docker 的 02:42:ac），说明这是有意分配的地址，
            // 此时标成「随机」会误导，所以以厂商是否已知为准。
            let randomized = vendor.is_empty() && is_locally_administered(&r.mac);
            ArpEntry {
                alive: alive_map.get(&r.ip).copied(),
                ip: r.ip,
                mac: r.mac,
                vendor,
                interface: r.interface,
                state: r.state,
                randomized,
            }
        })
        .collect();

    entries.sort_by_key(|e| {
        e.ip.parse::<std::net::Ipv4Addr>()
            .map(u32::from)
            .unwrap_or(u32::MAX)
    });

    if entries.is_empty() {
        warnings.push(
            "ARP 邻居表为空。若刚开机或未与局域网通信过，可勾选「主动探测」先扫一遍网段。".into(),
        );
    }

    Ok(MacScanReport {
        collected_at,
        raw_count,
        entries,
        probed,
        probed_alive,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use qqhu_core::parse_scan_scope;

    /// 只读模式：不探测，所有条目的 alive 应为 None。
    #[tokio::test]
    async fn arp_only_mode_leaves_alive_unknown() {
        let opts = MacScanOptions::default();
        let r = run_mac_scan(
            &opts,
            &OuiDb::builtin(),
            Arc::new(AtomicBool::new(false)),
            |_| {},
        )
        .await
        .expect("只读 ARP 应成功");

        assert_eq!(r.probed, 0);
        assert_eq!(r.probed_alive, 0);
        for e in &r.entries {
            assert!(e.alive.is_none(), "只读模式不该给出在线状态：{}", e.ip);
            assert!(e.mac.contains(':'));
            assert!(!e.ip.is_empty());
        }
    }

    /// 主动探测回环：回环地址在 ARP 表里未必有记录，所以只验证流程跑通、
    /// 且探测阶段计数正确。
    #[tokio::test]
    async fn active_probe_runs_and_reports_counts() {
        let scope = parse_scan_scope("127.0.0.1", 4096).unwrap();
        let opts = MacScanOptions {
            probe_scope: Some(scope),
            probe_input: "127.0.0.1".into(),
            ..Default::default()
        };

        let r = run_mac_scan(
            &opts,
            &OuiDb::builtin(),
            Arc::new(AtomicBool::new(false)),
            |_| {},
        )
        .await
        .expect("主动探测应成功");

        assert_eq!(r.probed, 1);
        assert_eq!(r.probed_alive, 1, "回环必定存活");
    }

    /// 厂商填充：凡是命中内置库的条目，vendor 必须非空且与库一致。
    #[tokio::test]
    async fn vendor_filled_from_oui_db() {
        let opts = MacScanOptions::default();
        let db = OuiDb::builtin();
        let r = run_mac_scan(&opts, &db, Arc::new(AtomicBool::new(false)), |_| {})
            .await
            .unwrap();

        for e in &r.entries {
            if let Some(v) = db.lookup(&e.mac) {
                assert_eq!(e.vendor, v, "条目 {} 的厂商应与库一致", e.ip);
            } else {
                assert!(e.vendor.is_empty(), "库里查不到就必须留空，不能猜");
            }
        }
    }
}
