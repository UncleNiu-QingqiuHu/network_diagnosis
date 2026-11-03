//! MAC 扫描命令行示例。
//!
//! 用法：
//! ```text
//! cargo run -p qqhu-probe --example macscan_demo                # 只读 ARP 表
//! cargo run -p qqhu-probe --example macscan_demo -- 192.168.60.32/27   # 先探测再读表
//! ```

use qqhu_core::{parse_scan_scope, OuiDb};
use qqhu_probe::{run_mac_scan, MacScanOptions};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let input = std::env::args().nth(1);

    let opts = match input.as_deref() {
        Some(spec) => match parse_scan_scope(spec, 4096) {
            Ok(scope) => MacScanOptions {
                probe_scope: Some(scope),
                probe_input: spec.to_string(),
                ..Default::default()
            },
            Err(e) => {
                println!("范围解析失败：{e}");
                return;
            }
        },
        None => MacScanOptions::default(),
    };

    let mode = if opts.probe_scope.is_some() {
        "主动探测 + 读表"
    } else {
        "只读 ARP 表"
    };
    println!("=== MAC 扫描（{mode}）===");

    let db = OuiDb::builtin();
    println!("内置 OUI 库 {} 条，未命中显示「未知」\n", db.len());

    match run_mac_scan(&opts, &db, Arc::new(AtomicBool::new(false)), |p| {
        if p.total > 0 && (p.done % 32 == 0 || p.done == p.total) {
            println!("  {} ({}/{})", p.message, p.done, p.total);
        } else if p.total == 0 {
            println!("  {}", p.message);
        }
    })
    .await
    {
        Ok(r) => {
            println!(
                "\n采集时间 {}，原始 {} 条，展示 {} 条（已知厂商 {}）",
                r.collected_at,
                r.raw_count,
                r.entries.len(),
                r.known_vendor_count()
            );
            if r.probed > 0 {
                println!("主动探测：{} 个地址，存活 {}", r.probed, r.probed_alive);
            }
            for w in &r.warnings {
                println!("警告：{w}");
            }

            println!(
                "\n{:<16} {:<19} {:<18} {:<12} {:<8} {:>4}",
                "IP", "MAC", "厂商", "接口", "状态", "在线"
            );
            for e in &r.entries {
                let vendor = if !e.vendor.is_empty() {
                    e.vendor.clone()
                } else if e.randomized {
                    "（本地随机）".to_string()
                } else {
                    // 厂商未知时给出 OUI 前缀，便于自行查证
                    format!("OUI {}", OuiDb::oui_prefix(&e.mac).unwrap_or_default())
                };
                println!(
                    "{:<16} {:<19} {:<18} {:<12} {:<8} {:>4}",
                    e.ip,
                    e.mac,
                    truncate(&vendor, 16),
                    truncate(&e.interface, 10),
                    e.state.zh(),
                    match e.alive {
                        Some(true) => "是",
                        Some(false) => "否",
                        None => "—",
                    }
                );
            }
        }
        Err(e) => println!("扫描失败：{e}"),
    }
}

/// 按显示宽度粗略截断（中文按 2 列计），避免长接口名把表格挤散。
fn truncate(s: &str, max_cols: usize) -> String {
    let mut width = 0;
    let mut out = String::new();
    for ch in s.chars() {
        let w = if ch.is_ascii() { 1 } else { 2 };
        if width + w > max_cols {
            out.push('…');
            break;
        }
        width += w;
        out.push(ch);
    }
    out
}
