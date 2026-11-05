//! IP 扫描命令行示例。
//!
//! 用法：
//! ```text
//! cargo run -p qqhu-probe --example ipscan_demo -- 192.168.60.0/24
//! cargo run -p qqhu-probe --example ipscan_demo -- 192.168.60.0/24 445,3389
//! ```

use qqhu_core::parse_scan_scope;
use qqhu_probe::{scan_scope, IpScanOptions, ScanProgress};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let input = args.next().unwrap_or_else(|| "127.0.0.1-127.0.0.5".into());
    let tcp_ports: Vec<u16> = args
        .next()
        .map(|s| s.split(',').filter_map(|p| p.trim().parse().ok()).collect())
        .unwrap_or_default();

    let scope = match parse_scan_scope(&input, 4096) {
        Ok(s) => s,
        Err(e) => {
            println!("范围解析失败：{e}");
            return;
        }
    };

    println!("=== 扫描 {} ===", scope.desc);
    println!(
        "参数：并发 64，超时 800ms，TCP 兜底 {:?}",
        if tcp_ports.is_empty() { "无".to_string() } else { format!("{tcp_ports:?}") }
    );

    let opts = IpScanOptions {
        count: 1,
        timeout: Duration::from_millis(800),
        interval: Duration::from_millis(80),
        concurrency: 64,
        tcp_fallback_ports: tcp_ports,
        tcp_timeout: Duration::from_millis(800),
    };

    let progress = |p: ScanProgress| {
        if p.done == p.total || p.done % 16 == 0 {
            println!("  进度 {}/{}，存活 {}", p.done, p.total, p.alive);
        }
    };

    match scan_scope(&input, &scope, &opts, Arc::new(AtomicBool::new(false)), progress).await {
        Ok(r) => {
            println!(
                "\n完成：{} 个地址，存活 {}，耗时 {:.1}s{}",
                r.total,
                r.alive_count,
                r.duration_ms as f64 / 1000.0,
                if r.cancelled { "（已取消）" } else { "" }
            );
            for w in &r.warnings {
                println!("警告：{w}");
            }

            println!("\n{:<16} {:<8} {:<8} {:>10} {:>8}", "IP", "状态", "判定", "RTT(ms)", "丢包");
            for h in &r.hosts {
                if !h.alive {
                    continue;
                }
                println!(
                    "{:<16} {:<8} {:<8} {:>10} {:>7.0}%",
                    h.ip,
                    "存活",
                    h.method.zh(),
                    h.rtt_ms.map(|v| format!("{v:.1}")).unwrap_or_else(|| "—".into()),
                    h.loss_percent
                );
            }
            if r.alive_count == 0 {
                println!("（无存活主机）");
            }
        }
        Err(e) => println!("扫描失败：{e}"),
    }
}
