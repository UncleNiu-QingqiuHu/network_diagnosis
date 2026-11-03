//! 端到端冒烟：跑一次完整诊断并打印结论与关键指标。
//!
//! `cargo run -p qqhu-probe --example diagnose_demo -- <target> [port,port...]`

use qqhu_probe::{run_diagnosis, DiagContext, DiagOptions, PingOptions, TcpProbeOptions};
use std::path::PathBuf;
use std::time::Duration;

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let target = args.next().unwrap_or_else(|| "127.0.0.1".into());
    let ports: Vec<u16> = args
        .next()
        .map(|s| s.split(',').filter_map(|p| p.trim().parse::<u16>().ok()).collect())
        .unwrap_or_else(|| vec![443]);

    let opts = DiagOptions {
        target: target.clone(),
        ports: ports.clone(),
        enable_ping: true,
        ping: PingOptions {
            count: 3,
            interval: Duration::from_millis(200),
            timeout: Duration::from_secs(2),
            ..Default::default()
        },
        tcp: TcpProbeOptions {
            samples: 2,
            timeout: Duration::from_secs(1),
            concurrency: 8,
        },
    };

    let ctx = DiagContext {
        hostname: "spike".into(),
        os_summary: std::env::consts::OS.into(),
        report_dir: PathBuf::from("."),
    };

    let progress = |msg: &str| println!("  · {msg}");
    println!("=== 诊断 {target} 端口 {ports:?} ===");

    match run_diagnosis(&opts, &ctx, &progress).await {
        Ok(r) => {
            let s = r.summary.expect("摘要必须存在");
            println!("\n结论: {} [{}]", s.headline, s.grade.zh());
            for b in &s.bullets {
                println!("  - {b}");
            }
            for a in &s.actions {
                println!("  建议: {a}");
            }
            if let Some(p) = &r.ping {
                println!(
                    "\nICMP: {}/{} 通, avg={:?}ms, min={:?}ms, max={:?}ms",
                    p.received, p.attempted, p.avg_ms, p.min_ms, p.max_ms
                );
            }
            for pr in &r.ports {
                println!(
                    "端口 {}: {:?} 成功率 {:.0}%",
                    pr.port,
                    pr.failure_class,
                    pr.success_rate * 100.0
                );
            }
            if !r.degradations.is_empty() {
                println!("\n降级: {:?}", r.degradations);
            }
        }
        Err(e) => println!("诊断失败: {e}"),
    }
}
