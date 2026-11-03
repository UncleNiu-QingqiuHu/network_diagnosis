//! M0 spike：验证 Windows 上非管理员能否用原生 ICMP。
//!
//! 运行：`cargo run -p qqhu-probe --example spike_icmp`

use std::net::IpAddr;
use std::time::Duration;
use surge_ping::{Client, Config, PingIdentifier, PingSequence};

#[tokio::main]
async fn main() {
    println!("=== surge-ping 原生 ICMP spike ===");
    println!("进程管理员权限: {}", qqhu_sys::host().is_elevated());
    println!("系统: {}", qqhu_sys::host().os_summary());
    println!();

    // 支持命令行传入目标；默认给一组常见对照
    let args: Vec<String> = std::env::args().skip(1).collect();
    let targets: Vec<String> = if args.is_empty() {
        vec![
            "127.0.0.1".into(),
            "223.5.5.5".into(),
            "8.8.8.8".into(),
        ]
    } else {
        args
    };

    for target in targets {
        let addr: IpAddr = match target.parse() {
            Ok(a) => a,
            Err(e) => {
                println!("{target}: 地址解析失败 {e}");
                continue;
            }
        };

        let client = match Client::new(&Config::default()) {
            Ok(c) => c,
            Err(e) => {
                println!("{target}: 创建客户端失败 -> {e}");
                continue;
            }
        };

        let mut pinger = client.pinger(addr, PingIdentifier(0x1234)).await;
        pinger.timeout(Duration::from_secs(2));

        let mut ok = 0;
        let mut rtts = Vec::new();
        let mut last_err = String::new();
        for seq in 0..3u16 {
            match pinger.ping(PingSequence(seq), &[0u8; 8]).await {
                Ok((_pkt, rtt)) => {
                    ok += 1;
                    rtts.push(rtt.as_secs_f64() * 1000.0);
                }
                Err(e) => last_err = e.to_string(),
            }
        }
        if ok > 0 {
            let avg: f64 = rtts.iter().sum::<f64>() / rtts.len() as f64;
            println!("{target:<16} {ok}/3 通, 平均 {avg:.1} ms");
        } else {
            println!("{target:<16} 0/3 通 ({last_err})");
        }
    }
}
