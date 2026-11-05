//! 路径追踪（Traceroute）。
//!
//! 逐跳递增 IP TTL 发 ICMP Echo：TTL 归零时路由器回 Time Exceeded，
//! 我们就拿到了这一跳的地址；收到 Echo Reply 即表示到达目标。
//!
//! 每跳重建 socket —— raw socket 的 TTL 是 socket 级选项，
//! 而 socket 已交给 tokio 托管，重建比反复取句柄更简单可靠。

use crate::icmp::{IcmpSocket, ReplyKind};
use crate::resolve_target;
use crate::ProbeError;
use qqhu_core::traceroute::{TraceHop, TraceReport};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// 连续多少跳无响应就提前收尾（避免对屏蔽 ICMP 的目标死等）。
const MAX_SILENT_HOPS: u8 = 5;

#[derive(Debug, Clone)]
pub struct TraceOptions {
    pub max_hops: u8,
    /// 每跳探测次数（取最快的一次 RTT）
    pub probes_per_hop: u8,
    pub timeout: Duration,
    pub payload_len: usize,
}

impl Default for TraceOptions {
    fn default() -> Self {
        Self {
            max_hops: 30,
            probes_per_hop: 1,
            timeout: Duration::from_millis(1200),
            payload_len: 32,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceProgress {
    pub hop: TraceHop,
    pub done: u8,
    pub total: u8,
}

/// 追踪到目标的路径。
///
/// `on_hop` 在每跳结束时调用一次，用于向前端推进度。
pub async fn trace_route<F>(
    target: &str,
    opts: &TraceOptions,
    on_hop: F,
) -> Result<TraceReport, ProbeError>
where
    F: Fn(TraceProgress),
{
    let started = Instant::now();
    let addr = resolve_target(target, false).await?;
    let IpAddr::V4(dst) = addr else {
        return Err(ProbeError::InvalidTarget(format!(
            "{target} 解析到 IPv6 地址，路径追踪当前仅支持 IPv4"
        )));
    };

    let max_hops = opts.max_hops.clamp(1, 64);
    let probes = opts.probes_per_hop.clamp(1, 5);
    let mut hops: Vec<TraceHop> = Vec::new();
    let mut completed = false;
    let mut silent_run: u8 = 0;

    for ttl in 1..=max_hops {
        let outcome = probe_hop(dst, ttl, probes, opts).await;
        let hop = outcome.hop;
        let reached = hop.reached;

        if hop.addr.is_none() {
            silent_run += 1;
        } else {
            silent_run = 0;
        }

        hops.push(hop.clone());
        on_hop(TraceProgress {
            hop,
            done: ttl,
            total: max_hops,
        });

        if reached {
            completed = true;
            break;
        }
        if silent_run >= MAX_SILENT_HOPS && ttl >= MAX_SILENT_HOPS {
            break;
        }
    }

    let mut warnings = Vec::new();
    if !completed {
        warnings.push(
            "未在限定跳数内收到目标应答。若目标确实可达，通常是路径上的设备过滤了 ICMP 差错报文。"
                .to_string(),
        );
    }
    let report = TraceReport {
        target: target.to_string(),
        resolved_ip: dst.to_string(),
        hops,
        completed,
        cancelled: false,
        duration_ms: started.elapsed().as_millis() as u64,
        warnings,
    };

    let repeated = report.repeated_addrs();
    if !repeated.is_empty() {
        // 重复地址多半是等价多路径（ECMP），也可能是路由环路，交给用户判断
        let list = repeated
            .iter()
            .map(|(a, n)| format!("{a}（{n} 次）"))
            .collect::<Vec<_>>()
            .join("、");
        let mut r = report;
        r.warnings.push(format!("路径中出现重复地址：{list}，可能是负载均衡或路由环路。"));
        return Ok(r);
    }

    Ok(report)
}

struct HopOutcome {
    hop: TraceHop,
}

async fn probe_hop(
    dst: std::net::Ipv4Addr,
    ttl: u8,
    probes: u8,
    opts: &TraceOptions,
) -> HopOutcome {
    let sock = match IcmpSocket::open(Some(ttl as u32), false) {
        Ok(s) => s,
        Err(e) => {
            let mut hop = TraceHop::timed_out(ttl);
            hop.note = Some(format!("无法创建 ICMP socket：{e}"));
            return HopOutcome { hop };
        }
    };
    // send 需要 &mut，recv 只需 &；这里用局部可变绑定即可
    let mut sock = sock;

    let mut best_rtt: Option<f64> = None;
    let mut addr: Option<String> = None;
    let mut reached = false;
    let mut note: Option<String> = None;
    let mut buf = vec![0u8; 1500];

    for _ in 0..probes {
        let sent_at = Instant::now();
        let seq = match sock.send_echo(dst, opts.payload_len).await {
            Ok(s) => s,
            Err(e) => {
                note = Some(format!("发送失败：{e}"));
                break;
            }
        };

        let deadline = Instant::now() + opts.timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let recv = tokio::time::timeout(remaining, sock.recv(&mut buf)).await;
            let Ok(Ok((n, from))) = recv else { break };
            let IpAddr::V4(src) = from.ip() else { continue };

            let Some(reply) = crate::icmp::parse_reply(&buf[..n], src, sock.ident(), dst) else {
                continue;
            };
            if reply.seq != Some(seq) {
                continue;
            }

            let rtt = sent_at.elapsed().as_secs_f64() * 1000.0;
            match reply.kind {
                ReplyKind::EchoReply => {
                    reached = true;
                    addr = Some(reply.source.to_string());
                    best_rtt = Some(min_f(best_rtt, rtt));
                }
                ReplyKind::TimeExceeded => {
                    addr = Some(reply.source.to_string());
                    best_rtt = Some(min_f(best_rtt, rtt));
                }
                ReplyKind::FragmentationNeeded => {
                    addr = Some(reply.source.to_string());
                    best_rtt = Some(min_f(best_rtt, rtt));
                    note = Some("需要分片（ICMP 3/4）".to_string());
                }
                ReplyKind::Unreachable => {
                    addr = Some(reply.source.to_string());
                    best_rtt = Some(min_f(best_rtt, rtt));
                    note = Some("目标或中间设备不可达（ICMP 3）".to_string());
                }
                ReplyKind::Other => continue,
            }
            break;
        }

        if addr.is_some() {
            break;
        }
    }

    HopOutcome {
        hop: TraceHop {
            ttl,
            addr,
            rtt_ms: best_rtt,
            reached,
            note,
        },
    }
}

fn min_f(cur: Option<f64>, v: f64) -> f64 {
    match cur {
        Some(c) if c <= v => c,
        _ => v,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_options_are_conservative() {
        let o = TraceOptions::default();
        assert!(o.max_hops >= 30);
        assert!(o.timeout >= Duration::from_millis(1000));
    }

    #[tokio::test]
    async fn trace_to_loopback_reaches_target_immediately() {
        // 127.0.0.1 必定第一跳就到达（不依赖外网）
        let opts = TraceOptions {
            max_hops: 5,
            probes_per_hop: 1,
            timeout: Duration::from_millis(800),
            payload_len: 32,
        };
        match trace_route("127.0.0.1", &opts, |_| {}).await {
            Ok(r) => {
                for h in &r.hops {
                    eprintln!(
                        "[traceroute] ttl={} addr={:?} rtt={:?} reached={}",
                        h.ttl, h.addr, h.rtt_ms, h.reached
                    );
                }
                assert!(!r.hops.is_empty());
                assert!(r.hops[0].reached, "回环地址应第一跳到达：{:?}", r.hops[0]);
                assert!(r.hops[0].rtt_ms.is_some());
                assert!(r.completed);
            }
            Err(e) => eprintln!("[traceroute] 跳过真实探测：{e}"),
        }
    }

    /// 手动验证：对默认网关（或 `QQHU_TRACE_TARGET` 指定的目标）做一次真实追踪。
    ///
    /// 网关一定在第一跳，能同时验证 raw socket、TTL 设置与收包解析；
    /// 指定公网目标时还能验证中间跳的 Time Exceeded 解析。
    #[tokio::test]
    #[ignore = "需要真实网络环境，手动运行 --ignored"]
    async fn trace_gateway_manual() {
        let target = std::env::var("QQHU_TRACE_TARGET").ok().filter(|s| !s.trim().is_empty());
        let target = match target {
            Some(t) => t,
            None => match qqhu_sys::netif::default_gateway() {
                Some(gw) => gw.to_string(),
                None => {
                    eprintln!("[traceroute] 本机无默认网关，跳过");
                    return;
                }
            },
        };
        let opts = TraceOptions {
            max_hops: 12,
            ..Default::default()
        };
        match trace_route(&target, &opts, |p| {
            eprintln!("[traceroute] hop {} → {:?}", p.hop.ttl, p.hop.addr)
        })
        .await
        {
            Ok(r) => {
                eprintln!(
                    "[traceroute] {target} 共 {} 跳（完成={}，耗时 {} ms）",
                    r.hops.len(),
                    r.completed,
                    r.duration_ms
                );
                for w in &r.warnings {
                    eprintln!("[traceroute] 警告：{w}");
                }
            }
            Err(e) => eprintln!("[traceroute] 失败：{e}"),
        }
    }
}

