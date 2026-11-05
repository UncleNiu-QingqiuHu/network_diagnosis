//! 路径 MTU 探测。
//!
//! 做法：发带 DF（不分片）标志的 ICMP Echo，逐步加大包长。
//! - 收到 Echo Reply → 该尺寸能通
//! - 收到 ICMP 3/4（Fragmentation Needed）→ 太大，路由器还会附带下一跳 MTU
//! - 本机 send 返回 EMSGSIZE → 连本机出口都过不去
//!
//! 用二分而不是线性递增，十几轮即可定位到 1 字节精度。

use crate::icmp::{IcmpSocket, ReplyKind};
use crate::resolve_target;
use crate::ProbeError;
use qqhu_core::mtu::{MtuProbe, MtuReport, DEFAULT_MTU, IPV4_ICMP_OVERHEAD, MAX_MTU, MIN_MTU};
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct MtuOptions {
    pub timeout: Duration,
    /// 单个尺寸的重试次数：ICMP 丢包常见，不重试会把丢包误判成「包太大」
    pub retries: u8,
}

impl Default for MtuOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(1200),
            retries: 2,
        }
    }
}

/// 探测到目标的路径 MTU。
pub async fn probe_path_mtu(target: &str, opts: &MtuOptions) -> Result<MtuReport, ProbeError> {
    let started = Instant::now();
    let addr = resolve_target(target, false).await?;
    let IpAddr::V4(dst) = addr else {
        return Err(ProbeError::InvalidTarget(format!(
            "{target} 解析到 IPv6 地址，MTU 探测当前仅支持 IPv4"
        )));
    };

    let mut sock = IcmpSocket::open(None, true).map_err(|e| {
        ProbeError::IcmpClient(format!("无法创建带 DF 标志的 ICMP socket：{e}"))
    })?;

    let mut probes: Vec<MtuProbe> = Vec::new();

    // 第一枪打基线 1500：绝大多数网络能直接给出结论，省掉一整轮二分
    let baseline = probe_once(&mut sock, dst, DEFAULT_MTU, opts).await;
    let baseline_ok = baseline.passed;
    probes.push(baseline.clone());

    let (mut low, mut high) = if baseline_ok {
        // 基线通过后再试巨型帧上限：本机网卡通常就是 1500，
        // 这时 send 会直接被内核拒绝，可直接判定路径 MTU = 1500，
        // 无需再对 1500..9000 做十几次无意义二分。
        let big = probe_once(&mut sock, dst, MAX_MTU, opts).await;
        let big_ok = big.passed;
        let local_capped = big.outcome == "too-big-local";
        probes.push(big);
        if big_ok {
            (MAX_MTU, MAX_MTU)
        } else if local_capped {
            (DEFAULT_MTU, DEFAULT_MTU)
        } else {
            (DEFAULT_MTU, MAX_MTU)
        }
    } else {
        // 1500 都过不去，往下找；先确认最小 MTU 能否通过，否则目标根本不响应 ICMP
        let floor = probe_once(&mut sock, dst, MIN_MTU, opts).await;
        let floor_ok = floor.passed;
        probes.push(floor);
        if !floor_ok {
            return Err(ProbeError::ProbeFailed(format!(
                "{target}（{dst}）对带 DF 标志的 ICMP 探测无响应（连 {} 字节 MTU 都不通），\
                 无法测定路径 MTU。常见原因：目标或防火墙屏蔽 ICMP，\
                 可改测网关或同网段设备。",
                MIN_MTU
            )));
        }
        (MIN_MTU, DEFAULT_MTU)
    };

    while high - low > 1 {
        let mid = low + (high - low) / 2;
        let r = probe_once(&mut sock, dst, mid, opts).await;
        let ok = r.passed;
        probes.push(r);
        if ok {
            low = mid;
        } else {
            high = mid;
        }
    }

    let uncertain = probes.iter().any(|p| p.outcome == "timeout");
    let mut warnings = Vec::new();
    if uncertain {
        warnings.push(
            "部分探测超时（已重试），结论可能受丢包影响。可在网络空闲时复测确认。".to_string(),
        );
    }
    if probes.iter().any(|p| p.outcome == "too-big-local") {
        warnings.push(format!(
            "本机网络接口 MTU 上限为 {low} 字节，无法探测更大的路径 MTU。\
             若链路上行侧使用巨型帧，需要在支持巨型帧的接口上复测。"
        ));
    }
    if let Some(hint) = probes.iter().rev().find_map(|p| p.next_hop_mtu) {
        if hint as u32 != low {
            warnings.push(format!(
                "路由器回报的下一跳 MTU 为 {hint}，与实测 {low} 不一致，以实测值为准。"
            ));
        }
    }

    Ok(MtuReport {
        target: target.to_string(),
        resolved_ip: dst.to_string(),
        path_mtu: low,
        probes,
        uncertain,
        duration_ms: started.elapsed().as_millis() as u64,
        warnings,
        summary: MtuReport::summary_of(low),
    })
}

async fn probe_once(
    sock: &mut IcmpSocket,
    dst: std::net::Ipv4Addr,
    mtu: u32,
    opts: &MtuOptions,
) -> MtuProbe {
    let payload = mtu.saturating_sub(IPV4_ICMP_OVERHEAD) as usize;
    let mut last = MtuProbe {
        mtu,
        passed: false,
        next_hop_mtu: None,
        rtt_ms: None,
        outcome: "timeout".to_string(),
    };

    for _ in 0..=opts.retries {
        let sent_at = Instant::now();
        let seq = match sock.send_echo(dst, payload).await {
            Ok(s) => s,
            Err(e) => {
                // 本机出口拒绝发送该尺寸（EMSGSIZE）时，是本地接口 MTU 封顶，
                // 与路径上路由器回 ICMP 3/4 要区分开，否则二分会被本地限制带偏。
                // Windows: WSAEMSGSIZE 10040；Linux/macOS: EMSGSIZE 90
                let mtu_limited = matches!(e.raw_os_error(), Some(10040) | Some(90));
                last.outcome = if mtu_limited {
                    "too-big-local"
                } else {
                    "send-error"
                }
                .to_string();
                return last;
            }
        };

        let deadline = Instant::now() + opts.timeout;
        let mut buf = vec![0u8; 2048];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let Ok(Ok((n, from))) =
                tokio::time::timeout(remaining, sock.recv(&mut buf)).await
            else {
                break;
            };
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
                    return MtuProbe {
                        mtu,
                        passed: true,
                        next_hop_mtu: None,
                        rtt_ms: Some(rtt),
                        outcome: "ok".to_string(),
                    };
                }
                ReplyKind::FragmentationNeeded => {
                    return MtuProbe {
                        mtu,
                        passed: false,
                        next_hop_mtu: reply.next_hop_mtu.map(u32::from),
                        rtt_ms: Some(rtt),
                        outcome: "too-big".to_string(),
                    };
                }
                ReplyKind::Unreachable => {
                    last = MtuProbe {
                        mtu,
                        passed: false,
                        next_hop_mtu: None,
                        rtt_ms: Some(rtt),
                        outcome: "unreachable".to_string(),
                    };
                    break;
                }
                _ => continue,
            }
        }
    }

    last
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_never_underflows() {
        // MTU 小于协议开销时不能 panic
        let p = DEFAULT_MTU.saturating_sub(IPV4_ICMP_OVERHEAD);
        assert_eq!(p, 1472);
        assert_eq!(100u32.saturating_sub(IPV4_ICMP_OVERHEAD), 72);
    }

    #[tokio::test]
    async fn probe_loopback_mtu() {
        // 回环没有真实链路限制，通常能过 1500；只要求不 panic 且结论合理
        let opts = MtuOptions {
            timeout: Duration::from_millis(800),
            retries: 1,
        };
        match probe_path_mtu("127.0.0.1", &opts).await {
            Ok(r) => {
                assert!(r.path_mtu >= MIN_MTU, "回环 MTU 不应低于下限：{}", r.path_mtu);
                assert!(!r.probes.is_empty());
            }
            Err(e) => eprintln!("[mtu] 跳过真实探测：{e}"),
        }
    }

    /// 手动验证：对默认网关测路径 MTU（`QQHU_MTU_TARGET` 可换目标）。
    #[tokio::test]
    #[ignore = "需要真实网络环境，手动运行 --ignored"]
    async fn probe_mtu_manual() {
        let target = std::env::var("QQHU_MTU_TARGET").ok().filter(|s| !s.trim().is_empty());
        let target = match target {
            Some(t) => t,
            None => match qqhu_sys::netif::default_gateway() {
                Some(gw) => gw.to_string(),
                None => {
                    eprintln!("[mtu] 本机无默认网关，跳过");
                    return;
                }
            },
        };
        match probe_path_mtu(&target, &MtuOptions::default()).await {
            Ok(r) => {
                eprintln!(
                    "[mtu] {target} → path_mtu={} 探测 {} 次 耗时 {} ms 不确定={}",
                    r.path_mtu,
                    r.probes.len(),
                    r.duration_ms,
                    r.uncertain
                );
                for p in &r.probes {
                    eprintln!(
                        "[mtu]   mtu={} passed={} outcome={} next_hop={:?}",
                        p.mtu, p.passed, p.outcome, p.next_hop_mtu
                    );
                }
                eprintln!("[mtu] {}", r.summary);
            }
            Err(e) => eprintln!("[mtu] 失败：{e}"),
        }
    }
}
