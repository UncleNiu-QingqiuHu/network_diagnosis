//! 网络质量综合评判 —— 与旧版 `quality_assessment.py` 的判定分支逐条对齐。
//!
//! 判定顺序是业务语义的一部分（先"堵塞"后"较差"），改动顺序会改变结论，
//! 因此这里保持与旧版完全相同的 `if/else` 级联，并附单测锁定行为。

use crate::model::{
    BandwidthProbeResult, DnsAnswer, Grade, IperfUdpQualityResult, NetworkQualityAssessment, PingStats,
    PortFailureClass, PortProbeResult,
};

const THROUGHPUT_NOTE: &str = "本工具默认未做带宽/吞吐量压测；若未手动启用下方抽样，则无 Mbps 级速率。\
其它指标来自 ICMP 与 TCP 连接层面的抽样，可间接反映链路稳定性与时延。";

#[derive(Debug, Clone, Copy, Default)]
pub struct QualityOptions {
    /// 用户是否显式配置了端口（决定是否用 TCP 抽样估算丢包）。
    pub user_configured_ports: bool,
    pub enable_ping: bool,
    /// 是否把 iperf3 UDP 结果并入丢包/抖动（取较差）。
    pub use_iperf_udp_for_quality: bool,
}

pub fn compute_network_quality(
    dns: &DnsAnswer,
    ping: Option<&PingStats>,
    port_results: &[PortProbeResult],
    bandwidth: Option<&BandwidthProbeResult>,
    iperf_udp: Option<&IperfUdpQualityResult>,
    opts: QualityOptions,
) -> NetworkQualityAssessment {
    let mut metric_lines: Vec<String> = Vec::new();

    // DNS 失败：直接判定堵塞，不做后续估算。
    if dns.error.is_some() || dns.addresses.is_empty() {
        metric_lines.push("丢包率：—（DNS 失败，未建立有效探测）".into());
        metric_lines.push("时延/延迟：—".into());
        metric_lines.push("抖动：—".into());
        let (body, note) = throughput_body(bandwidth);
        metric_lines.push(format!("带宽/吞吐量：{}", body));
        return NetworkQualityAssessment {
            grade: Grade::Congested,
            loss_pct: None,
            avg_latency_ms: None,
            jitter_ms: None,
            throughput_note: note,
            metric_lines,
        };
    }

    // ---- 丢包率
    let mut loss_pct: Option<f64> = None;
    let mut loss_source = String::new();

    if opts.enable_ping {
        if let Some(p) = ping.filter(|p| p.attempted > 0) {
            loss_pct = Some(100.0 * p.lost as f64 / p.attempted as f64);
            loss_source = "ICMP Ping".into();
        }
    }
    if loss_pct.is_none() && opts.user_configured_ports && !port_results.is_empty() {
        loss_pct = tcp_sample_loss_pct(port_results);
        loss_source = "TCP 连接尝试（tcping 抽样）".into();
    }

    // ---- 平均时延
    let mut avg_lat: Option<f64> = None;
    let mut lat_source = String::new();

    let ping_ok = if opts.enable_ping { ping } else { None };
    if let Some(p) = ping_ok.filter(|p| !p.rtts_ms.is_empty()) {
        avg_lat = Some(mean(&p.rtts_ms));
        lat_source = "ICMP Ping RTT".into();
    } else {
        let rtts = collect_tcp_rtts(port_results);
        if !rtts.is_empty() {
            avg_lat = Some(mean(&rtts));
            lat_source = "TCP 握手 RTT（tcping）".into();
        }
    }

    // ---- 抖动
    let mut jitter_ms: Option<f64> = None;
    let mut jitter_src = String::new();

    if let Some(p) = ping_ok.filter(|p| !p.rtts_ms.is_empty()) {
        jitter_ms = mean_jitter_ipdv(&p.rtts_ms);
        jitter_src = if p.rtts_ms.len() >= 2 {
            "ICMP".into()
        } else {
            "ICMP（单样本，抖动近似）".into()
        };
    } else if !port_results.is_empty() {
        let rtts = collect_tcp_rtts(port_results);
        jitter_ms = stdev(&rtts);
        if jitter_ms.is_some() {
            jitter_src = "TCP RTT 波动（tcping）".into();
            if lat_source.is_empty() {
                lat_source = "TCP 握手 RTT（tcping）".into();
            }
        }
    }

    // ---- iperf3 UDP 合并（取较差）
    if opts.use_iperf_udp_for_quality {
        if let Some(q) = iperf_udp.filter(|q| q.ok) {
            if let Some(ul) = q.packet_loss_pct {
                loss_pct = Some(match loss_pct {
                    Some(cur) => {
                        loss_source = format!("{}；已与 iperf3 UDP 合并（取较差）", loss_source);
                        cur.max(ul)
                    }
                    None => {
                        loss_source = "iperf3 UDP".into();
                        ul
                    }
                });
            }
            if let Some(uj) = q.jitter_ms {
                jitter_ms = Some(match jitter_ms {
                    Some(cur) => {
                        jitter_src = format!("{}；已与 iperf3 UDP 合并（取较差）", jitter_src);
                        cur.max(uj)
                    }
                    None => {
                        jitter_src = "iperf3 UDP".into();
                        uj
                    }
                });
            }
        }
    }

    // ---- 指标文案
    match (loss_pct, loss_source.is_empty()) {
        (Some(v), false) => metric_lines.push(format!("丢包率：{:.1}%（依据 {}）", v, loss_source)),
        _ => metric_lines.push("丢包率：—（本轮未启用 Ping 或未配置端口抽样，无法估算）".into()),
    }
    match (avg_lat, lat_source.is_empty()) {
        (Some(v), false) => metric_lines.push(format!("时延/延迟：平均约 {:.1} ms（{}）", v, lat_source)),
        _ => metric_lines.push("时延/延迟：—（无可用 RTT 样本）".into()),
    }
    match jitter_ms {
        Some(v) => {
            let src = if jitter_src.is_empty() { "—" } else { jitter_src.as_str() };
            metric_lines.push(format!("抖动：约 {:.1} ms（{}）", v, src));
        }
        None => metric_lines.push("抖动：—（样本过少）".into()),
    }

    let (body, note) = throughput_body(bandwidth);
    metric_lines.push(format!("带宽/吞吐量：{}", body));

    if opts.use_iperf_udp_for_quality {
        if let Some(q) = iperf_udp {
            if q.ok {
                metric_lines.push(format!("iperf3 UDP（质量辅助）：{}", q.summary));
            } else {
                let tail = if q.summary.is_empty() {
                    String::new()
                } else {
                    format!(" {}", q.summary.trim_end())
                };
                metric_lines.push(format!(
                    "iperf3 UDP（质量辅助）：抽样失败，未并入丢包/抖动档位。{}",
                    tail
                ));
            }
        }
    }

    // ---- 分档判定（顺序即业务语义，勿调整）
    let all_ports_bad = opts.user_configured_ports
        && !port_results.is_empty()
        && port_results.iter().all(|p| p.failure_class != PortFailureClass::Ok);
    let some_ports_bad = opts.user_configured_ports
        && !port_results.is_empty()
        && port_results.iter().any(|p| p.failure_class != PortFailureClass::Ok);
    let bad_ports = port_results.iter().any(|p| {
        matches!(
            p.failure_class,
            PortFailureClass::Timeout | PortFailureClass::Unreachable | PortFailureClass::Error
        )
    });
    let ping_hard_fail = opts.enable_ping
        && ping.map(|p| p.attempted > 0 && p.received == 0).unwrap_or(false);

    let grade = if all_ports_bad {
        Grade::Congested
    } else if ping_hard_fail && (loss_pct.is_none() || loss_pct.unwrap_or(0.0) >= 25.0) {
        Grade::Congested
    } else if loss_pct.map(|v| v >= 15.0).unwrap_or(false) {
        Grade::Congested
    } else if avg_lat.map(|v| v >= 400.0).unwrap_or(false) && loss_pct.map(|v| v >= 5.0).unwrap_or(false) {
        Grade::Congested
    } else if loss_pct.map(|v| v >= 5.0).unwrap_or(false) {
        Grade::Poor
    } else if avg_lat.map(|v| v >= 150.0).unwrap_or(false) {
        Grade::Poor
    } else if jitter_ms.map(|v| v >= 40.0).unwrap_or(false) {
        Grade::Poor
    } else if some_ports_bad && bad_ports {
        Grade::Poor
    } else if ping_hard_fail && !opts.user_configured_ports {
        Grade::Poor
    } else if loss_pct.map(|v| v <= 2.0).unwrap_or(false)
        && avg_lat.map(|v| v <= 70.0).unwrap_or(false)
        && jitter_ms.map(|v| v <= 25.0).unwrap_or(true)
        && !some_ports_bad
    {
        Grade::Excellent
    } else {
        Grade::Normal
    };

    NetworkQualityAssessment {
        grade,
        loss_pct,
        avg_latency_ms: avg_lat,
        jitter_ms,
        throughput_note: note,
        metric_lines,
    }
}

// ---------------------------------------------------------------- 内部工具

fn throughput_body(bw: Option<&BandwidthProbeResult>) -> (String, String) {
    let Some(bw) = bw else {
        return (THROUGHPUT_NOTE.to_string(), THROUGHPUT_NOTE.to_string());
    };
    if bw.ok {
        if let Some(mbps) = bw.megabits_per_second {
            let body = format!(
                "抽样约 {:.1} Mbps（{} → {}）。仅为到该目标与当前窗口条件下的估计，非签约带宽。",
                mbps, bw.mode, bw.target_label
            );
            let short = format!("抽样约 {:.1} Mbps（{}）。", mbps, bw.mode);
            return (body, short);
        }
        let tail = if bw.summary.is_empty() { "抽样已完成。" } else { bw.summary.as_str() };
        let body = format!("{}（未得到统一 Mbps 汇总）。", tail);
        let short = body.chars().take(200).collect();
        return (body, short);
    }
    let err = [bw.summary.as_str(), bw.error.as_str()]
        .iter()
        .filter(|s| !s.trim().is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(" ");
    let err = if err.is_empty() { "失败".to_string() } else { err };
    let body = format!("本次抽样未成功：{}。不作为签约带宽依据。", err);
    let short = body.chars().take(200).collect();
    (body, short)
}

fn mean(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / values.len() as f64
}

/// 相邻 RTT 差分绝对值的平均（ipdv 抖动近似）。
fn mean_jitter_ipdv(rtts: &[f64]) -> Option<f64> {
    match rtts.len() {
        0 => None,
        1 => Some(0.0),
        n => {
            let sum: f64 = rtts.windows(2).map(|w| (w[1] - w[0]).abs()).sum();
            Some(sum / (n - 1) as f64)
        }
    }
}

/// 样本标准差（n-1），与 Python `statistics.stdev` 一致。
fn stdev(values: &[f64]) -> Option<f64> {
    if values.len() < 2 {
        return None;
    }
    let m = mean(values);
    let var = values.iter().map(|v| (v - m).powi(2)).sum::<f64>() / (values.len() - 1) as f64;
    Some(var.sqrt())
}

fn collect_tcp_rtts(ports: &[PortProbeResult]) -> Vec<f64> {
    ports.iter().flat_map(|p| p.ok_rtts()).collect()
}

fn tcp_sample_loss_pct(ports: &[PortProbeResult]) -> Option<f64> {
    let total: usize = ports.iter().map(|p| p.samples.len()).sum();
    if total == 0 {
        return None;
    }
    let bad = ports.iter().flat_map(|p| p.samples.iter()).filter(|s| !s.success).count();
    Some(100.0 * bad as f64 / total as f64)
}

// ---------------------------------------------------------------- 单测

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{PortSample, PingSample};

    fn dns_ok() -> DnsAnswer {
        DnsAnswer {
            family: "ipv4".into(),
            addresses: vec!["10.0.0.1".into()],
            elapsed_ms: 5.0,
            error: None,
        }
    }

    fn ping_with(rtts: &[f64], attempted: u32) -> PingStats {
        let received = rtts.len() as u32;
        PingStats {
            target: "10.0.0.1".into(),
            attempted,
            received,
            lost: attempted - received,
            rtts_ms: rtts.to_vec(),
            min_ms: rtts.iter().cloned().reduce(f64::min),
            max_ms: rtts.iter().cloned().reduce(f64::max),
            avg_ms: if rtts.is_empty() { None } else { Some(mean(rtts)) },
            samples: rtts
                .iter()
                .enumerate()
                .map(|(i, r)| PingSample { seq: i as u32, rtt_ms: Some(*r), ttl: Some(64) })
                .collect(),
            raw_stdout: String::new(),
        }
    }

    fn port(port: u16, ok: bool, rtt: f64, failure: PortFailureClass) -> PortProbeResult {
        PortProbeResult {
            port,
            samples: vec![PortSample {
                success: ok,
                rtt_ms: if ok { Some(rtt) } else { None },
                failure,
                detail: String::new(),
            }],
            failure_class: failure,
            success_count: if ok { 1 } else { 0 },
            success_rate: if ok { 1.0 } else { 0.0 },
        }
    }

    #[test]
    fn dns_failure_is_congested() {
        let dns = DnsAnswer::failed("ipv4", "查询超时");
        let a = compute_network_quality(&dns, None, &[], None, None, QualityOptions::default());
        assert_eq!(a.grade, Grade::Congested);
        assert_eq!(a.grade.zh(), "堵塞");
    }

    #[test]
    fn excellent_link() {
        let ping = ping_with(&[10.0, 11.0, 10.5], 3);
        let a = compute_network_quality(
            &dns_ok(),
            Some(&ping),
            &[],
            None,
            None,
            QualityOptions { enable_ping: true, ..Default::default() },
        );
        assert_eq!(a.grade, Grade::Excellent);
        assert!((a.loss_pct.unwrap() - 0.0).abs() < 1e-9);
    }

    #[test]
    fn hard_loss_is_congested() {
        let ping = ping_with(&[], 10);
        let a = compute_network_quality(
            &dns_ok(),
            Some(&ping),
            &[],
            None,
            None,
            QualityOptions { enable_ping: true, ..Default::default() },
        );
        assert_eq!(a.grade, Grade::Congested);
    }

    #[test]
    fn partial_loss_is_poor() {
        let ping = ping_with(&[10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 10.0], 10);
        let a = compute_network_quality(
            &dns_ok(),
            Some(&ping),
            &[],
            None,
            None,
            QualityOptions { enable_ping: true, ..Default::default() },
        );
        assert_eq!(a.loss_pct.unwrap(), 10.0);
        assert_eq!(a.grade, Grade::Poor);
    }

    #[test]
    fn all_ports_bad_is_congested_even_with_ping() {
        let ping = ping_with(&[8.0], 1);
        let ports = vec![
            port(80, false, 0.0, PortFailureClass::Timeout),
            port(443, false, 0.0, PortFailureClass::Refused),
        ];
        let a = compute_network_quality(
            &dns_ok(),
            Some(&ping),
            &ports,
            None,
            None,
            QualityOptions {
                enable_ping: true,
                user_configured_ports: true,
                ..Default::default()
            },
        );
        assert_eq!(a.grade, Grade::Congested);
    }

    #[test]
    fn iperf_udp_takes_worse() {
        let ping = ping_with(&[10.0, 11.0], 2);
        let udp = IperfUdpQualityResult {
            ok: true,
            packet_loss_pct: Some(30.0),
            jitter_ms: Some(60.0),
            summary: "UDP 30% 丢包".into(),
        };
        let a = compute_network_quality(
            &dns_ok(),
            Some(&ping),
            &[],
            None,
            Some(&udp),
            QualityOptions {
                enable_ping: true,
                use_iperf_udp_for_quality: true,
                ..Default::default()
            },
        );
        assert_eq!(a.loss_pct.unwrap(), 30.0);
        assert_eq!(a.jitter_ms.unwrap(), 60.0);
        assert_eq!(a.grade, Grade::Congested);
    }

    #[test]
    fn ipdv_jitter() {
        assert_eq!(mean_jitter_ipdv(&[10.0]), Some(0.0));
        assert_eq!(mean_jitter_ipdv(&[]), None);
        assert!((mean_jitter_ipdv(&[10.0, 20.0, 15.0]).unwrap() - 7.5).abs() < 1e-9);
    }
}
