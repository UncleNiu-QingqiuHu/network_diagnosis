//! 一次完整网络诊断的编排层。
//!
//! 顺序：解析 → ICMP → TCP 端口 → 质量评判 → 结论摘要。
//! 任一可选探针失败不中断整体，失败原因写入 `degradations`，保证报告可解释。

use crate::dns;
use crate::ping::{ping_addr, PingOptions};
use crate::tcp::{probe_ports, TcpProbeOptions};
use crate::{resolve_target, ProbeError};
use qqhu_core::quality::QualityOptions;
use qqhu_core::{
    build_summary, compute_network_quality, DiagnosticReport, Grade, InputSnapshot, NetworkQualityAssessment,
    TaskMeta,
};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct DiagOptions {
    pub target: String,
    pub ports: Vec<u16>,
    pub enable_ping: bool,
    pub ping: PingOptions,
    pub tcp: TcpProbeOptions,
}

impl Default for DiagOptions {
    fn default() -> Self {
        Self {
            target: String::new(),
            ports: vec![443],
            enable_ping: true,
            ping: PingOptions::default(),
            tcp: TcpProbeOptions::default(),
        }
    }
}

/// 运行环境信息，由调用方（Tauri 层 / CLI）注入，避免探针层依赖平台实现。
#[derive(Debug, Clone)]
pub struct DiagContext {
    pub hostname: String,
    pub os_summary: String,
    pub report_dir: PathBuf,
}

/// 执行一次诊断。`on_progress` 用于向界面推送阶段文案。
pub async fn run_diagnosis(
    opts: &DiagOptions,
    ctx: &DiagContext,
    on_progress: &(dyn Fn(&str) + Send + Sync),
) -> Result<DiagnosticReport, ProbeError> {
    let target = opts.target.trim().to_string();
    if target.is_empty() {
        return Err(ProbeError::InvalidTarget("目标不能为空".into()));
    }

    let meta = TaskMeta::new(ctx.hostname.clone(), ctx.os_summary.clone(), ctx.report_dir.clone());
    let mut report = DiagnosticReport::new(meta, build_input(opts));

    // ---- 1. 解析
    on_progress("正在解析目标…");
    let dns_answer = dns::resolve(&target).await;
    let dns_failed = dns_answer.error.is_some();
    report.dns = Some(dns_answer.clone());

    if dns_failed {
        report.degrade(
            "dns_failed",
            "域名解析失败，后续探测无法进行",
            dns_answer.error.clone().unwrap_or_default(),
        );
        report.quality = Some(empty_quality(&dns_answer));
        report.summary = Some(build_summary(&report));
        report.overall = report.summary.as_ref().map(|s| s.overall).unwrap_or_default();
        report.meta.finished_at = Some(chrono::Utc::now());
        return Ok(report);
    }

    let addr = match resolve_target(&target, opts.ping.prefer_ipv6).await {
        Ok(a) => a,
        Err(e) => {
            report.degrade("resolve_failed", "目标地址不可用", e.to_string());
            report.summary = Some(build_summary(&report));
            report.overall = report.summary.as_ref().map(|s| s.overall).unwrap_or_default();
            report.meta.finished_at = Some(chrono::Utc::now());
            return Ok(report);
        }
    };

    // ---- 2. ICMP
    if opts.enable_ping {
        on_progress("正在发送 ICMP 探测…");
        match ping_addr(addr, &target, &opts.ping).await {
            Ok(stats) => report.ping = Some(stats),
            Err(e) => report.degrade("icmp_unavailable", "ICMP 探测不可用，已降级为端口抽样", e.to_string()),
        }
    }

    // ---- 3. TCP 端口
    if !opts.ports.is_empty() {
        on_progress("正在探测端口…");
        report.ports = probe_ports(addr, &opts.ports, &opts.tcp).await;
    }

    // ---- 4. 质量评判
    on_progress("正在评估链路质量…");
    let bandwidth = report.bandwidth.as_ref();
    let quality = compute_network_quality(
        &dns_answer,
        report.ping.as_ref(),
        &report.ports,
        bandwidth,
        None,
        QualityOptions {
            user_configured_ports: !opts.ports.is_empty(),
            enable_ping: opts.enable_ping,
            use_iperf_udp_for_quality: false,
        },
    );

    // ---- 5. 摘要
    report.quality = Some(quality);
    let summary = build_summary(&report);
    report.overall = summary.overall;
    report.summary = Some(summary);
    report.meta.finished_at = Some(chrono::Utc::now());
    on_progress("诊断完成");
    Ok(report)
}

fn empty_quality(dns: &qqhu_core::DnsAnswer) -> NetworkQualityAssessment {
    NetworkQualityAssessment {
        grade: Grade::Unknown,
        loss_pct: None,
        avg_latency_ms: None,
        jitter_ms: None,
        throughput_note: String::new(),
        metric_lines: vec![format!(
            "解析失败：{}",
            dns.error.clone().unwrap_or_else(|| "未知原因".into())
        )],
    }
}

fn build_input(opts: &DiagOptions) -> InputSnapshot {
    let d = InputSnapshot {
        target_host: opts.target.clone(),
        ports: opts.ports.clone(),
        samples_per_port: opts.tcp.samples,
        tcp_connect_timeout_ms: opts.tcp.timeout.as_millis() as u64,
        enable_ping: opts.enable_ping,
        enable_capture: false,
        prefer_ipv6: opts.ping.prefer_ipv6,
        ping_count: opts.ping.count,
        ping_long: false,
        long_ping_seconds: 30,
        ping_packet_timeout_ms: opts.ping.timeout.as_millis() as u64,
        enable_traceroute: false,
        traceroute_max_hops: 30,
        traceroute_hop_timeout_ms: 4000,
        bandwidth_mode: "off".into(),
        bandwidth_http_url: String::new(),
        bandwidth_http_parallel: 4,
        bandwidth_http_seconds: 15,
        bandwidth_iperf_host: String::new(),
        bandwidth_iperf_port: 5201,
        bandwidth_iperf_seconds: 30,
        bandwidth_iperf_parallel: 4,
        bandwidth_iperf_for_quality: true,
        bandwidth_iperf_udp_bitrate: "1000M".into(),
        optional_dns_server: String::new(),
        enable_pathping: false,
        enable_tcp_traceroute: false,
        tcp_traceroute_max_hops: 30,
        enable_http_tls_probe: false,
        enable_egress_probe: false,
        enable_mtu_probe: false,
        enable_history_compare: true,
        authorized: true,
    };
    d
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ctx() -> DiagContext {
        DiagContext {
            hostname: "test".into(),
            os_summary: "test".into(),
            report_dir: PathBuf::from("."),
        }
    }

    fn opts(target: &str) -> DiagOptions {
        DiagOptions {
            target: target.into(),
            ports: vec![],
            enable_ping: true,
            ping: PingOptions {
                count: 2,
                interval: Duration::from_millis(30),
                timeout: Duration::from_secs(2),
                ..Default::default()
            },
            tcp: TcpProbeOptions::default(),
        }
    }

    #[tokio::test]
    async fn loopback_diagnosis_completes() {
        let noop = |_: &str| {};
        let r = run_diagnosis(&opts("127.0.0.1"), &ctx(), &noop).await.unwrap();
        assert!(r.dns.is_some());
        assert!(r.ping.is_some());
        assert_eq!(r.ping.unwrap().received, 2);
        assert!(r.summary.is_some());
        assert!(r.meta.finished_at.is_some());
    }

    #[tokio::test]
    async fn empty_target_rejected() {
        let noop = |_: &str| {};
        assert!(run_diagnosis(&opts("  "), &ctx(), &noop).await.is_err());
    }

    #[tokio::test]
    async fn dns_failure_short_circuits_gracefully() {
        let noop = |_: &str| {};
        let r = run_diagnosis(&opts("no-such-host.invalid"), &ctx(), &noop)
            .await
            .unwrap();
        assert!(r.dns.as_ref().unwrap().error.is_some());
        assert!(!r.degradations.is_empty());
        assert_eq!(r.overall, qqhu_core::OverallStatus::Failed);
    }
}
