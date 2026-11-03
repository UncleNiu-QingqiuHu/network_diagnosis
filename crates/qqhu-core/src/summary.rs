//! 结论摘要生成 —— 供界面「结论」区与报告摘要共用同一份数据。

use crate::model::{
    DiagnosticReport, Grade, GuiSummary, OverallStatus, PortFailureClass,
};

/// 根据报告内容生成面向非技术用户的摘要。
pub fn build_summary(report: &DiagnosticReport) -> GuiSummary {
    let mut bullets: Vec<String> = Vec::new();
    let mut actions: Vec<String> = Vec::new();

    // ---- DNS
    match &report.dns {
        Some(d) if d.error.is_some() => {
            bullets.push(format!("域名解析失败：{}", d.error.as_deref().unwrap_or("未知原因")));
            actions.push("检查 DNS 服务器配置或域名拼写".into());
        }
        Some(d) if !d.addresses.is_empty() => {
            bullets.push(format!(
                "解析到 {} 个地址：{}（{} ms）",
                d.addresses.len(),
                d.addresses.join(", "),
                d.elapsed_ms.round() as i64
            ));
        }
        _ => {}
    }

    // ---- ICMP
    if let Some(p) = &report.ping {
        if p.attempted > 0 {
            let loss = p.loss_pct().unwrap_or(0.0);
            let avg = p.avg_ms.map(|v| format!("{v:.1} ms")).unwrap_or_else(|| "—".into());
            bullets.push(format!(
                "ICMP：{}/{} 通，丢包 {:.0}%，平均时延 {}",
                p.received, p.attempted, loss, avg
            ));
            if p.received == 0 {
                actions.push("目标不响应 ICMP，可改用端口探测判断连通性".into());
            }
        }
    }

    // ---- TCP 端口
    if !report.ports.is_empty() {
        let open: Vec<u16> = report
            .ports
            .iter()
            .filter(|p| p.failure_class == PortFailureClass::Ok)
            .map(|p| p.port)
            .collect();
        let closed = report.ports.len() - open.len();
        if open.is_empty() {
            bullets.push(format!("端口：{} 个端口全部不可达", report.ports.len()));
            actions.push("确认目标服务是否在运行、防火墙是否放行".into());
        } else {
            bullets.push(format!(
                "端口：{} 个开放（{}）{}",
                open.len(),
                open.iter().map(u16::to_string).collect::<Vec<_>>().join(", "),
                if closed > 0 { format!("，{closed} 个不可达") } else { String::new() }
            ));
        }
    }

    // ---- 质量档位
    let grade = report
        .quality
        .as_ref()
        .map(|q| q.grade)
        .unwrap_or(Grade::Unknown);

    let dns_failed = report.dns.as_ref().map(|d| d.error.is_some()).unwrap_or(false);
    let ping_tried = report.ping.as_ref().map(|p| p.attempted > 0).unwrap_or(false);
    let ping_ok = report.ping.as_ref().map(|p| p.received > 0).unwrap_or(false);
    let all_ports_bad = !report.ports.is_empty()
        && report
            .ports
            .iter()
            .all(|p| p.failure_class != PortFailureClass::Ok);
    let any_port_ok = report
        .ports
        .iter()
        .any(|p| p.failure_class == PortFailureClass::Ok);

    // 判定要点：主机可达与端口可达是两件事。
    // ICMP 通但端口全不通，说明主机在线、只是服务未监听或被过滤，属于「降级」而非「中断」。
    let overall = if dns_failed {
        OverallStatus::Failed
    } else if all_ports_bad && !any_port_ok {
        if ping_ok {
            OverallStatus::Degraded
        } else if ping_tried {
            // ICMP 全丢且端口全不通 —— 真实不可达
            OverallStatus::Failed
        } else {
            // 没有可达性证据，只凭端口判断
            OverallStatus::Failed
        }
    } else {
        match grade {
            Grade::Poor | Grade::Congested => OverallStatus::Degraded,
            _ if !report.degradations.is_empty() => OverallStatus::Degraded,
            _ => OverallStatus::Ok,
        }
    };

    let headline = match (overall, all_ports_bad && ping_ok) {
        (OverallStatus::Failed, _) if dns_failed => "域名解析失败，无法发起探测".to_string(),
        (OverallStatus::Failed, _) => "目标不可达，链路疑似中断".to_string(),
        (OverallStatus::Degraded, true) => "主机可达，但目标端口均未响应".to_string(),
        (OverallStatus::Degraded, false) => format!("链路{}，存在可用性问题", grade.zh()),
        (OverallStatus::Ok, _) => format!("链路{}，未发现明显异常", grade.zh()),
    };

    if all_ports_bad && ping_ok {
        // 上面端口段落已给出通用建议，这里补一条更精确的因果判断
        actions.retain(|a| !a.contains("确认目标服务是否在运行"));
        actions.push("主机在线但端口无响应：优先排查服务是否监听、防火墙规则是否放行".into());
    }

    for d in &report.degradations {
        bullets.push(format!("降级：{}", d.message));
    }

    GuiSummary {
        headline,
        overall,
        grade,
        bullets,
        actions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;
    use chrono::Utc;
    use std::path::PathBuf;

    fn base_report() -> DiagnosticReport {
        let meta = TaskMeta {
            task_id: "t".into(),
            started_at: Utc::now(),
            finished_at: None,
            app_version: "test".into(),
            hostname: "h".into(),
            os_summary: "o".into(),
            report_dir: PathBuf::from("."),
        };
        DiagnosticReport::new(
            meta,
            InputSnapshot {
                target_host: "10.0.0.1".into(),
                ports: vec![443],
                samples_per_port: 1,
                tcp_connect_timeout_ms: 1000,
                enable_ping: true,
                enable_capture: false,
                prefer_ipv6: false,
                ping_count: 3,
                ping_long: false,
                long_ping_seconds: 30,
                ping_packet_timeout_ms: 2000,
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
            },
        )
    }

    #[test]
    fn healthy_report_is_ok() {
        let mut r = base_report();
        r.dns = Some(DnsAnswer {
            family: "ipv4".into(),
            addresses: vec!["10.0.0.1".into()],
            elapsed_ms: 3.0,
            error: None,
        });
        r.ports = vec![PortProbeResult {
            port: 443,
            samples: vec![],
            failure_class: PortFailureClass::Ok,
            success_count: 1,
            success_rate: 1.0,
        }];
        let s = build_summary(&r);
        assert_eq!(s.overall, OverallStatus::Ok);
        assert!(s.headline.contains("未发现明显异常"));
    }

    #[test]
    fn dns_failure_is_failed() {
        let mut r = base_report();
        r.dns = Some(DnsAnswer::failed("ipv4", "查询超时"));
        let s = build_summary(&r);
        assert_eq!(s.overall, OverallStatus::Failed);
        assert!(!s.actions.is_empty());
    }

    #[test]
    fn all_ports_bad_is_failed() {
        let mut r = base_report();
        r.ports = vec![PortProbeResult {
            port: 443,
            samples: vec![],
            failure_class: PortFailureClass::Timeout,
            success_count: 0,
            success_rate: 0.0,
        }];
        let s = build_summary(&r);
        assert_eq!(s.overall, OverallStatus::Failed);
    }

    #[test]
    fn reachable_host_with_blocked_ports_is_degraded_not_failed() {
        let mut r = base_report();
        r.dns = Some(DnsAnswer {
            family: "ipv4".into(),
            addresses: vec!["10.0.0.1".into()],
            elapsed_ms: 1.0,
            error: None,
        });
        r.ping = Some(PingStats {
            target: "10.0.0.1".into(),
            attempted: 3,
            received: 3,
            lost: 0,
            rtts_ms: vec![1.0, 1.2, 0.9],
            min_ms: Some(0.9),
            max_ms: Some(1.2),
            avg_ms: Some(1.03),
            samples: vec![],
            raw_stdout: String::new(),
        });
        r.ports = vec![PortProbeResult {
            port: 443,
            samples: vec![],
            failure_class: PortFailureClass::Timeout,
            success_count: 0,
            success_rate: 0.0,
        }];
        let s = build_summary(&r);
        assert_eq!(
            s.overall,
            OverallStatus::Degraded,
            "ICMP 通说明主机在线，不应判为链路中断"
        );
        assert!(s.headline.contains("端口"), "结论应点明端口不通，而不是整体不可达");
        assert!(s.actions.iter().any(|a| a.contains("防火墙")));
    }
}
