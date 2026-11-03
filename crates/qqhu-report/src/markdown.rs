//! Markdown 技术报告渲染。
//!
//! 与界面共用同一份 [`DiagnosticReport`]，避免「界面上看到的」与「报告里写的」不一致。

use crate::history::HistoryCompare;
use chrono::{DateTime, Local, Utc};
use qqhu_core::{DiagnosticReport, PortFailureClass, PingStats};

const MAX_PING_ROWS: usize = 30;

/// 渲染完整报告。`compare` 存在时会追加「与上次诊断对比」章节。
pub fn render_report(report: &DiagnosticReport, compare: Option<&HistoryCompare>) -> String {
    let mut md = String::with_capacity(4096);

    // ---- 标题
    md.push_str(&format!(
        "# 网络诊断报告 · {}\n\n",
        esc(&report.input.target_host)
    ));
    if let Some(s) = &report.summary {
        md.push_str(&format!("> 结论：**{}**（{}）\n\n", esc(&s.headline), s.grade.zh()));
    }

    // ---- 任务信息
    md.push_str("## 任务信息\n\n| 项 | 值 |\n|---|---|\n");
    row(&mut md, "任务 ID", &report.meta.task_id);
    row(&mut md, "开始时间", &fmt_dt(report.meta.started_at));
    row(&mut md, "完成时间", &report.meta.finished_at.map(fmt_dt).unwrap_or_else(|| "—".into()));
    row(&mut md, "程序版本", &report.meta.app_version);
    row(&mut md, "执行主机", &report.meta.hostname);
    row(&mut md, "操作系统", &report.meta.os_summary);
    row(&mut md, "报告目录", &report.meta.report_dir.display().to_string());
    md.push('\n');

    // ---- 结论
    if let Some(s) = &report.summary {
        md.push_str("## 结论与建议\n\n");
        for b in &s.bullets {
            md.push_str(&format!("- {}\n", esc(b)));
        }
        if !s.actions.is_empty() {
            md.push_str("\n**建议**\n\n");
            for a in &s.actions {
                md.push_str(&format!("- {}\n", esc(a)));
            }
        }
        md.push('\n');
    }

    // ---- 输入
    md.push_str("## 输入参数\n\n| 项 | 值 |\n|---|---|\n");
    let ports = if report.input.ports.is_empty() {
        "（未配置）".to_string()
    } else {
        report.input.ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", ")
    };
    row(&mut md, "目标", &report.input.target_host);
    row(&mut md, "端口", &ports);
    row(&mut md, "每端口样本", &report.input.samples_per_port.to_string());
    row(&mut md, "TCP 连接超时", &format!("{} ms", report.input.tcp_connect_timeout_ms));
    row(&mut md, "ICMP", if report.input.enable_ping { "启用" } else { "关闭" });
    row(&mut md, "ICMP 发包数", &report.input.ping_count.to_string());
    row(&mut md, "ICMP 单包超时", &format!("{} ms", report.input.ping_packet_timeout_ms));
    row(&mut md, "优先 IPv6", if report.input.prefer_ipv6 { "是" } else { "否" });
    md.push('\n');

    // ---- DNS
    md.push_str("## 域名解析\n\n");
    match &report.dns {
        Some(d) if d.error.is_some() => {
            md.push_str(&format!("解析失败：{}\n\n", esc(d.error.as_deref().unwrap_or("未知原因"))));
        }
        Some(d) => {
            md.push_str(&format!(
                "- 协议族：{}\n- 地址：{}\n- 耗时：{:.1} ms\n\n",
                esc(&d.family),
                if d.addresses.is_empty() {
                    "—".to_string()
                } else {
                    d.addresses.iter().map(|a| esc(a)).collect::<Vec<_>>().join(", ")
                },
                d.elapsed_ms
            ));
        }
        None => md.push_str("未执行。\n\n"),
    }

    // ---- ICMP
    md.push_str("## ICMP 连通性\n\n");
    match &report.ping {
        Some(p) if p.attempted > 0 => render_ping(&mut md, p),
        _ => md.push_str("未启用或未获得样本。\n\n"),
    }

    // ---- 端口
    md.push_str("## 端口探测\n\n");
    if report.ports.is_empty() {
        md.push_str("未配置端口。\n\n");
    } else {
        md.push_str("| 端口 | 状态 | 成功率 | 平均 RTT | 最小 | 最大 |\n|---|---|---|---|---|---|\n");
        for pr in &report.ports {
            let rtts: Vec<f64> = pr.ok_rtts().collect();
            let avg = if rtts.is_empty() {
                "—".to_string()
            } else {
                format!("{:.1} ms", rtts.iter().sum::<f64>() / rtts.len() as f64)
            };
            let min = rtts.iter().cloned().reduce(f64::min).map(|v| format!("{v:.1} ms"));
            let max = rtts.iter().cloned().reduce(f64::max).map(|v| format!("{v:.1} ms"));
            md.push_str(&format!(
                "| {} | {} | {:.0}% | {} | {} | {} |\n",
                pr.port,
                failure_zh(pr.failure_class),
                pr.success_rate * 100.0,
                avg,
                min.unwrap_or_else(|| "—".into()),
                max.unwrap_or_else(|| "—".into()),
            ));
        }
        md.push('\n');
    }

    // ---- 质量
    if let Some(q) = &report.quality {
        md.push_str("## 质量评判\n\n");
        md.push_str(&format!("档位：**{}**\n\n", q.grade.zh()));
        for line in &q.metric_lines {
            md.push_str(&format!("- {}\n", esc(line)));
        }
        md.push('\n');
    }

    // ---- 对比
    if let Some(c) = compare {
        md.push_str("## 与上次诊断对比\n\n");
        md.push_str(&format!("- 上次时间：{}\n", fmt_dt(c.previous_finished_at)));
        md.push_str(&format!("- 上次档位：{} → 本次：{}\n", c.previous_grade.zh(), c.current_grade.zh()));
        md.push_str(&format!("- 丢包变化：{}\n", fmt_delta(c.loss_delta, "%")));
        md.push_str(&format!("- 平均时延变化：{}\n", fmt_delta(c.latency_delta_ms, " ms")));
        md.push_str(&format!("- 抖动变化：{}\n", fmt_delta(c.jitter_delta_ms, " ms")));
        md.push_str(&format!("- 判定：{}\n\n", esc(&c.summary)));
    }

    // ---- 降级
    if !report.degradations.is_empty() {
        md.push_str("## 降级事件\n\n");
        for d in &report.degradations {
            if d.detail.is_empty() {
                md.push_str(&format!("- `{}` {}\n", d.code, esc(&d.message)));
            } else {
                md.push_str(&format!("- `{}` {}：{}\n", d.code, esc(&d.message), esc(&d.detail)));
            }
        }
        md.push('\n');
    }

    md.push_str("---\n\n");
    md.push_str(&format!(
        "本报告由青丘湖网络工作台 v{} 生成于 {}。所有探测均为本机原生实现，未调用系统 ping/tcping。\n",
        report.meta.app_version,
        fmt_dt(Utc::now())
    ));

    md
}

fn render_ping(md: &mut String, p: &PingStats) {
    let loss = p.loss_pct().unwrap_or(0.0);
    md.push_str(&format!(
        "| 指标 | 值 |\n|---|---|\n| 发送/接收 | {} / {} |\n| 丢包率 | {:.0}% |\n| 平均 | {} |\n| 最小 | {} |\n| 最大 | {} |\n\n",
        p.attempted,
        p.received,
        loss,
        fmt_ms(p.avg_ms),
        fmt_ms(p.min_ms),
        fmt_ms(p.max_ms),
    ));

    if !p.samples.is_empty() {
        md.push_str("逐包结果：\n\n| # | RTT |\n|---|---|\n");
        for s in p.samples.iter().take(MAX_PING_ROWS) {
            let v = s.rtt_ms.map(|v| format!("{v:.1} ms")).unwrap_or_else(|| "超时".into());
            md.push_str(&format!("| {} | {} |\n", s.seq + 1, v));
        }
        if p.samples.len() > MAX_PING_ROWS {
            md.push_str(&format!("\n> 仅列出前 {MAX_PING_ROWS} 条，共 {} 条。\n", p.samples.len()));
        }
        md.push('\n');
    }
}

fn failure_zh(c: PortFailureClass) -> &'static str {
    match c {
        PortFailureClass::Ok => "开放",
        PortFailureClass::Timeout => "超时",
        PortFailureClass::Refused => "拒绝",
        PortFailureClass::Unreachable => "不可达",
        PortFailureClass::Error => "错误",
        PortFailureClass::Unknown => "未知",
    }
}

fn fmt_ms(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.1} ms")).unwrap_or_else(|| "—".into())
}

fn fmt_delta(v: Option<f64>, unit: &str) -> String {
    match v {
        None => "无对比数据".into(),
        Some(d) if d.abs() < 0.05 => "基本持平".into(),
        Some(d) if d > 0.0 => format!("上升 {:.1}{unit}", d),
        Some(d) => format!("下降 {:.1}{unit}", d.abs()),
    }
}

fn fmt_dt(t: DateTime<Utc>) -> String {
    t.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S").to_string()
}

fn row(md: &mut String, k: &str, v: &str) {
    md.push_str(&format!("| {} | {} |\n", esc(k), esc(v)));
}

/// 表格单元格转义：竖线与换行会破坏 Markdown 表格结构。
fn esc(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use qqhu_core::*;
    use std::path::PathBuf;

    fn sample_report() -> DiagnosticReport {
        let meta = TaskMeta {
            task_id: "20261103_120000_abcd1234".into(),
            started_at: Utc::now(),
            finished_at: Some(Utc::now()),
            app_version: "4.0.0-alpha.2".into(),
            hostname: "PC-01".into(),
            os_summary: "Windows x86_64".into(),
            report_dir: PathBuf::from("/tmp/r"),
        };
        let input = InputSnapshot {
            target_host: "10.0.0.1".into(),
            ports: vec![443, 80],
            samples_per_port: 2,
            tcp_connect_timeout_ms: 1000,
            enable_ping: true,
            enable_capture: false,
            prefer_ipv6: false,
            ping_count: 2,
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
        };
        let mut r = DiagnosticReport::new(meta, input);
        r.dns = Some(DnsAnswer {
            family: "ipv4".into(),
            addresses: vec!["10.0.0.1".into()],
            elapsed_ms: 2.0,
            error: None,
        });
        r.ping = Some(PingStats {
            target: "10.0.0.1".into(),
            attempted: 2,
            received: 2,
            lost: 0,
            rtts_ms: vec![1.0, 1.5],
            min_ms: Some(1.0),
            max_ms: Some(1.5),
            avg_ms: Some(1.25),
            samples: vec![],
            raw_stdout: String::new(),
        });
        r.ports = vec![PortProbeResult {
            port: 443,
            samples: vec![],
            failure_class: PortFailureClass::Ok,
            success_count: 2,
            success_rate: 1.0,
        }];
        r.quality = Some(NetworkQualityAssessment {
            grade: Grade::Excellent,
            loss_pct: Some(0.0),
            avg_latency_ms: Some(1.25),
            jitter_ms: Some(0.5),
            throughput_note: String::new(),
            metric_lines: vec!["丢包率：0.0%".into()],
        });
        r.summary = Some(GuiSummary {
            headline: "链路极佳，未发现明显异常".into(),
            overall: OverallStatus::Ok,
            grade: Grade::Excellent,
            bullets: vec!["ICMP：2/2 通".into()],
            actions: vec![],
        });
        r
    }

    #[test]
    fn contains_all_major_sections() {
        let md = render_report(&sample_report(), None);
        for h in ["# 网络诊断报告", "## 任务信息", "## 结论与建议", "## 输入参数", "## 域名解析", "## ICMP 连通性", "## 端口探测", "## 质量评判"] {
            assert!(md.contains(h), "缺少章节: {h}");
        }
        assert!(md.contains("10.0.0.1"));
        assert!(md.contains("4.0.0-alpha.2"));
    }

    #[test]
    fn table_pipe_is_escaped() {
        let mut r = sample_report();
        r.input.target_host = "a|b".into();
        let md = render_report(&r, None);
        assert!(md.contains("a\\|b"), "竖线必须转义，否则表格会错位");
    }

    #[test]
    fn compare_section_rendered_when_present() {
        let c = HistoryCompare {
            previous_finished_at: Utc::now(),
            previous_grade: Grade::Normal,
            current_grade: Grade::Excellent,
            loss_delta: Some(-1.0),
            latency_delta_ms: Some(-5.0),
            jitter_delta_ms: None,
            summary: "较上次改善".into(),
        };
        let md = render_report(&sample_report(), Some(&c));
        assert!(md.contains("## 与上次诊断对比"));
        assert!(md.contains("较上次改善"));
        assert!(md.contains("下降 5.0 ms"));
    }

    #[test]
    fn empty_ports_renders_notice() {
        let mut r = sample_report();
        r.ports.clear();
        let md = render_report(&r, None);
        assert!(md.contains("未配置端口"));
    }
}
