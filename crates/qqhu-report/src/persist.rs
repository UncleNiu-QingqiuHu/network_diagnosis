//! 诊断产物落盘：创建任务目录 → 生成对比 → 渲染 Markdown → 追加历史。
//!
//! 抽成单一入口，Tauri 命令与 CLI 共用，避免两处实现漂移。

use crate::history::{HistoryEntry, HistoryStore};
use crate::markdown::render_report;
use crate::ReportError;
use qqhu_core::DiagnosticReport;
use std::path::{Path, PathBuf};

/// 落盘结果。
#[derive(Debug, Clone)]
pub struct DiagnosisArtifacts {
    pub report_path: PathBuf,
    pub task_dir: PathBuf,
    pub compare: Option<crate::HistoryCompare>,
}

/// 把一次诊断结果写成报告并登记到历史索引。
///
/// `base_dir` 是诊断根目录（如 `reports/diagnosis`），任务目录在其下按 `task_id` 创建。
/// 成功后会把 `report.meta.report_dir` 指向实际任务目录。
pub fn persist(report: &mut DiagnosticReport, base_dir: &Path) -> Result<DiagnosisArtifacts, ReportError> {
    let task_dir = base_dir.join(&report.meta.task_id);
    std::fs::create_dir_all(&task_dir).map_err(|e| ReportError::Write(e.to_string()))?;
    report.meta.report_dir = task_dir.clone();

    let store = HistoryStore::under(base_dir);
    let compare = store.compare(report);

    let markdown = render_report(report, compare.as_ref());
    let report_path = task_dir.join("report.md");
    std::fs::write(&report_path, markdown).map_err(|e| ReportError::Write(e.to_string()))?;

    let entry = HistoryEntry::from_report(report, &report_path.to_string_lossy());
    store.append(entry)?;

    Ok(DiagnosisArtifacts {
        report_path,
        task_dir,
        compare,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use qqhu_core::*;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("qqhu-persist-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn report_with(target: &str, grade: Grade, avg: f64) -> DiagnosticReport {
        let meta = TaskMeta::new("h", "o", PathBuf::from("."));
        let input = InputSnapshot {
            target_host: target.into(),
            ports: vec![443],
            samples_per_port: 1,
            tcp_connect_timeout_ms: 1000,
            enable_ping: true,
            enable_capture: false,
            prefer_ipv6: false,
            ping_count: 1,
            ping_long: false,
            long_ping_seconds: 30,
            ping_packet_timeout_ms: 1000,
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
        r.meta.finished_at = Some(chrono::Utc::now());
        r.quality = Some(NetworkQualityAssessment {
            grade,
            loss_pct: Some(0.0),
            avg_latency_ms: Some(avg),
            jitter_ms: Some(1.0),
            throughput_note: String::new(),
            metric_lines: vec![],
        });
        r
    }

    #[test]
    fn writes_report_and_indexes_history() {
        let base = dir("basic");
        let mut r = report_with("10.0.0.1", Grade::Normal, 10.0);
        let a = persist(&mut r, &base).unwrap();

        assert!(a.report_path.exists(), "报告文件必须存在");
        assert_eq!(r.meta.report_dir, a.task_dir, "元信息目录应指向任务目录");
        assert!(a.compare.is_none(), "首次诊断无历史可对比");

        let store = HistoryStore::under(&base);
        assert_eq!(store.load().len(), 1);

        let text = std::fs::read_to_string(&a.report_path).unwrap();
        assert!(text.contains("网络诊断报告"));
        assert!(text.contains("10.0.0.1"));
    }

    #[test]
    fn second_run_produces_compare() {
        let base = dir("compare");
        let mut first = report_with("10.0.0.1", Grade::Normal, 20.0);
        persist(&mut first, &base).unwrap();

        let mut second = report_with("10.0.0.1", Grade::Excellent, 10.0);
        let a = persist(&mut second, &base).unwrap();

        let c = a.compare.expect("第二次应有对比");
        assert_eq!(c.previous_grade, Grade::Normal);
        assert_eq!(c.current_grade, Grade::Excellent);
        assert!(c.latency_delta_ms.unwrap() < 0.0, "时延应显示下降");

        let text = std::fs::read_to_string(&a.report_path).unwrap();
        assert!(text.contains("与上次诊断对比"));
    }

    #[test]
    fn different_targets_do_not_compare() {
        let base = dir("cross");
        let mut a1 = report_with("10.0.0.1", Grade::Normal, 10.0);
        persist(&mut a1, &base).unwrap();
        let mut b = report_with("10.0.0.2", Grade::Poor, 90.0);
        let art = persist(&mut b, &base).unwrap();
        assert!(art.compare.is_none(), "不同目标之间不应比较");
    }
}
