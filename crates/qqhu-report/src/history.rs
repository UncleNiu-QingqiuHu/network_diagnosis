//! 同目标历史索引与对比。
//!
//! 索引文件是单个 JSON 数组，默认位于 `reports/diagnosis/_history.json`。
//! 写入采用「临时文件 + 重命名」，避免进程中断留下半截 JSON。

use crate::ReportError;
use chrono::{DateTime, Utc};
use qqhu_core::{DiagnosticReport, Grade, OverallStatus, PortFailureClass};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// 保留的最大历史条数，超出后丢弃最旧的。
pub const MAX_HISTORY_ENTRIES: usize = 500;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryEntry {
    pub task_id: String,
    pub target: String,
    pub finished_at: DateTime<Utc>,
    pub overall: OverallStatus,
    pub grade: Grade,
    pub loss_pct: Option<f64>,
    pub avg_latency_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub open_ports: Vec<u16>,
    pub report_path: String,
}

impl HistoryEntry {
    pub fn from_report(report: &DiagnosticReport, report_path: &str) -> Self {
        let quality = report.quality.as_ref();
        let open_ports: Vec<u16> = report
            .ports
            .iter()
            .filter(|p| p.failure_class == PortFailureClass::Ok)
            .map(|p| p.port)
            .collect();

        Self {
            task_id: report.meta.task_id.clone(),
            target: report.input.target_host.clone(),
            finished_at: report.meta.finished_at.unwrap_or_else(Utc::now),
            overall: report.overall,
            grade: quality.map(|q| q.grade).unwrap_or(Grade::Unknown),
            loss_pct: quality.and_then(|q| q.loss_pct),
            avg_latency_ms: quality.and_then(|q| q.avg_latency_ms),
            jitter_ms: quality.and_then(|q| q.jitter_ms),
            open_ports,
            report_path: report_path.to_string(),
        }
    }

    pub fn has_port(&self, port: u16) -> bool {
        self.open_ports.contains(&port)
    }
}

/// 本次与上一次同目标诊断的差异。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryCompare {
    pub previous_finished_at: DateTime<Utc>,
    pub previous_grade: Grade,
    pub current_grade: Grade,
    pub loss_delta: Option<f64>,
    pub latency_delta_ms: Option<f64>,
    pub jitter_delta_ms: Option<f64>,
    pub summary: String,
}

pub struct HistoryStore {
    path: PathBuf,
}

impl HistoryStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// `reports/diagnosis/_history.json`
    pub fn under(dir: &Path) -> Self {
        Self::new(dir.join("_history.json"))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 读取全部历史。文件不存在或损坏时返回空列表，不阻断诊断流程。
    pub fn load(&self) -> Vec<HistoryEntry> {
        let Ok(text) = std::fs::read_to_string(&self.path) else {
            return Vec::new();
        };
        match serde_json::from_str::<Vec<HistoryEntry>>(&text) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(path = %self.path.display(), "历史索引解析失败，按空处理: {e}");
                Vec::new()
            }
        }
    }

    /// 同目标最近一次记录（不包含 `task_id` 相同的本次记录）。
    pub fn last_for(&self, target: &str, exclude_task_id: &str) -> Option<HistoryEntry> {
        self.load()
            .into_iter()
            .rev()
            .find(|e| e.target == target && e.task_id != exclude_task_id)
    }

    /// 追加一条记录，超过上限时裁剪最旧的。
    pub fn append(&self, entry: HistoryEntry) -> Result<(), ReportError> {
        let mut all = self.load();
        all.push(entry);
        if all.len() > MAX_HISTORY_ENTRIES {
            let drop_n = all.len() - MAX_HISTORY_ENTRIES;
            all.drain(0..drop_n);
        }
        self.save(&all)
    }

    /// 基于当前报告生成对比结果；无历史时返回 `None`。
    pub fn compare(&self, report: &DiagnosticReport) -> Option<HistoryCompare> {
        let prev = self.last_for(&report.input.target_host, &report.meta.task_id)?;
        let quality = report.quality.as_ref();
        let current_grade = quality.map(|q| q.grade).unwrap_or(Grade::Unknown);

        let loss_delta = diff(quality.and_then(|q| q.loss_pct), prev.loss_pct);
        let latency_delta_ms = diff(quality.and_then(|q| q.avg_latency_ms), prev.avg_latency_ms);
        let jitter_delta_ms = diff(quality.and_then(|q| q.jitter_ms), prev.jitter_ms);

        Some(HistoryCompare {
            previous_finished_at: prev.finished_at,
            previous_grade: prev.grade,
            current_grade,
            loss_delta,
            latency_delta_ms,
            jitter_delta_ms,
            summary: describe(prev.grade, current_grade, loss_delta, latency_delta_ms),
        })
    }

    fn save(&self, entries: &[HistoryEntry]) -> Result<(), ReportError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| ReportError::Write(e.to_string()))?;
        }
        let json = serde_json::to_string_pretty(entries).map_err(|e| ReportError::Write(e.to_string()))?;

        // 原子写：先写临时文件再替换，避免半截文件
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, json).map_err(|e| ReportError::Write(e.to_string()))?;
        std::fs::rename(&tmp, &self.path).map_err(|e| ReportError::Write(e.to_string()))?;
        Ok(())
    }
}

fn diff(current: Option<f64>, previous: Option<f64>) -> Option<f64> {
    match (current, previous) {
        (Some(c), Some(p)) => Some(((c - p) * 100.0).round() / 100.0),
        _ => None,
    }
}

fn grade_rank(g: Grade) -> u8 {
    match g {
        Grade::Congested => 0,
        Grade::Poor => 1,
        Grade::Normal => 2,
        Grade::Excellent => 3,
        Grade::Unknown => 2,
    }
}

fn describe(prev: Grade, cur: Grade, loss_delta: Option<f64>, latency_delta: Option<f64>) -> String {
    let pr = grade_rank(prev);
    let cr = grade_rank(cur);
    if cr > pr {
        return "较上次改善".into();
    }
    if cr < pr {
        return "较上次变差".into();
    }
    if let Some(d) = loss_delta {
        if d >= 5.0 {
            return format!("档位未变，但丢包上升 {d:.1} 个百分点");
        }
        if d <= -5.0 {
            return format!("档位未变，丢包下降 {:.1} 个百分点", d.abs());
        }
    }
    if let Some(d) = latency_delta {
        if d >= 50.0 {
            return format!("档位未变，但平均时延上升 {d:.0} ms");
        }
        if d <= -50.0 {
            return format!("档位未变，平均时延下降 {:.0} ms", d.abs());
        }
    }
    "与上次基本持平".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("qqhu-hist-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn entry(task: &str, target: &str, grade: Grade) -> HistoryEntry {
        HistoryEntry {
            task_id: task.into(),
            target: target.into(),
            finished_at: Utc::now(),
            overall: OverallStatus::Ok,
            grade,
            loss_pct: Some(0.0),
            avg_latency_ms: Some(10.0),
            jitter_ms: Some(1.0),
            open_ports: vec![443],
            report_path: "r.md".into(),
        }
    }

    #[test]
    fn append_and_load_roundtrip() {
        let dir = tmp_dir("roundtrip");
        let store = HistoryStore::under(&dir);
        store.append(entry("t1", "10.0.0.1", Grade::Normal)).unwrap();
        store.append(entry("t2", "10.0.0.1", Grade::Poor)).unwrap();

        let all = store.load();
        assert_eq!(all.len(), 2);
        assert_eq!(all[1].grade, Grade::Poor);
        assert!(store.path().exists());
    }

    #[test]
    fn last_for_filters_target_and_task() {
        let dir = tmp_dir("lastfor");
        let store = HistoryStore::under(&dir);
        store.append(entry("t1", "a", Grade::Normal)).unwrap();
        store.append(entry("t2", "b", Grade::Poor)).unwrap();
        store.append(entry("t3", "a", Grade::Excellent)).unwrap();

        let last_a = store.last_for("a", "t4").unwrap();
        assert_eq!(last_a.task_id, "t3");

        // 排除自己：t3 是本次，应回退到 t1
        let prev_a = store.last_for("a", "t3").unwrap();
        assert_eq!(prev_a.task_id, "t1");

        assert!(store.last_for("c", "t4").is_none());
    }

    #[test]
    fn pruning_keeps_most_recent() {
        let dir = tmp_dir("prune");
        let store = HistoryStore::under(&dir);
        for i in 0..MAX_HISTORY_ENTRIES + 5 {
            store.append(entry(&format!("t{i}"), "x", Grade::Normal)).unwrap();
        }
        let all = store.load();
        assert_eq!(all.len(), MAX_HISTORY_ENTRIES);
        assert_eq!(all.last().unwrap().task_id, format!("t{}", MAX_HISTORY_ENTRIES + 4));
    }

    #[test]
    fn corrupt_file_degrades_to_empty() {
        let dir = tmp_dir("corrupt");
        let store = HistoryStore::under(&dir);
        std::fs::write(store.path(), "{ not json").unwrap();
        assert!(store.load().is_empty(), "损坏的历史不应让诊断崩溃");
    }

    #[test]
    fn describe_detects_improvement_and_regression() {
        assert_eq!(describe(Grade::Poor, Grade::Normal, None, None), "较上次改善");
        assert_eq!(describe(Grade::Normal, Grade::Poor, None, None), "较上次变差");
        assert!(describe(Grade::Normal, Grade::Normal, Some(8.0), None).contains("丢包上升"));
        assert_eq!(describe(Grade::Normal, Grade::Normal, Some(0.0), Some(0.0)), "与上次基本持平");
    }
}
