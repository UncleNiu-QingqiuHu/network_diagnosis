//! 青丘湖网络工作台 —— 报告层。
//!
//! - [`markdown`]：把 `DiagnosticReport` 渲染为可直接归档的 Markdown 技术报告
//! - [`history`]：同目标历史索引与本次/上次对比
//!
//! 两者都只做纯计算与本地文件读写，不依赖任何平台 API。

pub mod history;
pub mod markdown;
pub mod persist;

pub use history::{HistoryCompare, HistoryEntry, HistoryStore, MAX_HISTORY_ENTRIES};
pub use markdown::render_report;
pub use persist::{persist, DiagnosisArtifacts};

#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    #[error("写入报告失败：{0}")]
    Write(String),

    #[error("读取历史索引失败：{0}")]
    ReadHistory(String),

    #[error("历史索引损坏：{0}")]
    HistoryCorrupt(String),
}
