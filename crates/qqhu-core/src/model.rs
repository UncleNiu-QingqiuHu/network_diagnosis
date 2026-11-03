//! 结构化诊断结果模型 —— 前端与 Markdown 报告的同源契约。
//!
//! 设计要点：所有结构体 `serde(rename_all = "camelCase")`，直接可序列化为前端
//! TypeScript 类型；枚举使用稳定英文 code，中文展示文案由 `zh()` 提供，
//! 避免把展示文案写进数据层。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

// ---------------------------------------------------------------- 枚举

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OverallStatus {
    Ok,
    Degraded,
    Failed,
}

impl Default for OverallStatus {
    fn default() -> Self {
        OverallStatus::Ok
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PortFailureClass {
    Ok,
    Timeout,
    Refused,
    Unreachable,
    Error,
    Unknown,
}

/// 网络质量档位。旧版用中文字符串直接参与比较，此处改为枚举 + 展示文案，
/// 保证前端可做类型判断，报告仍输出原文案。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Grade {
    Excellent,
    Normal,
    Poor,
    Congested,
    Unknown,
}

impl Grade {
    pub fn zh(self) -> &'static str {
        match self {
            Grade::Excellent => "极佳",
            Grade::Normal => "正常",
            Grade::Poor => "较差",
            Grade::Congested => "堵塞",
            Grade::Unknown => "未知",
        }
    }

    /// 供前端直接绑定的配色档位（用于徽章着色）。
    pub fn tone(self) -> &'static str {
        match self {
            Grade::Excellent => "success",
            Grade::Normal => "neutral",
            Grade::Poor => "warning",
            Grade::Congested => "danger",
            Grade::Unknown => "neutral",
        }
    }
}

// ---------------------------------------------------------------- 基础结构

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DegradationEvent {
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskMeta {
    pub task_id: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub app_version: String,
    pub hostname: String,
    pub os_summary: String,
    pub report_dir: PathBuf,
}

impl TaskMeta {
    pub fn new(hostname: impl Into<String>, os_summary: impl Into<String>, report_dir: PathBuf) -> Self {
        let now = Utc::now();
        Self {
            task_id: new_task_id(),
            started_at: now,
            finished_at: None,
            app_version: crate::APP_VERSION.to_string(),
            hostname: hostname.into(),
            os_summary: os_summary.into(),
            report_dir,
        }
    }
}

/// 与旧版 `20260526_231017_a1b2c3d4` 保持同一格式，便于历史索引混用。
pub fn new_task_id() -> String {
    format!(
        "{}_{}",
        Utc::now().format("%Y%m%d_%H%M%S"),
        &Uuid::new_v4().simple().to_string()[..8]
    )
}

/// 用户输入快照 —— 报告可复现的关键，字段与旧版 `RunOptions` 一一对应。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InputSnapshot {
    pub target_host: String,
    pub ports: Vec<u16>,
    pub samples_per_port: u32,
    pub tcp_connect_timeout_ms: u64,
    pub enable_ping: bool,
    pub enable_capture: bool,
    pub prefer_ipv6: bool,
    #[serde(default = "default_ping_count")]
    pub ping_count: u32,
    #[serde(default)]
    pub ping_long: bool,
    #[serde(default = "default_long_ping_seconds")]
    pub long_ping_seconds: u32,
    #[serde(default = "default_ping_timeout")]
    pub ping_packet_timeout_ms: u64,
    #[serde(default)]
    pub enable_traceroute: bool,
    #[serde(default = "default_max_hops")]
    pub traceroute_max_hops: u8,
    #[serde(default = "default_hop_timeout")]
    pub traceroute_hop_timeout_ms: u64,
    #[serde(default = "default_bw_mode")]
    pub bandwidth_mode: String,
    #[serde(default)]
    pub bandwidth_http_url: String,
    #[serde(default = "default_parallel")]
    pub bandwidth_http_parallel: u8,
    #[serde(default = "default_bw_seconds")]
    pub bandwidth_http_seconds: u32,
    #[serde(default)]
    pub bandwidth_iperf_host: String,
    #[serde(default = "default_iperf_port")]
    pub bandwidth_iperf_port: u16,
    #[serde(default = "default_bw_seconds")]
    pub bandwidth_iperf_seconds: u32,
    #[serde(default = "default_parallel")]
    pub bandwidth_iperf_parallel: u8,
    #[serde(default = "default_true")]
    pub bandwidth_iperf_for_quality: bool,
    #[serde(default = "default_udp_bitrate")]
    pub bandwidth_iperf_udp_bitrate: String,
    #[serde(default)]
    pub optional_dns_server: String,
    #[serde(default)]
    pub enable_pathping: bool,
    #[serde(default)]
    pub enable_tcp_traceroute: bool,
    #[serde(default = "default_max_hops")]
    pub tcp_traceroute_max_hops: u8,
    #[serde(default)]
    pub enable_http_tls_probe: bool,
    #[serde(default)]
    pub enable_egress_probe: bool,
    #[serde(default)]
    pub enable_mtu_probe: bool,
    #[serde(default = "default_true")]
    pub enable_history_compare: bool,
    /// 远端探测授权确认 —— 旧版为界面勾选框，跨平台版保留为报告必填字段。
    #[serde(default)]
    pub authorized: bool,
}

fn default_ping_count() -> u32 {
    10
}
fn default_long_ping_seconds() -> u32 {
    30
}
fn default_ping_timeout() -> u64 {
    2000
}
fn default_max_hops() -> u8 {
    30
}
fn default_hop_timeout() -> u64 {
    4000
}
fn default_bw_mode() -> String {
    "off".into()
}
fn default_parallel() -> u8 {
    4
}
fn default_bw_seconds() -> u32 {
    15
}
fn default_iperf_port() -> u16 {
    5201
}
fn default_true() -> bool {
    true
}
fn default_udp_bitrate() -> String {
    "1000M".into()
}

// ---------------------------------------------------------------- 探测结果

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsAnswer {
    pub family: String,
    pub addresses: Vec<String>,
    pub elapsed_ms: f64,
    pub error: Option<String>,
}

impl DnsAnswer {
    pub fn failed(family: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            family: family.into(),
            addresses: Vec::new(),
            elapsed_ms: 0.0,
            error: Some(error.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PingSample {
    pub seq: u32,
    pub rtt_ms: Option<f64>,
    pub ttl: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PingStats {
    pub target: String,
    pub attempted: u32,
    pub received: u32,
    pub lost: u32,
    pub rtts_ms: Vec<f64>,
    pub min_ms: Option<f64>,
    pub max_ms: Option<f64>,
    pub avg_ms: Option<f64>,
    pub samples: Vec<PingSample>,
    #[serde(default)]
    pub raw_stdout: String,
}

impl PingStats {
    pub fn loss_pct(&self) -> Option<f64> {
        if self.attempted == 0 {
            None
        } else {
            Some(100.0 * self.lost as f64 / self.attempted as f64)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortSample {
    pub success: bool,
    pub rtt_ms: Option<f64>,
    pub failure: PortFailureClass,
    #[serde(default)]
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortProbeResult {
    pub port: u16,
    pub samples: Vec<PortSample>,
    pub failure_class: PortFailureClass,
    pub success_count: u32,
    pub success_rate: f64,
}

impl PortProbeResult {
    /// 成功样本的 RTT 集合。
    pub fn ok_rtts(&self) -> impl Iterator<Item = f64> + '_ {
        self.samples.iter().filter(|s| s.success).filter_map(|s| s.rtt_ms)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BandwidthProbeResult {
    pub ok: bool,
    pub mode: String,
    pub target_label: String,
    pub megabits_per_second: Option<f64>,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IperfUdpQualityResult {
    pub ok: bool,
    pub packet_loss_pct: Option<f64>,
    pub jitter_ms: Option<f64>,
    #[serde(default)]
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TracerouteHop {
    pub hop: u8,
    pub addresses: Vec<String>,
    pub rtts_ms: Vec<f64>,
    pub timed_out: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TracerouteResult {
    pub target: String,
    pub hops: Vec<TracerouteHop>,
    pub reached: bool,
    /// 首跳时延合计，可作为端到端路径时延参考。
    pub total_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MtuProbeResult {
    pub target: String,
    pub mtu: Option<u32>,
    pub tested_sizes: Vec<u32>,
    #[serde(default)]
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpTlsProbeResult {
    pub url: String,
    pub ok: bool,
    pub status_code: Option<u16>,
    pub elapsed_ms: Option<f64>,
    pub tls_version: Option<String>,
    pub cert_subject: Option<String>,
    pub cert_issuer: Option<String>,
    pub cert_expires_at: Option<DateTime<Utc>>,
    pub cert_days_left: Option<i64>,
    #[serde(default)]
    pub issues: Vec<String>,
    #[serde(default)]
    pub error: String,
}

// ---------------------------------------------------------------- 综合评估

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkQualityAssessment {
    pub grade: Grade,
    pub loss_pct: Option<f64>,
    pub avg_latency_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    #[serde(default)]
    pub throughput_note: String,
    #[serde(default)]
    pub metric_lines: Vec<String>,
}

/// 面向非技术用户的结论摘要。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuiSummary {
    pub headline: String,
    pub overall: OverallStatus,
    pub grade: Grade,
    pub bullets: Vec<String>,
    #[serde(default)]
    pub actions: Vec<String>,
}

// ---------------------------------------------------------------- 总报告

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticReport {
    pub meta: TaskMeta,
    pub input: InputSnapshot,
    pub dns: Option<DnsAnswer>,
    pub ping: Option<PingStats>,
    pub ports: Vec<PortProbeResult>,
    pub traceroute: Option<TracerouteResult>,
    pub mtu: Option<MtuProbeResult>,
    pub http_tls: Option<HttpTlsProbeResult>,
    pub bandwidth: Option<BandwidthProbeResult>,
    pub iperf_udp: Option<IperfUdpQualityResult>,
    pub quality: Option<NetworkQualityAssessment>,
    pub degradations: Vec<DegradationEvent>,
    pub overall: OverallStatus,
    pub summary: Option<GuiSummary>,
}

impl DiagnosticReport {
    pub fn new(meta: TaskMeta, input: InputSnapshot) -> Self {
        Self {
            meta,
            input,
            dns: None,
            ping: None,
            ports: Vec::new(),
            traceroute: None,
            mtu: None,
            http_tls: None,
            bandwidth: None,
            iperf_udp: None,
            quality: None,
            degradations: Vec::new(),
            overall: OverallStatus::Ok,
            summary: None,
        }
    }

    pub fn degrade(&mut self, code: impl Into<String>, message: impl Into<String>, detail: impl Into<String>) {
        self.degradations.push(DegradationEvent {
            code: code.into(),
            message: message.into(),
            detail: detail.into(),
        });
    }
}
