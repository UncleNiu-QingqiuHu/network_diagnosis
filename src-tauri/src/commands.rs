//! Tauri IPC 契约。
//!
//! 约定：所有命令的出入参都走 `serde(rename_all = "camelCase")`，
//! 与 `src/lib/types.ts` 一一对应。前端不硬编码模块清单，
//! 而是由 [`app_info`] 返回，平台差异在这里统一收敛。

use qqhu_core::{
    calc_from_cidr_combo, calc_subnet, parse_scan_scope, subdivide_ipv4_equal_children,
    DiagnosticReport, IpScanReport, MacScanReport, OuiDb, SubnetCalcResult, MAX_SCAN_HOSTS,
};
use qqhu_probe::{
    run_diagnosis as probe_run, run_mac_scan, scan_scope, DiagContext, DiagOptions, IpScanOptions,
    MacScanOptions, MacScanProgress, PingOptions, ScanProgress, TcpProbeOptions,
};
use qqhu_sys::{host, CapabilitySet, CapabilityLevel, PlatformKind};
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter, State};

pub const APP_NAME: &str = "青丘湖网络工作台";
pub const APP_NAME_EN: &str = "Qingqiuhu Network Workbench";
pub const AUTHOR_NAME: &str = "Mr. Z";
pub const AUTHOR_EMAIL: &str = "mr.zed@qq.com";
pub const AUTHOR_QQ: &str = "40061980";
pub const AUTHOR_QQ_GROUP: &str = "292621190";
pub const WEBSITE_URL: &str = "https://www.qingqiuhu.net";
pub const REPO_URL: &str = "https://github.com/UncleNiu-QingqiuHu/network_diagnosis";
pub const COMMUNITY_URL: &str = "https://www.pheks.com/community/";
pub const COPYRIGHT: &str = "Copyright © 2025-2026 Mr. Z";
pub const LICENSE_NAME: &str = "MIT License";

/// 许可全文在编译期嵌入，运行期不依赖外部文件（避免打包漏带）。
pub const LICENSE_TEXT: &str = include_str!("../../LICENSE");

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleInfo {
    pub key: String,
    pub label: String,
    /// 侧栏图标语义名（wave / split / radar / chip / shield / info / doc）。
    /// 前端按名查图标注册表，未知名称回退默认图标，避免新增模块时导航空白。
    pub icon: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    pub version: String,
    pub platform: PlatformKind,
    pub platform_display: String,
    pub hostname: String,
    pub os_summary: String,
    pub elevated: bool,
    pub capabilities: CapabilitySet,
    pub modules: Vec<ModuleInfo>,
}

fn module(key: &str, label: &str, icon: &str) -> ModuleInfo {
    ModuleInfo {
        key: key.into(),
        label: label.into(),
        icon: icon.into(),
    }
}

/// 当前构建可用的模块清单。
///
/// v0.1 只登记已排期的 5 个模块（AI Agent 是常驻右栏，不占导航位）。
/// 后续每实现一个功能，在这里追加一行即可，前端自动出现。
fn available_modules(caps: &CapabilitySet) -> Vec<ModuleInfo> {
    let mut out = Vec::new();

    let push_if = |out: &mut Vec<ModuleInfo>, level: CapabilityLevel, key: &str, label: &str, icon: &str| {
        if level.is_usable() {
            out.push(module(key, label, icon));
        }
    };

    push_if(&mut out, caps.network_probe, "network", "网络诊断", "wave");
    push_if(&mut out, caps.network_probe, "trace", "路径追踪", "route");
    push_if(&mut out, caps.subnet, "subnet", "子网计算", "split");
    push_if(&mut out, caps.ip_scan, "ipScan", "IP 扫描", "radar");
    push_if(&mut out, caps.mac_scan, "macScan", "MAC 扫描", "chip");
    push_if(&mut out, caps.ssl_cert, "sslCert", "SSL 证书", "shield");

    // 关于与许可为纯信息页，与平台能力无关，恒定可用。
    out.push(module("about", "关于", "info"));
    out.push(module("license", "许可", "doc"));

    out
}

/// 「关于」页所需的静态信息 + 运行环境快照。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AboutInfo {
    pub name: String,
    pub name_en: String,
    pub version: String,
    pub platform_display: String,
    pub hostname: String,
    pub os_summary: String,
    pub elevated: bool,
    pub author: String,
    pub email: String,
    pub qq: String,
    pub qq_group: String,
    pub website: String,
    pub repository: String,
    pub community: String,
    pub copyright: String,
    pub license: String,
}

#[tauri::command]
pub fn about_info() -> AboutInfo {
    let h = host();
    AboutInfo {
        name: APP_NAME.into(),
        name_en: APP_NAME_EN.into(),
        version: qqhu_core::APP_VERSION.into(),
        platform_display: h.kind().display().into(),
        hostname: h.hostname(),
        os_summary: h.os_summary(),
        elevated: h.is_elevated(),
        author: AUTHOR_NAME.into(),
        email: AUTHOR_EMAIL.into(),
        qq: AUTHOR_QQ.into(),
        qq_group: AUTHOR_QQ_GROUP.into(),
        website: WEBSITE_URL.into(),
        repository: REPO_URL.into(),
        community: COMMUNITY_URL.into(),
        copyright: COPYRIGHT.into(),
        license: LICENSE_NAME.into(),
    }
}

#[tauri::command]
pub fn license_text() -> &'static str {
    LICENSE_TEXT
}

pub fn build_app_info() -> AppInfo {
    let h = host();
    let caps = h.capabilities();
    AppInfo {
        version: qqhu_core::APP_VERSION.to_string(),
        platform: h.kind(),
        platform_display: h.kind().display().to_string(),
        hostname: h.hostname(),
        os_summary: h.os_summary(),
        elevated: h.is_elevated(),
        modules: available_modules(&caps),
        capabilities: caps,
    }
}

#[tauri::command]
pub fn app_info() -> AppInfo {
    build_app_info()
}

/// 本机网络概况：接口列表 + 默认网关 + 推断出的建议网段。
///
/// 前端用它替换硬编码的 `192.168.1.0/24`：只有用户从未填过范围时才自动带入，
/// 填过就沿用本地记忆值。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalNetworkInfo {
    pub scope: Option<String>,
    pub gateway: Option<String>,
    pub interfaces: Vec<qqhu_sys::NetInterface>,
}

#[tauri::command]
pub fn local_network() -> LocalNetworkInfo {
    let h = host();
    let interfaces = h.interfaces();
    LocalNetworkInfo {
        scope: qqhu_sys::netif::suggest_scope(&interfaces),
        gateway: h.default_gateway().map(|g| g.to_string()),
        interfaces,
    }
}

/// 检查目标站点的 TLS 证书链。
#[tauri::command]
pub async fn ssl_check(
    input: String,
    timeout_ms: Option<u64>,
) -> Result<qqhu_core::SslCheckReport, String> {
    let opts = qqhu_probe::SslCheckOptions {
        timeout_ms: timeout_ms.unwrap_or(8000),
    };
    qqhu_probe::check_certificate(&input, opts).await
}

/// 事件名：路径追踪逐跳进度。
pub const TRACE_PROGRESS_EVENT: &str = "trace-progress";

/// 路径追踪（Traceroute）。逐跳把结果推给前端，最后返回完整报告。
#[tauri::command]
pub async fn trace_route(
    app: AppHandle,
    target: String,
    max_hops: Option<u8>,
    timeout_ms: Option<u64>,
) -> Result<qqhu_core::TraceReport, String> {
    let opts = qqhu_probe::TraceOptions {
        max_hops: max_hops.unwrap_or(30),
        timeout: Duration::from_millis(timeout_ms.unwrap_or(1200).clamp(200, 5000)),
        ..Default::default()
    };

    let handle = app.clone();
    qqhu_probe::trace_route(&target, &opts, move |p| {
        let _ = handle.emit(TRACE_PROGRESS_EVENT, &p);
    })
    .await
    .map_err(|e| e.to_string())
}

/// 路径 MTU 探测。
#[tauri::command]
pub async fn probe_mtu(target: String, timeout_ms: Option<u64>) -> Result<qqhu_core::MtuReport, String> {
    let opts = qqhu_probe::MtuOptions {
        timeout: Duration::from_millis(timeout_ms.unwrap_or(1200).clamp(200, 5000)),
        ..Default::default()
    };
    qqhu_probe::probe_path_mtu(&target, &opts)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn subnet_calc(
    ip: String,
    prefix: Option<u8>,
    netmask: Option<String>,
) -> Result<SubnetCalcResult, String> {
    calc_subnet(&ip, prefix, netmask.as_deref()).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn subnet_from_cidr(combo: String) -> Result<SubnetCalcResult, String> {
    calc_from_cidr_combo(&combo).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn subnet_subdivide(parent: String, child_prefix: u8, max_list: usize) -> Result<String, String> {
    subdivide_ipv4_equal_children(&parent, child_prefix, max_list).map_err(|e| e.to_string())
}

/// 事件名：诊断过程中的阶段文案。
pub const DIAG_PROGRESS_EVENT: &str = "diag-progress";

/// 一次诊断的完整产物：结构化结果 + 报告落盘路径 + 与上次的对比。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosisOutcome {
    pub report: DiagnosticReport,
    pub report_path: String,
    pub compare: Option<qqhu_report::HistoryCompare>,
}

/// 执行一次网络诊断并落盘 Markdown 报告。
///
/// 阶段文案通过 `diag-progress` 事件推送，前端据此更新进度条。
#[tauri::command]
pub async fn run_diagnosis(
    app: AppHandle,
    target: String,
    ports: Vec<u16>,
    enable_ping: bool,
    ping_count: u32,
    samples_per_port: u32,
) -> Result<DiagnosisOutcome, String> {
    let t = target.trim().to_string();
    if t.is_empty() {
        return Err("请填写诊断目标（域名或 IP）。".into());
    }

    let h = host();
    let report_base = crate::paths::report_root().join("diagnosis");
    let _ = std::fs::create_dir_all(&report_base);

    let opts = DiagOptions {
        target: t,
        ports,
        enable_ping,
        ping: PingOptions {
            count: ping_count.clamp(1, 20),
            ..Default::default()
        },
        tcp: TcpProbeOptions {
            samples: samples_per_port.clamp(1, 10),
            ..Default::default()
        },
    };

    let ctx = DiagContext {
        hostname: h.hostname(),
        os_summary: h.os_summary(),
        report_dir: report_base.clone(),
    };

    let emitter = app.clone();
    let on_progress = move |msg: &str| {
        let _ = emitter.emit(DIAG_PROGRESS_EVENT, msg.to_string());
    };

    let mut report = probe_run(&opts, &ctx, &on_progress)
        .await
        .map_err(|e| e.to_string())?;

    // ---- 报告落盘 + 历史索引（统一走 qqhu-report::persist）
    let artifacts = qqhu_report::persist(&mut report, &report_base).map_err(|e| e.to_string())?;

    Ok(DiagnosisOutcome {
        report,
        report_path: artifacts.report_path.to_string_lossy().to_string(),
        compare: artifacts.compare,
    })
}

/// AI Agent 通道。
/// 骨架阶段先把 IPC 打通、错误路径跑通；真正的 LLM 流式调用在 M4 接入
/// （复用旧版 OpenAI 兼容协议 + tool calling）。
#[tauri::command]
pub fn ai_chat(_message: String) -> Result<String, String> {
    Err("AI 通道尚未接入模型（计划 M4 实现，复用旧版 OpenAI 兼容协议）。".into())
}

// ------------------------------------------------------------------ IP 扫描

/// 事件名：扫描进度。
pub const IPSCAN_PROGRESS_EVENT: &str = "ipscan-progress";

/// 扫描的取消开关。
///
/// 放在 Tauri 托管状态里而不是命令参数：前端点「取消」时无法把句柄传回来，
/// 只能通过一次独立的命令置位。每次新扫描开始时重置。
#[derive(Default)]
pub struct ScanState {
    cancel: Arc<AtomicBool>,
}

impl ScanState {
    pub fn reset(&self) {
        self.cancel.store(false, Ordering::Relaxed);
    }

    pub fn request_cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    fn flag(&self) -> Arc<AtomicBool> {
        self.cancel.clone()
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpScanProgress {
    pub done: usize,
    pub total: usize,
    pub alive: usize,
    pub current: String,
}

/// 开始一次 IP 扫描。
///
/// 输入解析在 `qqhu_core::parse_scan_scope`（纯计算、有单测），
/// 实际探测在 `qqhu_probe::scan_scope`（并发 ICMP + 可选 TCP 兜底）。
#[tauri::command]
pub async fn ip_scan_start(
    app: AppHandle,
    state: State<'_, ScanState>,
    input: String,
    count: u32,
    timeout_ms: u64,
    concurrency: usize,
    tcp_ports: Vec<u16>,
) -> Result<IpScanReport, String> {
    let scope = parse_scan_scope(&input, MAX_SCAN_HOSTS).map_err(|e| e.to_string())?;

    state.reset();
    let cancel = state.flag();

    let opts = IpScanOptions {
        count: count.clamp(1, 5),
        timeout: Duration::from_millis(timeout_ms.clamp(100, 5000)),
        interval: Duration::from_millis(80),
        concurrency: concurrency.clamp(1, 256),
        tcp_fallback_ports: tcp_ports.into_iter().filter(|p| *p > 0).collect(),
        tcp_timeout: Duration::from_millis(timeout_ms.clamp(100, 5000)),
    };

    let emitter = app.clone();
    let on_progress = move |p: ScanProgress| {
        let _ = emitter.emit(
            IPSCAN_PROGRESS_EVENT,
            IpScanProgress {
                done: p.done,
                total: p.total,
                alive: p.alive,
                current: p.current,
            },
        );
    };

    scan_scope(&input, &scope, &opts, cancel, on_progress)
        .await
        .map_err(|e| e.to_string())
}

/// 请求取消当前扫描。命令本身立即返回，扫描任务在下一个检查点收尾。
#[tauri::command]
pub fn ip_scan_cancel(state: State<'_, ScanState>) {
    state.request_cancel();
}

/// 把扫描结果导出为 CSV，落在 `reports/ipscan/`，返回文件绝对路径。
///
/// 由后端写盘而不是前端调浏览器下载：Tauri 的 WebView 不支持 `<a download>`，
/// 且报告集中在便携目录里更符合这个工具的使用习惯。
#[tauri::command]
pub fn ip_scan_export_csv(report: IpScanReport) -> Result<String, String> {
    use std::io::Write;

    let dir = crate::paths::ipscan_dir();
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let path = dir.join(format!("ipscan-{stamp}.csv"));

    let file = std::fs::File::create(&path).map_err(|e| format!("创建 CSV 失败：{e}"))?;
    let mut w = std::io::BufWriter::new(file);

    // UTF-8 BOM：Excel 打开中文表头才不会乱码
    w.write_all(&[0xEF, 0xBB, 0xBF])
        .map_err(|e| format!("写入 CSV 失败：{e}"))?;

    writeln!(w, "IP,状态,判定方式,RTT(ms),丢包率(%),开放端口")
        .map_err(|e| format!("写入 CSV 失败：{e}"))?;

    for h in &report.hosts {
        writeln!(
            w,
            "{},{},{},{},{},{}",
            h.ip,
            if h.alive { "存活" } else { "无响应" },
            h.method.zh(),
            h.rtt_ms.map(|v| format!("{v:.1}")).unwrap_or_default(),
            format!("{:.1}", h.loss_percent),
            h.open_port.map(|p| p.to_string()).unwrap_or_default(),
        )
        .map_err(|e| format!("写入 CSV 失败：{e}"))?;
    }

    w.flush().map_err(|e| format!("写入 CSV 失败：{e}"))?;
    Ok(path.to_string_lossy().to_string())
}

// ------------------------------------------------------------------ MAC 扫描

/// 事件名：MAC 扫描进度。
pub const MACSCAN_PROGRESS_EVENT: &str = "macscan-progress";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacScanProgressPayload {
    pub message: String,
    pub done: usize,
    pub total: usize,
}

/// 构造 OUI 厂商库。
///
/// 内置库只收录确信的前缀；用户把 IEEE 的 `oui.csv` 放到 `config/oui.csv`
/// 即可补齐全量数据，外部条目优先。每次扫描都重新读文件，
/// 好处是放进去的库立即生效，不必重启应用。
fn oui_db() -> OuiDb {
    let mut db = OuiDb::builtin();
    let path = crate::paths::config_dir().join("oui.csv");
    if let Ok(text) = std::fs::read_to_string(&path) {
        let (extra, n) = OuiDb::from_csv(&text);
        if n > 0 {
            tracing::info!("已从 {} 加载 {n} 条 OUI 记录", path.display());
            db.extend(extra);
        }
    }
    db
}

/// 执行一次 MAC 扫描。
///
/// `probe_input` 为空表示只读 ARP 表；填写网段则先主动探活再读表。
#[tauri::command]
pub async fn mac_scan_run(
    app: AppHandle,
    state: State<'_, ScanState>,
    probe_input: Option<String>,
    concurrency: usize,
    timeout_ms: u64,
) -> Result<MacScanReport, String> {
    let probe = probe_input.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());

    let probe_scope = match &probe {
        Some(input) => Some(parse_scan_scope(input, MAX_SCAN_HOSTS).map_err(|e| e.to_string())?),
        None => None,
    };

    state.reset();
    let cancel = state.flag();

    let timeout = Duration::from_millis(timeout_ms.clamp(100, 5000));
    let opts = MacScanOptions {
        probe_scope,
        probe_input: probe.unwrap_or_default(),
        ip_scan: IpScanOptions {
            count: 1,
            timeout,
            interval: Duration::from_millis(80),
            concurrency: concurrency.clamp(1, 256),
            tcp_fallback_ports: Vec::new(),
            tcp_timeout: timeout,
        },
    };

    let emitter = app.clone();
    let on_progress = move |p: MacScanProgress| {
        let _ = emitter.emit(
            MACSCAN_PROGRESS_EVENT,
            MacScanProgressPayload {
                message: p.message,
                done: p.done,
                total: p.total,
            },
        );
    };

    run_mac_scan(&opts, &oui_db(), cancel, on_progress).await
}

/// 把 MAC 扫描结果导出为 CSV。
#[tauri::command]
pub fn mac_scan_export_csv(report: MacScanReport) -> Result<String, String> {
    use std::io::Write;

    let dir = crate::paths::macscan_dir();
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let path = dir.join(format!("macscan-{stamp}.csv"));

    let file = std::fs::File::create(&path).map_err(|e| format!("创建 CSV 失败：{e}"))?;
    let mut w = std::io::BufWriter::new(file);
    w.write_all(&[0xEF, 0xBB, 0xBF])
        .map_err(|e| format!("写入 CSV 失败：{e}"))?;

    writeln!(w, "IP,MAC,厂商,OUI,接口,状态,在线").map_err(|e| format!("写入 CSV 失败：{e}"))?;

    for e in &report.entries {
        writeln!(
            w,
            "{},{},{},{},{},{},{}",
            e.ip,
            e.mac,
            e.vendor,
            OuiDb::oui_prefix(&e.mac).unwrap_or_default(),
            e.interface,
            e.state.zh(),
            match e.alive {
                Some(true) => "在线",
                Some(false) => "离线",
                None => "",
            }
        )
        .map_err(|e| format!("写入 CSV 失败：{e}"))?;
    }

    w.flush().map_err(|e| format!("写入 CSV 失败：{e}"))?;
    Ok(path.to_string_lossy().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modules_follow_capabilities() {
        let info = build_app_info();
        let keys: Vec<&str> = info.modules.iter().map(|m| m.key.as_str()).collect();
        assert!(keys.contains(&"subnet"), "子网计算必须始终可用");
        assert!(keys.contains(&"about"), "关于页恒定可用");
        assert!(keys.contains(&"license"), "许可页恒定可用");
        assert!(!keys.contains(&"aiChat"), "AI 是常驻侧栏，不应出现在导航");
    }

    /// 每个导航项都必须带图标语义名 —— 新增模块若忘写，侧栏会出现空白图标位。
    #[test]
    fn every_module_has_icon() {
        let info = build_app_info();
        for m in &info.modules {
            assert!(!m.icon.is_empty(), "模块 {} 缺少图标名", m.key);
            assert!(
                m.icon.chars().all(|c| c.is_ascii_lowercase()),
                "图标名 {} 应为小写语义名（前端按名查表）",
                m.icon
            );
        }
    }

    #[test]
    fn license_text_is_embedded() {
        assert!(LICENSE_TEXT.contains("MIT License"));
        assert!(LICENSE_TEXT.contains("Mr. Z"));
        assert!(!LICENSE_TEXT.contains("[year]"), "许可占位符必须已替换");
    }

    #[test]
    fn app_info_serializes_camel_case() {
        let json = serde_json::to_string(&build_app_info()).unwrap();
        assert!(json.contains("\"platformDisplay\""));
        assert!(json.contains("\"osSummary\""));
    }

    /// CSV 导出：BOM、表头、存活与无响应两种行的格式都要稳定。
    #[test]
    fn csv_export_writes_bom_and_rows() {
        use qqhu_core::{IpScanHost, IpScanParams, ProbeMethod};

        let report = IpScanReport {
            input: "127.0.0.1-127.0.0.2".into(),
            scope_desc: "127.0.0.1 - 127.0.0.2 · 2 个地址".into(),
            started_at: "2026-11-03 16:00:00".into(),
            duration_ms: 123,
            total: 2,
            alive_count: 1,
            hosts: vec![
                IpScanHost {
                    ip: "127.0.0.1".into(),
                    alive: true,
                    method: ProbeMethod::Icmp,
                    rtt_ms: Some(0.4),
                    loss_percent: 0.0,
                    open_port: None,
                },
                IpScanHost {
                    ip: "127.0.0.2".into(),
                    alive: false,
                    method: ProbeMethod::None,
                    rtt_ms: None,
                    loss_percent: 100.0,
                    open_port: None,
                },
            ],
            cancelled: false,
            params: IpScanParams {
                count: 1,
                timeout_ms: 800,
                concurrency: 64,
                tcp_fallback_ports: vec![],
            },
            warnings: vec![],
        };

        let path = ip_scan_export_csv(report).expect("导出应成功");
        let bytes = std::fs::read(&path).expect("应能读回 CSV");

        assert_eq!(&bytes[..3], &[0xEF, 0xBB, 0xBF], "必须带 UTF-8 BOM，否则 Excel 中文乱码");

        let text = String::from_utf8_lossy(&bytes[3..]).to_string();
        let mut lines = text.lines();
        assert_eq!(
            lines.next().unwrap(),
            "IP,状态,判定方式,RTT(ms),丢包率(%),开放端口"
        );
        assert_eq!(lines.next().unwrap(), "127.0.0.1,存活,ICMP,0.4,0.0,");
        assert_eq!(lines.next().unwrap(), "127.0.0.2,无响应,无响应,,100.0,");

        let _ = std::fs::remove_file(&path);
    }

    /// MAC 扫描 CSV：厂商未知时留空、OUI 单独成列、在线状态三态化。
    #[test]
    fn mac_csv_export_rows() {
        use qqhu_core::{ArpEntry, ArpState};

        let report = MacScanReport {
            collected_at: "2026-11-03 16:47:06".into(),
            raw_count: 2,
            entries: vec![
                ArpEntry {
                    ip: "192.168.60.62".into(),
                    mac: "aa:bb:cc:dd:ee:ff".into(),
                    vendor: "Cisco".into(),
                    interface: "以太网".into(),
                    state: ArpState::Reachable,
                    randomized: false,
                    alive: Some(true),
                },
                ArpEntry {
                    ip: "192.168.60.63".into(),
                    mac: "02:11:22:33:44:55".into(),
                    vendor: String::new(),
                    interface: String::new(),
                    state: ArpState::Stale,
                    randomized: true,
                    alive: None,
                },
            ],
            probed: 30,
            probed_alive: 13,
            warnings: vec![],
        };

        let path = mac_scan_export_csv(report).expect("导出应成功");
        let bytes = std::fs::read(&path).expect("应能读回");
        assert_eq!(&bytes[..3], &[0xEF, 0xBB, 0xBF], "必须带 UTF-8 BOM");

        let text = String::from_utf8_lossy(&bytes[3..]).to_string();
        let mut lines = text.lines();
        assert_eq!(lines.next().unwrap(), "IP,MAC,厂商,OUI,接口,状态,在线");
        assert_eq!(
            lines.next().unwrap(),
            "192.168.60.62,aa:bb:cc:dd:ee:ff,Cisco,AABBCC,以太网,可达,在线"
        );
        // 厂商未知留空；未探测时在线列留空
        assert_eq!(
            lines.next().unwrap(),
            "192.168.60.63,02:11:22:33:44:55,,021122,,陈旧,"
        );

        let _ = std::fs::remove_file(&path);
    }
}
