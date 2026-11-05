import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type {
  AboutInfo,
  AcmeCertMeta,
  AcmeCertText,
  AcmeIssueSpec,
  AcmeOverview,
  AcmeProgress,
  AppInfo,
  DiagnosisOutcome,
  IpScanProgress,
  IpScanReport,
  IpScanRequest,
  LocalNetworkInfo,
  MacScanProgress,
  MacScanReport,
  MacScanRequest,
  CaMeta,
  CaSpec,
  CertMeta,
  CertSpec,
  CertText,
  MtuReport,
  PkiOverview,
  SslCheckReport,
  SubnetCalcResult,
  TraceProgress,
  TraceReport,
} from "./types";

/** 是否运行在 Tauri 容器内。浏览器直接 `pnpm dev` 时为 false。 */
export const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

const BROWSER_INFO: AppInfo = {
  version: __APP_VERSION__,
  platform: "windows",
  platformDisplay: "Windows",
  hostname: "browser-preview",
  osSummary: "浏览器预览模式（未连接 Rust 后端）",
  elevated: false,
  capabilities: {
    platform: "windows",
    networkProbe: "full",
    subnet: "full",
    ipScan: "full",
    macScan: "full",
    dhcp: "full",
    switchConsole: "full",
    database: "full",
    packetCapture: "full",
    arpMonitor: "full",
    securityBaseline: "full",
    domain: "full",
    codeSigning: "full",
    sslCert: "full",
    aiAssistant: "full",
    notes: [],
  },
  modules: [
    { key: "network", label: "网络诊断", icon: "wave" },
    { key: "subnet", label: "子网计算", icon: "split" },
    { key: "ipScan", label: "IP 扫描", icon: "radar" },
    { key: "macScan", label: "MAC 扫描", icon: "chip" },
    { key: "sslCert", label: "SSL 证书", icon: "shield" },
    { key: "about", label: "关于", icon: "info" },
    { key: "license", label: "许可", icon: "doc" },
  ],
};

export async function appInfo(): Promise<AppInfo> {
  if (!isTauri) {
    console.warn("[qqhu] 浏览器预览模式：Rust 后端未连接，接口返回占位数据。");
    return BROWSER_INFO;
  }
  return invoke<AppInfo>("app_info");
}

/** 本机接口与建议扫描范围。浏览器预览下返回空结果，不抛错。 */
export async function localNetwork(): Promise<LocalNetworkInfo> {
  if (!isTauri) return { scope: null, gateway: null, interfaces: [] };
  return invoke<LocalNetworkInfo>("local_network");
}

/** 检查目标站点的 TLS 证书。 */
export async function sslCheck(input: string, timeoutMs = 8000): Promise<SslCheckReport> {
  if (!isTauri) throw new Error("证书检查需要 Rust 后端，请在 Tauri 窗口中运行。");
  return invoke<SslCheckReport>("ssl_check", { input, timeoutMs });
}

export async function subnetCalc(
  ip: string,
  prefix: number | null,
  netmask: string | null,
): Promise<SubnetCalcResult> {
  if (!isTauri) throw new Error("子网计算需要 Rust 后端，请在 Tauri 窗口中运行。");
  return invoke<SubnetCalcResult>("subnet_calc", { ip, prefix, netmask });
}

export async function subnetFromCidr(combo: string): Promise<SubnetCalcResult> {
  if (!isTauri) throw new Error("子网计算需要 Rust 后端，请在 Tauri 窗口中运行。");
  return invoke<SubnetCalcResult>("subnet_from_cidr", { combo });
}

export async function subnetSubdivide(
  parent: string,
  childPrefix: number,
  maxList = 64,
): Promise<string> {
  if (!isTauri) throw new Error("子网划分需要 Rust 后端，请在 Tauri 窗口中运行。");
  return invoke<string>("subnet_subdivide", { parent, childPrefix, maxList });
}

export async function aiChat(message: string): Promise<string> {
  if (!isTauri) throw new Error("AI 通道需要 Rust 后端。");
  return invoke<string>("ai_chat", { message });
}

export async function aboutInfo(): Promise<AboutInfo> {
  if (!isTauri) throw new Error("关于信息需要 Rust 后端。");
  return invoke<AboutInfo>("about_info");
}

export async function licenseText(): Promise<string> {
  if (!isTauri) throw new Error("许可全文需要 Rust 后端。");
  return invoke<string>("license_text");
}

// ---------------------------------------------------------------- 网络诊断

export interface DiagnosisRequest {
  target: string;
  ports: number[];
  enablePing: boolean;
  pingCount: number;
  samplesPerPort: number;
}

export async function runDiagnosis(req: DiagnosisRequest): Promise<DiagnosisOutcome> {
  if (!isTauri) throw new Error("网络诊断需要 Rust 后端，请在 Tauri 窗口中运行。");
  return invoke<DiagnosisOutcome>("run_diagnosis", {
    target: req.target,
    ports: req.ports,
    enablePing: req.enablePing,
    pingCount: req.pingCount,
    samplesPerPort: req.samplesPerPort,
  });
}

/** 订阅诊断阶段文案，返回取消订阅函数。 */
export async function onDiagnosisProgress(handler: (msg: string) => void): Promise<() => void> {
  if (!isTauri) return () => undefined;
  return listen<string>("diag-progress", (e) => handler(e.payload));
}

// ---------------------------------------------------------------- IP 扫描

export async function startIpScan(req: IpScanRequest): Promise<IpScanReport> {
  if (!isTauri) throw new Error("IP 扫描需要 Rust 后端，请在 Tauri 窗口中运行。");
  return invoke<IpScanReport>("ip_scan_start", {
    input: req.input,
    count: req.count,
    timeoutMs: req.timeoutMs,
    concurrency: req.concurrency,
    tcpPorts: req.tcpPorts,
  });
}

/**
 * 取消当前正在进行的扫描。
 *
 * IP 扫描与 MAC 扫描共用后端的同一个取消开关（两者都是长任务，
 * 同时只可能有一个在跑），所以这里是一个通用入口而不是按模块命名。
 */
export async function cancelScan(): Promise<void> {
  if (!isTauri) return;
  await invoke("ip_scan_cancel");
}

/** 后端写 CSV 到 reports/ipscan/，返回文件绝对路径。 */
export async function exportIpScanCsv(report: IpScanReport): Promise<string> {
  if (!isTauri) throw new Error("导出需要 Rust 后端。");
  return invoke<string>("ip_scan_export_csv", { report });
}

/** 订阅扫描进度，返回取消订阅函数。 */
export async function onIpScanProgress(
  handler: (p: IpScanProgress) => void,
): Promise<() => void> {
  if (!isTauri) return () => undefined;
  return listen<IpScanProgress>("ipscan-progress", (e) => handler(e.payload));
}

// ---------------------------------------------------------------- MAC 扫描

export async function runMacScan(req: MacScanRequest): Promise<MacScanReport> {
  if (!isTauri) throw new Error("MAC 扫描需要 Rust 后端，请在 Tauri 窗口中运行。");
  return invoke<MacScanReport>("mac_scan_run", {
    probeInput: req.probeInput,
    concurrency: req.concurrency,
    timeoutMs: req.timeoutMs,
  });
}

export async function exportMacScanCsv(report: MacScanReport): Promise<string> {
  if (!isTauri) throw new Error("导出需要 Rust 后端。");
  return invoke<string>("mac_scan_export_csv", { report });
}

/** 订阅 MAC 扫描进度，返回取消订阅函数。 */
export async function onMacScanProgress(
  handler: (p: MacScanProgress) => void,
): Promise<() => void> {
  if (!isTauri) return () => undefined;
  return listen<MacScanProgress>("macscan-progress", (e) => handler(e.payload));
}

/** 路径追踪：逐跳结果通过事件推送，最终返回完整报告。 */
export async function traceRoute(
  target: string,
  maxHops = 30,
  timeoutMs = 1200,
): Promise<TraceReport> {
  if (!isTauri) throw new Error("路径追踪需要 Rust 后端，请在 Tauri 窗口中运行。");
  return invoke<TraceReport>("trace_route", { target, maxHops, timeoutMs });
}

/** 订阅逐跳进度，返回取消订阅函数。 */
export async function onTraceProgress(
  handler: (p: TraceProgress) => void,
): Promise<() => void> {
  if (!isTauri) return () => undefined;
  return listen<TraceProgress>("trace-progress", (e) => handler(e.payload));
}

/** 路径 MTU 探测。 */
export async function probeMtu(target: string, timeoutMs = 1200): Promise<MtuReport> {
  if (!isTauri) throw new Error("MTU 探测需要 Rust 后端，请在 Tauri 窗口中运行。");
  return invoke<MtuReport>("probe_mtu", { target, timeoutMs });
}

// ---------------------------------------------------------------- 私有 CA

export async function pkiOverview(): Promise<PkiOverview> {
  if (!isTauri) throw new Error("证书签发需要 Rust 后端，请在 Tauri 窗口中运行。");
  return invoke<PkiOverview>("pki_overview");
}

export async function pkiCreateCa(spec: CaSpec): Promise<CaMeta> {
  if (!isTauri) throw new Error("证书签发需要 Rust 后端。");
  return invoke<CaMeta>("pki_create_ca", { spec });
}

export async function pkiDeleteCa(id: string): Promise<void> {
  if (!isTauri) throw new Error("证书签发需要 Rust 后端。");
  return invoke<void>("pki_delete_ca", { id });
}

export async function pkiIssue(spec: CertSpec): Promise<CertMeta> {
  if (!isTauri) throw new Error("证书签发需要 Rust 后端。");
  return invoke<CertMeta>("pki_issue", { spec });
}

export async function pkiDeleteCert(id: string): Promise<void> {
  if (!isTauri) throw new Error("证书签发需要 Rust 后端。");
  return invoke<void>("pki_delete_cert", { id });
}

/** 导出 PKCS#12，返回落盘路径。 */
export async function pkiExportPfx(id: string, password: string): Promise<string> {
  if (!isTauri) throw new Error("证书签发需要 Rust 后端。");
  return invoke<string>("pki_export_pfx", { id, password });
}

export async function pkiCertText(id: string): Promise<CertText> {
  if (!isTauri) throw new Error("证书签发需要 Rust 后端。");
  return invoke<CertText>("pki_cert_text", { id });
}

/** 返回目录路径（kind 为 ca / cert）。 */
export async function pkiDirOf(id: string, kind: "ca" | "cert"): Promise<string> {
  if (!isTauri) throw new Error("证书签发需要 Rust 后端。");
  return invoke<string>("pki_dir_of", { id, kind });
}

// ---------------------------------------------------------------- ACME

export async function acmeOverview(): Promise<AcmeOverview> {
  if (!isTauri) throw new Error("ACME 签发需要 Rust 后端，请在 Tauri 窗口中运行。");
  return invoke<AcmeOverview>("acme_overview");
}

/** 申请证书：耗时较长，进度通过 acme-progress 事件推送。 */
export async function acmeIssue(spec: AcmeIssueSpec): Promise<AcmeCertMeta> {
  if (!isTauri) throw new Error("ACME 签发需要 Rust 后端。");
  return invoke<AcmeCertMeta>("acme_issue", { spec });
}

/** 订阅签发进度，返回取消订阅函数。 */
export async function onAcmeProgress(
  handler: (p: AcmeProgress) => void,
): Promise<() => void> {
  if (!isTauri) return () => undefined;
  return listen<AcmeProgress>("acme-progress", (e) => handler(e.payload));
}

export async function acmeCertText(id: string): Promise<AcmeCertText> {
  if (!isTauri) throw new Error("ACME 签发需要 Rust 后端。");
  return invoke<AcmeCertText>("acme_cert_text", { id });
}

export async function acmeDeleteCert(id: string): Promise<void> {
  if (!isTauri) throw new Error("ACME 签发需要 Rust 后端。");
  return invoke<void>("acme_delete_cert", { id });
}

export async function acmeExportPfx(id: string, password: string): Promise<string> {
  if (!isTauri) throw new Error("ACME 签发需要 Rust 后端。");
  return invoke<string>("acme_export_pfx", { id, password });
}

export async function acmeDirOf(id: string): Promise<string> {
  if (!isTauri) throw new Error("ACME 签发需要 Rust 后端。");
  return invoke<string>("acme_dir_of", { id });
}
