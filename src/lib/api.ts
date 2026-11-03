import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type {
  AboutInfo,
  AppInfo,
  DiagnosisOutcome,
  IpScanProgress,
  IpScanReport,
  IpScanRequest,
  MacScanProgress,
  MacScanReport,
  MacScanRequest,
  SubnetCalcResult,
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
