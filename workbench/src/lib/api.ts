import { invoke } from "@tauri-apps/api/core";
import type { AppInfo, SubnetCalcResult } from "./types";

/** 是否运行在 Tauri 容器内。浏览器直接 `pnpm dev` 时为 false。 */
export const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

const BROWSER_INFO: AppInfo = {
  version: "4.0.0-dev",
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
    { key: "network", label: "网络诊断", group: "core" },
    { key: "subnet", label: "子网计算", group: "core" },
    { key: "ipScan", label: "IP 扫描", group: "net" },
    { key: "macScan", label: "MAC 扫描", group: "net" },
    { key: "sslCert", label: "SSL 证书", group: "tool" },
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
