/**
 * 与 Rust 侧 serde 契约一一对应。
 * 修改任何一侧都必须同步这里；后续可用 ts-rs 自动导出，避免手工漂移。
 */

export type PlatformKind = "windows" | "macOs" | "linux";
export type CapabilityLevel = "full" | "partial" | "unavailable";

export interface ModuleNote {
  module: string;
  reason: string;
}

export interface CapabilitySet {
  platform: PlatformKind;
  networkProbe: CapabilityLevel;
  subnet: CapabilityLevel;
  ipScan: CapabilityLevel;
  macScan: CapabilityLevel;
  dhcp: CapabilityLevel;
  switchConsole: CapabilityLevel;
  database: CapabilityLevel;
  packetCapture: CapabilityLevel;
  arpMonitor: CapabilityLevel;
  securityBaseline: CapabilityLevel;
  domain: CapabilityLevel;
  codeSigning: CapabilityLevel;
  sslCert: CapabilityLevel;
  aiAssistant: CapabilityLevel;
  notes: ModuleNote[];
}

export interface ModuleInfo {
  key: string;
  label: string;
  group: "core" | "net" | "tool" | string;
}

export interface AppInfo {
  version: string;
  platform: PlatformKind;
  platformDisplay: string;
  hostname: string;
  osSummary: string;
  elevated: boolean;
  capabilities: CapabilitySet;
  modules: ModuleInfo[];
}

export interface SubnetCalcResult {
  inputInterface: string;
  networkCidr: string;
  networkAddress: string;
  broadcastAddress: string;
  netmask: string;
  wildcardMask: string;
  prefixLen: number;
  totalAddresses: number;
  usableHosts: number;
  firstHost: string;
  lastHost: string;
  scopeNote: string;
  hostRoleNote: string;
}
