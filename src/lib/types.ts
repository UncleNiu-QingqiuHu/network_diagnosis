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

export interface AboutInfo {
  name: string;
  nameEn: string;
  version: string;
  platformDisplay: string;
  hostname: string;
  osSummary: string;
  elevated: boolean;
  author: string;
  email: string;
  qq: string;
  qqGroup: string;
  website: string;
  repository: string;
  community: string;
  copyright: string;
  license: string;
}

// ---------------------------------------------------------------- 网络诊断

export type OverallStatus = "ok" | "degraded" | "failed";
export type PortFailureClass = "ok" | "timeout" | "refused" | "unreachable" | "error" | "unknown";
export type Grade = "excellent" | "normal" | "poor" | "congested" | "unknown";

export interface DegradationEvent {
  code: string;
  message: string;
  detail: string;
}

export interface DnsAnswer {
  family: string;
  addresses: string[];
  elapsedMs: number;
  error: string | null;
}

export interface PingSample {
  seq: number;
  rttMs: number | null;
  ttl: number | null;
}

export interface PingStats {
  target: string;
  attempted: number;
  received: number;
  lost: number;
  rttsMs: number[];
  minMs: number | null;
  maxMs: number | null;
  avgMs: number | null;
  samples: PingSample[];
  rawStdout: string;
}

export interface PortSample {
  success: boolean;
  rttMs: number | null;
  failure: PortFailureClass;
  detail: string;
}

export interface PortProbeResult {
  port: number;
  samples: PortSample[];
  failureClass: PortFailureClass;
  successCount: number;
  successRate: number;
}

export interface NetworkQualityAssessment {
  grade: Grade;
  lossPct: number | null;
  avgLatencyMs: number | null;
  jitterMs: number | null;
  throughputNote: string;
  metricLines: string[];
}

export interface GuiSummary {
  headline: string;
  overall: OverallStatus;
  grade: Grade;
  bullets: string[];
  actions: string[];
}

export interface TaskMeta {
  taskId: string;
  startedAt: string;
  finishedAt: string | null;
  appVersion: string;
  hostname: string;
  osSummary: string;
  reportDir: string;
}

export interface DiagnosticReport {
  meta: TaskMeta;
  input: Record<string, unknown>;
  dns: DnsAnswer | null;
  ping: PingStats | null;
  ports: PortProbeResult[];
  traceroute: unknown | null;
  mtu: unknown | null;
  httpTls: unknown | null;
  bandwidth: unknown | null;
  iperfUdp: unknown | null;
  quality: NetworkQualityAssessment | null;
  degradations: DegradationEvent[];
  overall: OverallStatus;
  summary: GuiSummary | null;
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
