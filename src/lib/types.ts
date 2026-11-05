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
  /** 侧栏图标语义名，未知值前端回退默认图标 */
  icon: string;
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

export interface HistoryCompare {
  previousFinishedAt: string;
  previousGrade: Grade;
  currentGrade: Grade;
  lossDelta: number | null;
  latencyDeltaMs: number | null;
  jitterDeltaMs: number | null;
  summary: string;
}

export interface DiagnosisOutcome {
  report: DiagnosticReport;
  reportPath: string;
  compare: HistoryCompare | null;
}

export interface DiagnosticReport {  meta: TaskMeta;
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

// ---------------------------------------------------------------- IP 扫描

export type ScanScopeKind = "cidr" | "range" | "single";
export type ProbeMethod = "icmp" | "tcp" | "none";

export interface IpScanHost {
  ip: string;
  alive: boolean;
  method: ProbeMethod;
  rttMs: number | null;
  lossPercent: number;
  openPort: number | null;
}

export interface IpScanParams {
  count: number;
  timeoutMs: number;
  concurrency: number;
  tcpFallbackPorts: number[];
}

export interface IpScanReport {
  input: string;
  scopeDesc: string;
  startedAt: string;
  durationMs: number;
  total: number;
  aliveCount: number;
  hosts: IpScanHost[];
  cancelled: boolean;
  params: IpScanParams;
  warnings: string[];
}

export interface IpScanProgress {
  done: number;
  total: number;
  alive: number;
  current: string;
}

export interface IpScanRequest {
  input: string;
  count: number;
  timeoutMs: number;
  concurrency: number;
  tcpPorts: number[];
}

// ---------------------------------------------------------------- MAC 扫描

export type ArpState = "reachable" | "stale" | "permanent" | "incomplete" | "other";

export interface ArpEntry {
  ip: string;
  mac: string;
  /** OUI 厂商；未命中为空串 */
  vendor: string;
  /** 接口友好名 */
  interface: string;
  state: ArpState;
  /** 本地管理地址（手机随机化 MAC 的典型特征） */
  randomized: boolean;
  /** 主动探测结果；null 表示本次未探测 */
  alive: boolean | null;
}

export interface MacScanReport {
  collectedAt: string;
  rawCount: number;
  entries: ArpEntry[];
  probed: number;
  probedAlive: number;
  warnings: string[];
}

export interface MacScanProgress {
  message: string;
  done: number;
  total: number;
}

export interface MacScanRequest {
  probeInput: string | null;
  concurrency: number;
  timeoutMs: number;
}

/** 本机一个 IPv4 接口。 */
export interface NetInterface {
  name: string;
  description: string;
  ip: string;
  /** 前缀长度（掩码中 1 的个数） */
  prefixLen: number;
  mac: string | null;
  isUp: boolean;
  isLoopback: boolean;
  hasGateway: boolean;
}

/** 本机网络概况：用于自动填入扫描范围，替代硬编码网段。 */
export interface LocalNetworkInfo {
  /** 推断出的建议扫描范围，如 `192.168.60.0/24`；无可用接口时为 null */
  scope: string | null;
  gateway: string | null;
  interfaces: NetInterface[];
}

/** 证书有效期状态 */
export type CertStatus = "valid" | "expiringSoon" | "expired" | "notYetValid";

export interface CertInfo {
  subject: string;
  issuer: string;
  commonName: string | null;
  serial: string;
  notBefore: string;
  notAfter: string;
  status: CertStatus;
  /** 距到期天数，已过期为负 */
  daysRemaining: number;
  sans: string[];
  signatureAlgorithm: string;
  keyAlgorithm: string;
  keyBits: number | null;
  isCa: boolean;
  selfSigned: boolean;
  sha256Fingerprint: string;
  /** 是否为服务器证书（链上第一张） */
  isLeaf: boolean;
}

export interface SslCheckReport {
  host: string;
  port: number;
  checkedAt: string;
  remoteIp: string;
  tlsVersion: string;
  cipherSuite: string;
  chain: CertInfo[];
  hostnameMatched: boolean;
  /** 系统根证书校验是否通过 */
  trusted: boolean;
  trustError: string | null;
  durationMs: number;
  warnings: string[];
}



/** 路径追踪单跳 */
export interface TraceHop {
  ttl: number;
  /** 全超时为 null */
  addr: string | null;
  rttMs: number | null;
  reached: boolean;
  note: string | null;
}

export interface TraceReport {
  target: string;
  resolvedIp: string;
  hops: TraceHop[];
  /** 是否到达目标（否则被跳数限制或提前收尾） */
  completed: boolean;
  cancelled: boolean;
  durationMs: number;
  warnings: string[];
}

export interface TraceProgress {
  hop: TraceHop;
  done: number;
  total: number;
}

export interface MtuProbe {
  /** 本次探测的 MTU 候选值 */
  mtu: number;
  passed: boolean;
  /** 路由器回报的下一跳 MTU */
  nextHopMtu: number | null;
  rttMs: number | null;
  /** ok / too-big / too-big-local / unreachable / timeout / send-error */
  outcome: string;
}

export interface MtuReport {
  target: string;
  resolvedIp: string;
  pathMtu: number;
  probes: MtuProbe[];
  /** 有探测超时，结论可能受丢包影响 */
  uncertain: boolean;
  durationMs: number;
  warnings: string[];
  /** 一句话结论（后端生成） */
  summary: string;
}

// ---------------------------------------------------------------- 私有 CA

export type KeyAlgorithm = "ecdsaP256" | "ed25519";
export type CertUsage = "server" | "client" | "both";

export interface CaSpec {
  commonName: string;
  organization?: string | null;
  organizationalUnit?: string | null;
  country?: string | null;
  state?: string | null;
  locality?: string | null;
  validityDays?: number | null;
  keyAlgorithm?: KeyAlgorithm;
}

export interface CaMeta {
  id: string;
  commonName: string;
  /** 完整 DN，取自证书本身 */
  subject: string;
  serial: string;
  fingerprint: string;
  keyAlgorithm: string;
  createdAt: string;
  notBefore: string;
  notAfter: string;
  daysRemaining: number;
  /** 该 CA 已签发证书数 */
  issuedCount: number;
}

export interface CertSpec {
  caId: string;
  commonName: string;
  sans: string[];
  validityDays?: number | null;
  keyAlgorithm?: KeyAlgorithm;
  usage?: CertUsage;
}

export interface CertMeta {
  id: string;
  caId: string;
  commonName: string;
  sans: string[];
  serial: string;
  fingerprint: string;
  keyAlgorithm: string;
  usage: string;
  createdAt: string;
  notBefore: string;
  notAfter: string;
  daysRemaining: number;
}

export interface PkiOverview {
  cas: CaMeta[];
  certs: CertMeta[];
  /** 私钥以明文 PEM 存放的根目录 */
  rootDir: string;
}

export interface CertText {
  certPem: string;
  chainPem: string;
  dir: string;
}
