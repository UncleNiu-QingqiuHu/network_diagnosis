"""结构化诊断结果模型：GUI 与 Markdown 同源。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path


class OverallStatus(str, Enum):
    OK = "ok"
    DEGRADED = "degraded"
    FAILED = "failed"


class PortFailureClass(str, Enum):
    OK = "ok"
    TIMEOUT = "timeout"
    REFUSED = "refused"
    UNREACHABLE = "unreachable"
    ERROR = "error"
    UNKNOWN = "unknown"


@dataclass
class DegradationEvent:
    """抓包或依赖缺失等降级事件。"""

    code: str
    message: str
    detail: str = ""


@dataclass
class TaskMeta:
    task_id: str
    started_at: datetime
    finished_at: datetime | None
    app_version: str
    design_doc_ref: str
    hostname: str
    os_summary: str
    tcping_path: str | None
    tcping_version_line: str | None
    tshark_path: str | None
    tshark_version_line: str | None
    report_dir: Path


@dataclass
class UserInputSnapshot:
    target_host: str
    ports: list[int]
    samples_per_port: int
    tcp_connect_timeout_ms: int
    enable_ping: bool
    enable_capture: bool
    prefer_ipv6: bool
    ping_count: int = 10
    ping_long: bool = False
    long_ping_seconds: int = 30
    ping_packet_timeout_ms: int = 2000


@dataclass
class AdapterInfo:
    name: str
    description: str
    enabled: bool
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    gateways: list[str] = field(default_factory=list)
    dns_servers: list[str] = field(default_factory=list)


@dataclass
class LocalContext:
    note: str
    adapters: list[AdapterInfo]
    raw_ipconfig_path: Path | None


@dataclass
class DnsAnswer:
    family: str
    addresses: list[str]
    elapsed_ms: float
    error: str | None


@dataclass
class PingSample:
    rtt_ms: float | None
    ttl: int | None
    line: str


@dataclass
class PingStats:
    attempted: int
    received: int
    lost: int
    rtts_ms: list[float]
    raw_stdout_path: Path
    raw_stderr_path: Path
    command: list[str]


@dataclass
class TcpingSample:
    success: bool
    rtt_ms: float | None
    raw_line: str


@dataclass
class PortProbeResult:
    port: int
    target_used: str
    samples: list[TcpingSample]
    stdout_path: Path
    stderr_path: Path
    command: list[str]
    failure_class: PortFailureClass = PortFailureClass.UNKNOWN


@dataclass
class CaptureInfo:
    requested: bool
    ran: bool
    tshark_cmd: list[str] | None
    pcap_path: Path | None
    stdout_path: Path | None
    stderr_path: Path | None
    notes: str = ""
    analysis_summary: str = ""


@dataclass
class GuiSummary:
    overall: OverallStatus
    headline: str
    bullets: list[str]
    markdown_path: Path


@dataclass
class DiagnosticReport:
    meta: TaskMeta
    user_input: UserInputSnapshot
    local: LocalContext
    dns: DnsAnswer
    ping: PingStats | None
    ports: list[PortProbeResult]
    capture: CaptureInfo
    degradations: list[DegradationEvent]
    gui: GuiSummary
