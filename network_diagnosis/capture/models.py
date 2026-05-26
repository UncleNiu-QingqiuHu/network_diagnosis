"""抓包分析数据模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Literal

CaptureStatus = Literal["running", "stopped", "failed", "cancelled"]
AnalysisSource = Literal["live", "imported", "from_diagnosis"]


@dataclass
class CaptureSessionResult:
    task_id: str
    started_at: datetime
    stopped_at: datetime | None
    interface_index: str
    interface_desc: str
    bpf_filter: str
    pcap_path: Path
    file_size_bytes: int
    frame_count: int | None
    status: CaptureStatus
    tshark_stdout_log: Path | None
    tshark_stderr_log: Path | None
    error_message: str = ""


@dataclass
class FlowStat:
    family: Literal["ipv4", "ipv6", "udp"]
    endpoint_a: str
    endpoint_b: str
    packet_count: int


@dataclass
class PacketPreviewRow:
    no: int
    time_relative: str
    src: str
    dst: str
    protocol: str
    length: int
    info: str


@dataclass
class ExpertWarning:
    severity: str
    summary: str
    count: int


@dataclass
class PcapAnalysisResult:
    task_id: str
    analyzed_at: datetime
    source: AnalysisSource
    pcap_path: Path
    display_filter: str | None
    frame_count: int
    file_size_bytes: int
    duration_sec: float | None
    summary_plain: str
    protocol_hierarchy: dict[str, int] = field(default_factory=dict)
    top_tcp_flows: list[FlowStat] = field(default_factory=list)
    top_udp_flows: list[FlowStat] = field(default_factory=list)
    retransmission_count: int | None = None
    rst_count: int | None = None
    dns_queries: list[str] = field(default_factory=list)
    tls_sni_list: list[str] = field(default_factory=list)
    http_status_summary: str = ""
    expert_warnings: list[ExpertWarning] = field(default_factory=list)
    packet_preview: list[PacketPreviewRow] = field(default_factory=list)
    markdown_path: Path | None = None
    analysis_json_path: Path | None = None
    report_dir: Path | None = None
