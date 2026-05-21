"""DHCP 诊断数据模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

Severity = Literal["info", "medium", "high"]
VerdictCode = Literal[
    "OK",
    "MULTIPLE_DHCP_SERVERS",
    "MULTIPLE_DHCP_SERVERS_HA",
    "UNKNOWN_DHCP_SERVER",
    "NO_DHCP_OFFERS",
    "CLIENT_ISSUES",
    "PROBE_SKIPPED",
]


@dataclass
class DhcpClientSnapshot:
    interface_name: str
    mac: str | None
    ipv4: str
    netmask: str
    address_source: str  # dhcp | manual | apipa | unknown
    dhcp_enabled: bool | None
    dhcp_server: str | None
    lease_obtained: datetime | None
    lease_expires: datetime | None
    gateways: tuple[str, ...]
    dns_servers: tuple[str, ...]
    is_apipa: bool
    health_flags: tuple[str, ...] = ()
    dhcp_server_reachable: bool | None = None


@dataclass
class DhcpOffer:
    server_id: str
    yiaddr: str | None = None
    router: str | None = None
    dns: tuple[str, ...] = ()
    subnet_mask: str | None = None
    in_whitelist: bool = False
    raw_lines: tuple[str, ...] = ()


@dataclass
class DhcpProbeRound:
    round_index: int
    offers: list[DhcpOffer] = field(default_factory=list)
    distinct_server_count: int = 0
    raw_output: str = ""
    error: str | None = None


@dataclass
class DhcpDiagnosisResult:
    task_id: str
    timestamp: datetime
    interface_ipv4: str
    network_cidr: str | None
    authorized_servers: tuple[str, ...]
    scope_cidr: str | None
    clients: list[DhcpClientSnapshot]
    probe_rounds: list[DhcpProbeRound]
    verdict: VerdictCode
    severity: Severity
    conclusions: list[str]
    recommendations: list[str]
    ipconfig_excerpt: str = ""
    event_log_excerpt: str = ""
    nmap_combined_output: str = ""
    probe_error: str | None = None
    probe_skipped_reason: str | None = None
