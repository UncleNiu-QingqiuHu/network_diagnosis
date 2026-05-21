"""域与组策略模块数据模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

GpScope = Literal["both", "user", "computer"]

OperationKind = Literal[
    "diagnose",
    "view_policy",
    "gpupdate",
    "repair_trust",
    "rename",
    "join_domain",
    "unjoin_domain",
]


@dataclass
class DomainIdentity:
    computer_name: str = ""
    dns_host_name: str = ""
    domain: str = ""
    workgroup: str = ""
    part_of_domain: bool = False


@dataclass
class DomainDiagnosisResult:
    task_id: str
    timestamp: datetime
    identity: DomainIdentity
    secure_channel_ok: bool | None = None
    secure_channel_detail: str = ""
    dc_name: str = ""
    dc_ip: str = ""
    srv_lookup: str = ""
    ping_dc_ok: bool | None = None
    tcp_389_ok: bool | None = None
    tcp_445_ok: bool | None = None
    time_status: str = ""
    pending_reboot: bool = False
    enabled_local_users: tuple[str, ...] = ()
    probe_domain_dns: str = ""
    conclusions: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    raw_sections: dict[str, str] = field(default_factory=dict)


@dataclass
class GpResultReport:
    task_id: str
    timestamp: datetime
    scope: GpScope
    text_summary: str = ""
    html_path: str = ""
    text_path: str = ""
    error: str | None = None


@dataclass
class DomainOperationResult:
    task_id: str
    timestamp: datetime
    operation: OperationKind
    success: bool
    message: str = ""
    needs_reboot: bool = False
    needs_logoff: bool = False
    detail: str = ""
    metadata: dict[str, str] = field(default_factory=dict)
