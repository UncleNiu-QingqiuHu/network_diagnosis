"""DHCP 诊断用户配置（白名单、作用域）。"""

from __future__ import annotations

import json
from dataclasses import dataclass

from network_diagnosis.paths import dhcp_diagnosis_config_path


@dataclass
class DhcpDiagnosisSettings:
    authorized_dhcp_servers: tuple[str, ...] = ()
    dhcp_scope_cidr: str = ""


def _parse_server_list(raw: object) -> tuple[str, ...]:
    if raw is None:
        return ()
    if isinstance(raw, str):
        parts = [p.strip() for p in raw.replace(";", ",").split(",") if p.strip()]
        return tuple(parts)
    if isinstance(raw, list):
        return tuple(str(x).strip() for x in raw if str(x).strip())
    return ()


def load_dhcp_diagnosis_settings() -> DhcpDiagnosisSettings:
    path = dhcp_diagnosis_config_path()
    if not path.is_file():
        return DhcpDiagnosisSettings()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return DhcpDiagnosisSettings()
    if not isinstance(data, dict):
        return DhcpDiagnosisSettings()
    return DhcpDiagnosisSettings(
        authorized_dhcp_servers=_parse_server_list(data.get("authorized_dhcp_servers")),
        dhcp_scope_cidr=str(data.get("dhcp_scope_cidr") or "").strip(),
    )


def save_dhcp_diagnosis_settings(settings: DhcpDiagnosisSettings) -> None:
    path = dhcp_diagnosis_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "authorized_dhcp_servers": list(settings.authorized_dhcp_servers),
        "dhcp_scope_cidr": settings.dhcp_scope_cidr,
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
