"""域模块用户配置。"""

from __future__ import annotations

import json
from dataclasses import dataclass

from network_diagnosis.paths import domain_ops_config_path


@dataclass
class DomainOpsSettings:
    default_domain_dns: str = ""
    default_workgroup: str = "WORKGROUP"
    post_join_local_group: str = "Power Users"


def load_domain_ops_settings() -> DomainOpsSettings:
    path = domain_ops_config_path()
    if not path.is_file():
        return DomainOpsSettings()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return DomainOpsSettings()
    if not isinstance(data, dict):
        return DomainOpsSettings()
    return DomainOpsSettings(
        default_domain_dns=str(data.get("default_domain_dns") or "").strip(),
        default_workgroup=str(data.get("default_workgroup") or "WORKGROUP").strip() or "WORKGROUP",
        post_join_local_group=str(data.get("post_join_local_group") or "Power Users").strip() or "Power Users",
    )


def save_domain_ops_settings(settings: DomainOpsSettings) -> None:
    path = domain_ops_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "default_domain_dns": settings.default_domain_dns,
        "default_workgroup": settings.default_workgroup,
        "post_join_local_group": settings.post_join_local_group,
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
