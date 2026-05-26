"""抓包分析用户配置。"""

from __future__ import annotations

import json
from dataclasses import dataclass

from network_diagnosis.paths import packet_capture_config_path


@dataclass
class PacketCaptureSettings:
    default_interface_index: str = ""
    default_bpf: str = "not broadcast and not multicast"
    default_duration_sec: int = 60
    default_filesize_limit_mb: int = 0
    preview_limit: int = 500
    max_analyze_bytes: int = 524_288_000
    confirm_empty_bpf: bool = True


def load_packet_capture_settings() -> PacketCaptureSettings:
    path = packet_capture_config_path()
    if not path.is_file():
        return PacketCaptureSettings()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return PacketCaptureSettings()
    if not isinstance(data, dict):
        return PacketCaptureSettings()
    default_bpf_raw = data.get("default_bpf")
    default_bpf = (
        str(default_bpf_raw)
        if default_bpf_raw is not None
        else "not broadcast and not multicast"
    )
    return PacketCaptureSettings(
        default_interface_index=str(data.get("default_interface_index") or "").strip(),
        default_bpf=default_bpf,
        default_duration_sec=int(data.get("default_duration_sec") or 60),
        default_filesize_limit_mb=int(data.get("default_filesize_limit_mb") or 0),
        preview_limit=int(data.get("preview_limit") or 500),
        max_analyze_bytes=int(data.get("max_analyze_bytes") or 524_288_000),
        confirm_empty_bpf=bool(data.get("confirm_empty_bpf", True)),
    )


def save_packet_capture_settings(settings: PacketCaptureSettings) -> None:
    path = packet_capture_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "default_interface_index": settings.default_interface_index,
        "default_bpf": settings.default_bpf,
        "default_duration_sec": settings.default_duration_sec,
        "default_filesize_limit_mb": settings.default_filesize_limit_mb,
        "preview_limit": settings.preview_limit,
        "max_analyze_bytes": settings.max_analyze_bytes,
        "confirm_empty_bpf": settings.confirm_empty_bpf,
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
