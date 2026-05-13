"""实时监控单次采样文本。"""

from __future__ import annotations

from typing import Any

from network_diagnosis.db_diagnosis.collect import monitor_lines


def collect_monitor_snapshot(engine: str, conn: Any) -> str:
    return "\n".join(monitor_lines(engine, conn))
