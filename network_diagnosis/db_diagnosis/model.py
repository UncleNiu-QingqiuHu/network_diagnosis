from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class DbDiagnosisReport:
    """一次完整诊断的结构化结果。"""

    task_id: str
    engine: str
    started_at: datetime
    finished_at: datetime
    version_line: str
    sections: dict[str, str]
    errors: list[str] = field(default_factory=list)
    report_dir: Path | None = None
    markdown_path: Path | None = None
