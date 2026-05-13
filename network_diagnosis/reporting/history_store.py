"""同目标多次诊断的轻量历史索引（仅存路径与摘要，便于对比）。"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from network_diagnosis.model.report import HistoryCompareResult
from network_diagnosis.paths import report_root


@dataclass
class HistoryEntry:
    task_id: str
    target_host: str
    finished_at: str
    grade: str
    report_dir: str
    markdown_path: str


def _index_path() -> Path:
    return report_root() / "_diagnosis_history.json"


def load_history() -> list[HistoryEntry]:
    p = _index_path()
    if not p.is_file():
        return []
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    out: list[HistoryEntry] = []
    for item in raw.get("entries", []):
        if not isinstance(item, dict):
            continue
        try:
            out.append(
                HistoryEntry(
                    task_id=str(item["task_id"]),
                    target_host=str(item["target_host"]),
                    finished_at=str(item["finished_at"]),
                    grade=str(item["grade"]),
                    report_dir=str(item["report_dir"]),
                    markdown_path=str(item["markdown_path"]),
                )
            )
        except KeyError:
            continue
    return out


def find_previous_same_target(target_host: str, exclude_task_id: str) -> HistoryEntry | None:
    norm = target_host.strip().lower()
    for e in reversed(load_history()):
        if e.task_id == exclude_task_id:
            continue
        if e.target_host.strip().lower() == norm:
            return e
    return None


def build_history_compare(
    *,
    target_host: str,
    current_task_id: str,
    current_grade: str,
    current_finished_iso: str,
) -> HistoryCompareResult:
    _ = current_finished_iso
    prev = find_previous_same_target(target_host, current_task_id)
    lines: list[str] = []
    if prev is None:
        lines.append("索引中尚无同一目标的更早记录；本次可作为基线。")
        return HistoryCompareResult(
            compared=False,
            previous_task_id=None,
            previous_finished=None,
            previous_grade=None,
            lines=lines,
        )
    lines.append(f"上次任务：`{prev.task_id}`，完成于 {prev.finished_at}。")
    lines.append(f"上次网络质量评判：**{prev.grade}**；本次：**{current_grade}**。")
    if prev.grade == current_grade:
        lines.append("与上次相比，综合评判档位未变化。")
    else:
        lines.append(f"档位变化：**{prev.grade}** → **{current_grade}**。")
    lines.append(f"上次报告目录：`{prev.report_dir}`")
    return HistoryCompareResult(
        compared=True,
        previous_task_id=prev.task_id,
        previous_finished=prev.finished_at,
        previous_grade=prev.grade,
        lines=lines,
    )


def append_history(entry: HistoryEntry, *, max_entries: int = 80) -> None:
    p = _index_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    entries = [asdict(x) for x in load_history()]
    entries.append(asdict(entry))
    if len(entries) > max_entries:
        entries = entries[-max_entries:]
    payload: dict[str, Any] = {"entries": entries}
    p.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
