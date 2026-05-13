"""数据库诊断结果 -> Markdown 文件内容。"""

from __future__ import annotations

from datetime import datetime

from network_diagnosis.db_diagnosis.model import DbDiagnosisReport
from network_diagnosis.version import APP_VERSION


def render_db_diagnosis_markdown(
    report: DbDiagnosisReport,
    *,
    host_hint: str,
    db_hint: str,
) -> str:
    lines = [
        "# 数据库诊断报告",
        "",
        "## 元信息",
        "",
        f"- **任务 ID**：`{report.task_id}`",
        f"- **开始**：{report.started_at.isoformat(timespec='seconds')}",
        f"- **结束**：{report.finished_at.isoformat(timespec='seconds')}",
        f"- **引擎**：{report.engine}",
        f"- **版本摘要**：{report.version_line or '—'}",
        f"- **主机（脱敏展示）**：{host_hint or '—'}",
        f"- **库名/文件**：{db_hint or '—'}",
        f"- **工具版本**：{APP_VERSION}",
        "",
        "## 执行摘要",
        "",
    ]
    if report.errors:
        lines.append("**采集过程存在告警/错误：**")
        for e in report.errors:
            lines.append(f"- `{e}`")
        lines.append("")
    else:
        lines.append("- 本轮只读查询总体完成（结论需结合业务与 DBA 复核）。")
        lines.append("")

    lines.append("## 明细")
    lines.append("")
    for title, body in report.sections.items():
        lines.append(f"### {title}")
        lines.append("")
        lines.append(body.rstrip() or "_（空）_")
        lines.append("")

    lines.extend(
        [
            "## 免责声明",
            "",
            "- 本报告由桌面工具通过只读查询生成，不等价于数据库厂商官方巡检；重要变更请在维护窗口内操作。",
            "",
        ]
    )
    return "\n".join(lines)


def write_report_file(
    report: DbDiagnosisReport,
    *,
    host_hint: str,
    db_hint: str,
) -> None:
    if report.markdown_path is None:
        return
    text = render_db_diagnosis_markdown(report, host_hint=host_hint, db_hint=db_hint)
    report.markdown_path.write_text(text, encoding="utf-8")


def render_monitor_snapshot_markdown(
    *,
    engine: str,
    host_hint: str,
    db_hint: str,
    interval_sec: int,
    chunks: list[str],
    started: datetime,
    ended: datetime,
) -> str:
    body = "\n\n---\n\n".join(chunks) if chunks else "_（无采样）_"
    return "\n".join(
        [
            "# 数据库监控片段导出",
            "",
            "## 元信息",
            "",
            f"- **引擎**：{engine}",
            f"- **主机**：{host_hint}",
            f"- **库/路径**：{db_hint}",
            f"- **采样间隔**：{interval_sec} 秒",
            f"- **时段**：{started.isoformat(timespec='seconds')} — {ended.isoformat(timespec='seconds')}",
            f"- **工具版本**：{APP_VERSION}",
            "",
            "## 采样日志",
            "",
            body,
            "",
        ]
    )
