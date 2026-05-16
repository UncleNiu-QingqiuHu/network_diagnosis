"""将诊断结果压缩为供大模型阅读的文本。"""

from __future__ import annotations

from pathlib import Path

from network_diagnosis.gui.main_app_report_text import (
    _any_advanced,
    _gui_lines_advanced,
    _gui_lines_bandwidth,
    _gui_lines_capture,
    _gui_lines_dns,
    _gui_lines_network_quality,
    _gui_lines_ping,
    _gui_lines_ports,
    _gui_lines_traceroute,
    _gui_oneline_advanced,
    _gui_oneline_dns,
    _gui_oneline_network_quality,
    _gui_oneline_ping,
    _gui_oneline_ports,
    _gui_oneline_traceroute,
)
from network_diagnosis.model.report import DiagnosticReport
from network_diagnosis.probes.subproc_util import read_text_best_effort


def summarize_diagnostic_report(rep: DiagnosticReport, *, include_markdown_excerpt: bool = True) -> str:
    g = rep.gui
    lines: list[str] = [
        "=== 网络诊断结果摘要 ===",
        "",
        g.headline,
        "",
        f"综合质量：{rep.network_quality.grade} — {_gui_oneline_network_quality(rep)}",
        f"DNS：{_gui_oneline_dns(rep)}",
        f"Ping：{_gui_oneline_ping(rep)}",
        f"端口：{_gui_oneline_ports(rep)}",
        f"路由追踪：{_gui_oneline_traceroute(rep)}",
    ]
    if _any_advanced(rep):
        lines.append(f"进阶探测：{_gui_oneline_advanced(rep)}")

    sections: list[tuple[str, list[str]]] = [
        ("网络质量明细", _gui_lines_network_quality(rep)),
        ("DNS", _gui_lines_dns(rep)),
        ("Ping", _gui_lines_ping(rep)),
        ("端口探测", _gui_lines_ports(rep)),
        ("路由追踪", _gui_lines_traceroute(rep)),
        ("抓包", _gui_lines_capture(rep)),
        ("带宽", _gui_lines_bandwidth(rep)),
    ]
    if _any_advanced(rep):
        sections.append(("进阶项", _gui_lines_advanced(rep)))

    for title, body in sections:
        if not body:
            continue
        lines.append("")
        lines.append(f"--- {title} ---")
        lines.extend(body)

    md_path = (g.markdown_path or "").strip()
    if md_path:
        lines.append("")
        lines.append(f"完整 Markdown 报告路径：{md_path}")

    if include_markdown_excerpt and md_path:
        p = Path(md_path)
        if p.is_file():
            full = read_text_best_effort(p)
            if full:
                cap = 12000
                excerpt = full if len(full) <= cap else full[:cap] + "\n\n…（报告已截断，完整内容见上述路径）"
                lines.append("")
                lines.append("--- Markdown 报告摘录 ---")
                lines.append(excerpt)

    return "\n".join(lines)
