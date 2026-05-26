"""抓包分析 Markdown 报告。"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import date, datetime
from pathlib import Path

from network_diagnosis.capture.models import CaptureSessionResult, PcapAnalysisResult
from network_diagnosis.version import APP_DISPLAY_NAME, APP_VERSION


def _path_str(p: Path | None) -> str:
    if p is None:
        return "—"
    try:
        return str(p.resolve())
    except OSError:
        return str(p)


def render_packet_capture_markdown(
    *,
    session: CaptureSessionResult | None,
    analysis: PcapAnalysisResult,
    tshark_path: str,
) -> str:
    lines: list[str] = []
    lines.append("# 抓包分析报告")
    lines.append("")
    lines.append(f"- 工具: {APP_DISPLAY_NAME} v{APP_VERSION}")
    lines.append(f"- 任务 ID: `{analysis.task_id}`")
    lines.append(f"- 分析时间: {analysis.analyzed_at.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"- 来源: {analysis.source}")
    lines.append(f"- pcap: `{_path_str(analysis.pcap_path)}`")
    lines.append(f"- tshark: `{tshark_path}`")
    if analysis.display_filter:
        lines.append(f"- Display Filter: `{analysis.display_filter}`")
    lines.append(f"- 帧数: {analysis.frame_count}")
    lines.append(f"- 文件大小: {analysis.file_size_bytes} 字节")
    if analysis.duration_sec is not None:
        lines.append(f"- 抓包时长（约）: {analysis.duration_sec:.2f} 秒")
    lines.append("")

    if session is not None:
        lines.append("## 抓包会话")
        lines.append("")
        lines.append(f"- 网卡: `{session.interface_index}` — {session.interface_desc}")
        lines.append(f"- BPF: `{session.bpf_filter or '（无）'}`")
        lines.append(f"- 开始: {session.started_at.strftime('%Y-%m-%d %H:%M:%S')}")
        if session.stopped_at:
            lines.append(f"- 结束: {session.stopped_at.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"- 状态: {session.status}")
        if session.error_message:
            lines.append(f"- 错误: {session.error_message}")
        lines.append("")

    lines.append("## 中文摘要")
    lines.append("")
    lines.append(analysis.summary_plain)
    lines.append("")

    if analysis.protocol_hierarchy:
        lines.append("## 协议分层（帧数）")
        lines.append("")
        lines.append("| 协议 | 帧数 |")
        lines.append("|------|------|")
        for name, fr in sorted(analysis.protocol_hierarchy.items(), key=lambda x: -x[1])[:30]:
            lines.append(f"| {name} | {fr} |")
        lines.append("")

    if analysis.retransmission_count is not None or analysis.rst_count is not None:
        lines.append("## 异常统计")
        lines.append("")
        if analysis.retransmission_count is not None:
            lines.append(f"- TCP 重传: {analysis.retransmission_count}")
        if analysis.rst_count is not None:
            lines.append(f"- TCP RST: {analysis.rst_count}")
        lines.append("")

    if analysis.dns_queries:
        lines.append("## DNS 查询（抽样）")
        lines.append("")
        for q in analysis.dns_queries:
            lines.append(f"- `{q}`")
        lines.append("")

    if analysis.tls_sni_list:
        lines.append("## TLS SNI（抽样，未解密）")
        lines.append("")
        for s in analysis.tls_sni_list:
            lines.append(f"- `{s}`")
        lines.append("")

    if analysis.http_status_summary:
        lines.append("## HTTP 状态码（明文 HTTP）")
        lines.append("")
        lines.append(analysis.http_status_summary)
        lines.append("")

    if analysis.top_tcp_flows or analysis.top_udp_flows:
        lines.append("## 会话 Top（结构化）")
        lines.append("")
        for flow in analysis.top_tcp_flows:
            lines.append(
                f"- TCP/{flow.family}: {flow.endpoint_a} ↔ {flow.endpoint_b} — {flow.packet_count} 帧"
            )
        for flow in analysis.top_udp_flows:
            lines.append(
                f"- UDP: {flow.endpoint_a} ↔ {flow.endpoint_b} — {flow.packet_count} 帧"
            )
        lines.append("")

    if analysis.expert_warnings:
        lines.append("## 专家提示")
        lines.append("")
        for w in analysis.expert_warnings:
            lines.append(f"- [{w.severity}] {w.summary}: {w.count}")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("> 如需确认 RST、重传、TLS 握手细节等，请用 Wireshark 打开同目录 pcap 深入分析。")
    return "\n".join(lines)


def write_analysis_artifacts(
    *,
    report_dir: Path,
    session: CaptureSessionResult | None,
    analysis: PcapAnalysisResult,
    tshark_path: str,
) -> tuple[Path, Path]:
    report_dir.mkdir(parents=True, exist_ok=True)
    md_path = report_dir / "report.md"
    md_text = render_packet_capture_markdown(
        session=session,
        analysis=analysis,
        tshark_path=tshark_path,
    )
    md_path.write_text(md_text, encoding="utf-8")

    json_path = report_dir / "analysis.json"

    def _json_default(obj: object) -> str:
        if isinstance(obj, Path):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat(timespec="seconds")
        if isinstance(obj, date):
            return obj.isoformat()
        raise TypeError(type(obj))

    payload = {
        "analysis": asdict(analysis),
        "session": asdict(session) if session else None,
        "tshark_path": tshark_path,
    }
    json_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, default=_json_default) + "\n",
        encoding="utf-8",
    )
    return md_path, json_path
