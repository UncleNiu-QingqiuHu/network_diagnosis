"""DHCP 诊断 Markdown / JSON 报告。"""

from __future__ import annotations

import json
from pathlib import Path

from network_diagnosis.dhcp.client import format_address_source
from network_diagnosis.dhcp.models import DhcpDiagnosisResult


def _severity_label(severity: str) -> str:
    return {"info": "信息", "medium": "中", "high": "高"}.get(severity, severity)


def _verdict_label(code: str) -> str:
    labels = {
        "OK": "正常",
        "MULTIPLE_DHCP_SERVERS": "疑似 DHCP 污染（多 DHCP 服务器）",
        "MULTIPLE_DHCP_SERVERS_HA": "多 DHCP 服务器（可能热备）",
        "UNKNOWN_DHCP_SERVER": "未知 DHCP 服务器",
        "NO_DHCP_OFFERS": "未收到 DHCP OFFER",
        "CLIENT_ISSUES": "本机 DHCP 客户端异常",
        "PROBE_SKIPPED": "未执行主动探测",
    }
    return labels.get(code, code)


def render_dhcp_diagnosis_markdown(result: DhcpDiagnosisResult) -> str:
    lines: list[str] = []
    lines.append("# DHCP 诊断报告")
    lines.append("")
    lines.append(f"- 任务 ID: `{result.task_id}`")
    lines.append(f"- 时间: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"- 绑定接口 IPv4: `{result.interface_ipv4}`")
    if result.network_cidr:
        lines.append(f"- 网段: `{result.network_cidr}`")
    if result.authorized_servers:
        lines.append(f"- 合法 DHCP 白名单: {', '.join(result.authorized_servers)}")
    if result.scope_cidr:
        lines.append(f"- DHCP 作用域: `{result.scope_cidr}`")
    lines.append("")

    lines.append("## 执行摘要")
    lines.append("")
    lines.append("| 级别 | 结论 |")
    lines.append("|------|------|")
    lines.append(f"| {_severity_label(result.severity)} | {_verdict_label(result.verdict)} |")
    for c in result.conclusions:
        lines.append(f"| | {c} |")
    lines.append("")

    lines.append("## 本机 DHCP 客户端")
    lines.append("")
    lines.append("| 接口 | 地址来源 | IPv4 | DHCP 服务器 | 租约到期 | 健康标记 |")
    lines.append("|------|----------|------|-------------|----------|----------|")
    for c in result.clients:
        lease = c.lease_expires.strftime("%Y-%m-%d %H:%M:%S") if c.lease_expires else "—"
        flags = "，".join(c.health_flags) if c.health_flags else "—"
        lines.append(
            f"| {c.interface_name} | {format_address_source(c.address_source)} | {c.ipv4} | "
            f"{c.dhcp_server or '—'} | {lease} | {flags} |"
        )
    lines.append("")

    lines.append("## DHCP 服务探测（多服务器 / DHCP 污染）")
    lines.append("")
    lines.append(
        "> 在同一广播域发送 DHCP DISCOVER，汇总 OFFER 中的 Server Identifier。"
        "若 distinct ≥ 2，则存在多 DHCP 服务器响应（DHCP 污染风险）。"
    )
    lines.append("")
    if result.probe_skipped_reason:
        lines.append(f"**说明：** {result.probe_skipped_reason}")
        lines.append("")
    if result.probe_error:
        lines.append(f"**探测警告：** {result.probe_error}")
        lines.append("")

    if result.probe_rounds:
        lines.append("| 轮次 | Server ID | 建议 IP | 网关 | DNS | 白名单 |")
        lines.append("|------|-----------|---------|------|-----|--------|")
        for r in result.probe_rounds:
            if not r.offers:
                lines.append(f"| {r.round_index} | — | — | — | — | 无 OFFER |")
                continue
            for o in r.offers:
                dns = ", ".join(o.dns) if o.dns else "—"
                wl = "是" if o.in_whitelist else "否"
                lines.append(
                    f"| {r.round_index} | {o.server_id} | {o.yiaddr or '—'} | {o.router or '—'} | {dns} | {wl} |"
                )
        lines.append("")

    if result.recommendations:
        lines.append("## 处置建议")
        lines.append("")
        for i, rec in enumerate(result.recommendations, 1):
            lines.append(f"{i}. {rec}")
        lines.append("")

    lines.append("## 原始证据")
    lines.append("")
    if result.event_log_excerpt:
        lines.append("### DHCP 客户端事件日志（节选）")
        lines.append("")
        lines.append("```text")
        lines.append(result.event_log_excerpt[:8000])
        lines.append("```")
        lines.append("")
    if result.nmap_combined_output:
        lines.append("### Nmap broadcast-dhcp-discover 输出")
        lines.append("")
        lines.append("```text")
        lines.append(result.nmap_combined_output[:16000])
        lines.append("```")
        lines.append("")

    return "\n".join(lines)


def write_dhcp_diagnosis_report(result: DhcpDiagnosisResult, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    md_path = out_dir / "report.md"
    md_path.write_text(render_dhcp_diagnosis_markdown(result), encoding="utf-8")

    probe_json = {
        "interface_ipv4": result.interface_ipv4,
        "network_cidr": result.network_cidr,
        "authorized_servers": list(result.authorized_servers),
        "verdict": result.verdict,
        "severity": result.severity,
        "rounds": [
            {
                "round": r.round_index,
                "distinct_server_count": r.distinct_server_count,
                "offers": [
                    {
                        "server_id": o.server_id,
                        "yiaddr": o.yiaddr,
                        "router": o.router,
                        "dns": list(o.dns),
                        "subnet_mask": o.subnet_mask,
                        "in_whitelist": o.in_whitelist,
                    }
                    for o in r.offers
                ],
                "error": r.error,
            }
            for r in result.probe_rounds
        ],
    }
    (out_dir / "dhcp_probe.json").write_text(
        json.dumps(probe_json, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    if result.ipconfig_excerpt:
        (out_dir / "ipconfig_excerpt.txt").write_text(result.ipconfig_excerpt, encoding="utf-8")
    if result.event_log_excerpt:
        (out_dir / "events_dhcp_client.txt").write_text(result.event_log_excerpt, encoding="utf-8")
    if result.nmap_combined_output:
        (out_dir / "nmap_dhcp.txt").write_text(result.nmap_combined_output, encoding="utf-8")
    return md_path
