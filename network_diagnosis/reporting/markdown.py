"""将 DiagnosticReport 序列化为 Markdown 技术报告。"""

from __future__ import annotations

import statistics
from datetime import datetime
from pathlib import Path

from network_diagnosis.model.report import (
    CaptureInfo,
    DiagnosticReport,
    DnsAnswer,
    PingStats,
    PortProbeResult,
    TaskMeta,
)
from network_diagnosis.probes.subproc_util import read_text_best_effort


def _fmt_dt(dt: datetime | None) -> str:
    if dt is None:
        return ""
    return dt.isoformat(timespec="seconds")


def _rtt_summary(values: list[float]) -> str:
    if not values:
        return "无有效 RTT 样本"
    return (
        f"n={len(values)}, min={min(values):.1f}ms, max={max(values):.1f}ms, "
        f"avg={statistics.mean(values):.1f}ms, jitter(极差)={max(values)-min(values):.1f}ms"
    )


def _dns_section(d: DnsAnswer) -> str:
    lines = [
        f"- 地址族策略: {d.family}",
        f"- 解析耗时: {d.elapsed_ms:.1f} ms",
    ]
    if d.error:
        lines.append(f"- 错误: `{d.error}`")
    else:
        lines.append(f"- 解析到的地址: {', '.join(d.addresses) if d.addresses else '（无）'}")
    return "\n".join(lines)


def _ping_section(p: PingStats | None) -> str:
    if p is None:
        return "（本轮未启用 ICMP ping。）"
    loss = 100.0 * p.lost / p.attempted if p.attempted else 0.0
    body = [
        f"- 命令: `{' '.join(p.command)}`",
        f"- 发送/接收/丢失: {p.attempted} / {p.received} / {p.lost} （约 {loss:.0f}% 丢失）",
        f"- RTT: {_rtt_summary(p.rtts_ms)}",
        f"- 原始 stdout: `{p.raw_stdout_path.resolve()}`",
        f"- 原始 stderr: `{p.raw_stderr_path.resolve()}`",
    ]
    return "\n".join(body)


def _port_table(ports: list[PortProbeResult]) -> str:
    rows = ["| 端口 | 探测目标 | 分类 | 成功次数/样本 | RTT 摘要 | stdout |", "|---|---|---|---|---|---|"]
    for pr in ports:
        ok = sum(1 for s in pr.samples if s.success)
        n = len(pr.samples) or 1
        rtts = [s.rtt_ms for s in pr.samples if s.rtt_ms is not None]
        rtt_s = _rtt_summary([x for x in rtts if x is not None]) if rtts else "—"
        stdout_cell = f"`{pr.stdout_path.resolve()}`"
        rows.append(
            f"| {pr.port} | `{pr.target_used}` | {pr.failure_class.value} | {ok}/{n} | {rtt_s} | {stdout_cell} |"
        )
    return "\n".join(rows)


def _tail_file(path: Path, n_lines: int = 40) -> str:
    text = read_text_best_effort(path, max_bytes=256_000)
    lines = text.splitlines()
    return "\n".join(lines[-n_lines:])


def write_markdown_report(report: DiagnosticReport, path: Path) -> None:
    m: TaskMeta = report.meta
    lines: list[str] = [
        "# 网络诊断技术报告",
        "",
        "## 1. 任务元数据",
        "",
        f"- 任务 ID: `{m.task_id}`",
        f"- 开始时间（本地）: {_fmt_dt(m.started_at)}",
        f"- 结束时间（本地）: {_fmt_dt(m.finished_at)}",
        f"- 工具版本: {m.app_version}（设计参考: {m.design_doc_ref}）",
        f"- 主机名: {m.hostname}",
        f"- 操作系统: {m.os_summary}",
        f"- tcping 路径: `{m.tcping_path or '未找到'}`",
        f"- tcping 版本/标识: {m.tcping_version_line or '—'}",
        f"- tshark 路径: `{m.tshark_path or '未探测到'}`",
        f"- tshark 版本: {m.tshark_version_line or '—'}",
        f"- 报告目录: `{m.report_dir.resolve()}`",
        "",
        "> 第三方致谢：tcping、Wireshark/tshark 均为各自版权方软件；再分发须遵守其许可条款。",
        "",
        "## 2. 用户输入",
        "",
        f"- 目标: `{report.user_input.target_host}`",
        f"- 端口: {report.user_input.ports if report.user_input.ports else '（未填写）'}",
        f"- 端口采样次数（有端口时）: {report.user_input.samples_per_port}",
        f"- TCP 连接超时 (ms): {report.user_input.tcp_connect_timeout_ms}",
        f"- Ping 次数: {report.user_input.ping_count}",
        f"- 长 Ping: {report.user_input.ping_long}（最长 {report.user_input.long_ping_seconds} 秒）",
        f"- ICMP 单次等待 (ms): {report.user_input.ping_packet_timeout_ms}",
        f"- 启用 ping: {report.user_input.enable_ping}",
        f"- 启用抓包: {report.user_input.enable_capture}",
        f"- 优先 IPv6: {report.user_input.prefer_ipv6}",
        "",
        "## 3. 本机与出口上下文",
        "",
        report.local.note,
        "",
    ]
    if report.local.raw_ipconfig_path:
        lines.append(f"- ipconfig 原始输出: `{report.local.raw_ipconfig_path.resolve()}`")
        lines.append("")
        lines.append("```")
        lines.append(_tail_file(report.local.raw_ipconfig_path, 60))
        lines.append("```")
        lines.append("")
    for ad in report.local.adapters:
        lines.append(f"### 适配器: {ad.name}")
        lines.append(f"- 启用: {ad.enabled}")
        lines.append(f"- IPv4: {', '.join(ad.ipv4) or '—'}")
        lines.append(f"- 默认网关: {', '.join(ad.gateways) or '—'}")
        lines.append(f"- DNS 服务器: {', '.join(ad.dns_servers) or '—'}")
        lines.append("")
    lines.extend(
        [
            "## 4. DNS",
            "",
            _dns_section(report.dns),
            "",
            "## 5. ICMP Ping",
            "",
            _ping_section(report.ping),
            "",
            "## 6. 端口连通性（tcping）",
            "",
            _port_table(report.ports),
            "",
        ]
    )
    cap: CaptureInfo = report.capture
    lines.extend(
        [
            "## 7. 抓包",
            "",
            f"- 用户请求: {cap.requested}",
            f"- 是否实际执行: {cap.ran}",
            f"- 命令: `{' '.join(cap.tshark_cmd)}`" if cap.tshark_cmd else "- 命令: —",
            f"- pcapng: `{cap.pcap_path.resolve()}`" if cap.pcap_path else "- pcapng: —",
            "",
            cap.notes,
            "",
        ]
    )
    if cap.analysis_summary:
        lines.append("### 抓包可读摘要（自动生成）")
        lines.append("")
        lines.append("```")
        lines.append(cap.analysis_summary)
        lines.append("```")
        lines.append("")
    if cap.stdout_path:
        lines.append("### tshark 日志摘录")
        lines.append("")
        lines.append("```")
        lines.append(_tail_file(cap.stdout_path, 30))
        lines.append("```")
        lines.append("")
    lines.append("## 8. 降级与异常")
    lines.append("")
    if not report.degradations:
        lines.append("（无）")
    else:
        for ev in report.degradations:
            lines.append(f"- **{ev.code}**: {ev.message}")
            if ev.detail:
                lines.append(f"  - 详情: {ev.detail}")
    lines.append("")
    lines.append("## 9. GUI 摘要（交叉核对）")
    lines.append("")
    lines.append(f"- 总览: **{report.gui.overall.value}** — {report.gui.headline}")
    for b in report.gui.bullets:
        lines.append(f"- {b}")
    lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
