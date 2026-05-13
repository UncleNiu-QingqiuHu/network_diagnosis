"""将 DiagnosticReport 序列化为 Markdown 技术报告。"""

from __future__ import annotations

import statistics
from datetime import datetime
from pathlib import Path

from network_diagnosis.model.report import (
    CaptureInfo,
    DiagnosticReport,
    DnsAnswer,
    EgressProbeResult,
    HistoryCompareResult,
    HttpTlsProbeResult,
    MtuProbeResult,
    PingStats,
    PortProbeResult,
    ShellProbeResult,
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
        f"avg={statistics.mean(values):.1f}ms, "
        f"抖动={max(values)-min(values):.1f}ms（简易度量：RTT 极差，即 max−min）"
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


def _traceroute_section(report: DiagnosticReport) -> str:
    ui = report.user_input
    tr = report.traceroute
    if not ui.enable_traceroute:
        return "（本轮未启用路由追踪。）"
    if tr is None:
        return "（已勾选路由追踪，但未得到输出结构。）"
    lines = [
        f"- 目标: `{tr.target}`",
        f"- 命令: `{' '.join(tr.command) if tr.command else '—'}`",
        f"- 退出码: {tr.returncode}",
        "",
        "**自动摘要：**",
        "",
        "```",
        tr.outline,
        "```",
        "",
        f"- stdout: `{tr.raw_stdout_path.resolve()}`",
        f"- stderr: `{tr.raw_stderr_path.resolve()}`",
        "",
        "**stdout 末尾摘录：**",
        "",
        "```",
        _tail_file(tr.raw_stdout_path, 100),
        "```",
    ]
    return "\n".join(lines)


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


def _bandwidth_section(report: DiagnosticReport) -> str:
    ui = report.user_input
    b = report.bandwidth
    lines = [
        f"- 模式: {ui.bandwidth_mode}（off / http / iperf3）",
        f"- HTTP URL: `{ui.bandwidth_http_url or '—'}`",
        f"- HTTP 并发连接数: {ui.bandwidth_http_parallel}，持续时间 (s): {ui.bandwidth_http_seconds}",
        f"- iperf3 服务器: `{ui.bandwidth_iperf_host or '—'}`，端口: {ui.bandwidth_iperf_port}，时长 (s): {ui.bandwidth_iperf_seconds}",
        "",
    ]
    if ui.bandwidth_mode == "off" or b is None:
        lines.append("（本轮未启用或未产生带宽抽样结果。）")
        return "\n".join(lines)
    lines.append(f"- 是否成功: {b.ok}")
    lines.append(f"- 摘要: {b.summary}")
    if b.megabits_per_second is not None:
        lines.append(f"- 估算平均速率: **{b.megabits_per_second:.2f} Mbps**")
    if b.bytes_total is not None:
        lines.append(f"- 字节量（如适用）: {b.bytes_total}")
    if b.duration_sec is not None:
        lines.append(f"- 时长（如适用）: {b.duration_sec:.3f} s")
    if b.command:
        lines.append(f"- 命令: `{' '.join(b.command)}`")
    if b.log_stdout_path:
        lines.append(f"- 日志/输出: `{b.log_stdout_path.resolve()}`")
    if b.log_stderr_path:
        lines.append(f"- stderr: `{b.log_stderr_path.resolve()}`")
    if b.error:
        lines.append(f"- 错误信息: {b.error}")
    return "\n".join(lines)


def _tail_file(path: Path, n_lines: int = 40) -> str:
    text = read_text_best_effort(path, max_bytes=256_000)
    lines = text.splitlines()
    return "\n".join(lines[-n_lines:])


def _shell_probe_subsection(title: str, p: ShellProbeResult | None, enabled: bool) -> list[str]:
    out = [f"### {title}", ""]
    if not enabled:
        out.append(f"（本轮未启用 {title}。）")
        out.append("")
        return out
    if p is None:
        out.append("（已勾选，但未得到结构化结果。）")
        out.append("")
        return out
    out.extend(
        [
            f"- 子类型: `{p.kind}`",
            f"- 摘要: {p.summary}",
            f"- 命令: `{' '.join(p.command)}`" if p.command else "- 命令: —",
            f"- 退出码: {p.returncode}",
            f"- stdout: `{p.raw_stdout_path.resolve()}`",
            f"- stderr: `{p.raw_stderr_path.resolve()}`",
            "",
            "**stdout 末尾摘录：**",
            "",
            "```",
            _tail_file(p.raw_stdout_path, 80),
            "```",
            "",
        ]
    )
    return out


def _http_tls_subsection(h: HttpTlsProbeResult | None, enabled: bool) -> list[str]:
    title = "HTTPS / TLS"
    out = [f"### {title}", ""]
    if not enabled:
        out.append("（本轮未启用 HTTPS / TLS 探测。）")
        out.append("")
        return out
    if h is None:
        out.append("（已勾选，但未得到结果。）")
        out.append("")
        return out
    lines = [
        f"- URL: `{h.url}`",
        f"- 成功: {h.ok}",
    ]
    if h.tls_handshake_ms is not None:
        lines.append(f"- TLS 握手耗时: {h.tls_handshake_ms:.1f} ms")
    if h.http_status is not None:
        lines.append(f"- HTTP 状态码: {h.http_status}")
    if h.tls_version:
        lines.append(f"- 协商 TLS 版本: {h.tls_version}")
    lines.extend(
        [
            f"- 证书主体: {h.cert_subject or '—'}",
            f"- 颁发者: {h.cert_issuer or '—'}",
            f"- 有效期至: {h.cert_not_after or '—'}",
        ]
    )
    if h.error:
        lines.append(f"- 错误: {h.error}")
    out.extend(lines)
    out.append("")
    return out


def _egress_subsection(e: EgressProbeResult | None, enabled: bool) -> list[str]:
    title = "出口公网与代理环境"
    out = [f"### {title}", ""]
    if not enabled:
        out.append("（本轮未启用出口 / 代理探测。）")
        out.append("")
        return out
    if e is None:
        out.append("（已勾选，但未得到结果。）")
        out.append("")
        return out
    out.extend(
        [
            f"- 公网 IPv4（国内接口）: `{e.public_ip or '—'}`",
            f"- 查询错误: {e.ipify_error or '—'}",
            f"- HTTP_PROXY: `{e.http_proxy or '—'}`",
            f"- HTTPS_PROXY: `{e.https_proxy or '—'}`",
            f"- ALL_PROXY: `{e.all_proxy or '—'}`",
            f"- NO_PROXY: `{e.no_proxy or '—'}`",
            f"- WinHTTP 代理摘要: {e.winhttp_note or '—'}",
            "",
        ]
    )
    return out


def _mtu_subsection(m: MtuProbeResult | None, enabled: bool) -> list[str]:
    title = "IPv4 MTU（DF ping 估算）"
    out = [f"### {title}", ""]
    if not enabled:
        out.append("（本轮未启用 MTU 探测。）")
        out.append("")
        return out
    if m is None:
        out.append("（已勾选，但未得到结果。）")
        out.append("")
        return out
    out.extend(
        [
            f"- 目标: `{m.target}`",
            f"- 摘要: {m.summary}",
            f"- 最大 ICMP payload（探测）: {m.max_icmp_payload}",
            f"- 推算 IPv4 MTU: {m.implied_ipv4_mtu}",
            f"- 原始日志: `{m.raw_log_path.resolve()}`" if m.raw_log_path else "- 原始日志: —",
            "",
        ]
    )
    return out


def _history_subsection(h: HistoryCompareResult | None, enabled: bool) -> list[str]:
    title = "与历史记录对比"
    out = [f"### {title}", ""]
    if not enabled:
        out.append("（本轮未启用历史索引对比。）")
        out.append("")
        return out
    if h is None:
        out.append("（已启用，但未生成对比结果。）")
        out.append("")
        return out
    for ln in h.lines:
        out.append(f"- {ln}")
    out.append("")
    return out


def _advanced_probes_section(report: DiagnosticReport) -> list[str]:
    ui = report.user_input
    lines: list[str] = ["## 11. 进阶探测（PathPing、TCP trace、TLS、出口、MTU、历史）", ""]
    lines.extend(
        _shell_probe_subsection(
            "路径质量（PathPing / mtr）",
            report.path_quality,
            ui.enable_pathping,
        )
    )
    lines.extend(
        _shell_probe_subsection(
            "TCP 路径（nmap / traceroute -T）",
            report.tcp_path,
            ui.enable_tcp_traceroute,
        )
    )
    lines.extend(_http_tls_subsection(report.http_tls, ui.enable_http_tls_probe))
    lines.extend(_egress_subsection(report.egress, ui.enable_egress_probe))
    lines.extend(_mtu_subsection(report.mtu, ui.enable_mtu_probe))
    lines.extend(_history_subsection(report.history_compare, ui.enable_history_compare))
    return lines


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
        f"- 路由追踪: {report.user_input.enable_traceroute}"
        f"（最大跳数 {report.user_input.traceroute_max_hops}，每跳超时 {report.user_input.traceroute_hop_timeout_ms} ms）",
        f"- 启用 ping: {report.user_input.enable_ping}",
        f"- 启用抓包: {report.user_input.enable_capture}",
        f"- 优先 IPv6: {report.user_input.prefer_ipv6}",
        f"- 带宽/吞吐抽样模式: `{report.user_input.bandwidth_mode}`",
        f"- HTTP 抽样 URL: `{report.user_input.bandwidth_http_url or '—'}`",
        f"- HTTP 并发: {report.user_input.bandwidth_http_parallel}，时长 (s): {report.user_input.bandwidth_http_seconds}",
        f"- iperf3 目标: `{report.user_input.bandwidth_iperf_host or '—'}:{report.user_input.bandwidth_iperf_port}`，时长 (s): {report.user_input.bandwidth_iperf_seconds}",
        f"- 指定 DNS（可选，与系统解析对比）: `{report.user_input.optional_dns_server or '—'}`",
        f"- PathPing / mtr: {report.user_input.enable_pathping}",
        f"- TCP 路径探测: {report.user_input.enable_tcp_traceroute}"
        f"（最大跳数 {report.user_input.tcp_traceroute_max_hops}）",
        f"- HTTPS / TLS 探测: {report.user_input.enable_http_tls_probe}",
        f"- 出口公网 / 代理探测: {report.user_input.enable_egress_probe}",
        f"- IPv4 MTU 探测: {report.user_input.enable_mtu_probe}",
        f"- 与同目标历史记录对比: {report.user_input.enable_history_compare}",
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
            "### 系统默认解析器",
            "",
            _dns_section(report.dns),
            "",
        ]
    )
    if report.dns_specified is not None:
        srv = (report.user_input.optional_dns_server or "").strip()
        lines.extend(
            [
                f"### 指定 DNS（`{srv}`）",
                "",
                _dns_section(report.dns_specified),
                "",
            ]
        )
    lines.extend(
        [
            "## 5. 网络质量与指标",
            "",
            f"- **综合评判**: **{report.network_quality.grade}**（极佳 / 正常 / 较差 / 堵塞）",
        ]
    )
    for ml in report.network_quality.metric_lines:
        lines.append(f"- {ml}")
    lines.extend(
        [
            "",
            "## 6. 带宽/吞吐抽样（可选）",
            "",
            _bandwidth_section(report),
            "",
            "## 7. ICMP Ping",
            "",
            _ping_section(report.ping),
            "",
            "## 8. 路由追踪（tracert / traceroute）",
            "",
            _traceroute_section(report),
            "",
            "## 9. 端口连通性（tcping）",
            "",
            _port_table(report.ports),
            "",
        ]
    )
    cap: CaptureInfo = report.capture
    lines.extend(
        [
            "## 10. 抓包",
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
    lines.extend(_advanced_probes_section(report))
    lines.append("## 12. 降级与异常")
    lines.append("")
    if not report.degradations:
        lines.append("（无）")
    else:
        for ev in report.degradations:
            lines.append(f"- **{ev.code}**: {ev.message}")
            if ev.detail:
                lines.append(f"  - 详情: {ev.detail}")
    lines.append("")
    lines.append("## 13. GUI 摘要（交叉核对）")
    lines.append("")
    lines.append(f"- 总览: **{report.gui.overall.value}** — {report.gui.headline}")
    for b in report.gui.bullets:
        lines.append(f"- {b}")
    lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
