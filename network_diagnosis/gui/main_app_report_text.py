"""诊断报告 → GUI 摘要/详情区的纯文本生成（不依赖 Tk 组件）。"""

from __future__ import annotations

from network_diagnosis.model.report import DiagnosticReport, PortFailureClass
from network_diagnosis.probes.dns_probe import pick_tcp_target

_PORT_CLASS_CN: dict[PortFailureClass, str] = {
    PortFailureClass.OK: "连接正常",
    PortFailureClass.TIMEOUT: "超时",
    PortFailureClass.REFUSED: "连接被拒绝",
    PortFailureClass.UNREACHABLE: "不可达或重置",
    PortFailureClass.ERROR: "探测异常",
    PortFailureClass.UNKNOWN: "结果不明确",
}


def _quality_tag_for_grade(grade: str) -> str:
    return {
        "极佳": "quality_grade_exc",
        "正常": "quality_grade_ok",
        "较差": "quality_grade_poor",
        "堵塞": "quality_grade_bad",
    }.get(grade, "quality_grade_ok")


def _gui_oneline_network_quality(rep: DiagnosticReport) -> str:
    nq = rep.network_quality
    parts: list[str] = []
    if nq.loss_pct is not None:
        parts.append(f"丢包约 {nq.loss_pct:.1f}%")
    if nq.avg_latency_ms is not None:
        parts.append(f"平均时延约 {nq.avg_latency_ms:.0f} ms")
    if nq.jitter_ms is not None:
        parts.append(f"抖动约 {nq.jitter_ms:.1f} ms")
    if parts:
        return "，".join(parts) + "。详情见下方「网络质量与指标」。"
    return "详见下方「网络质量与指标」。"


def _gui_oneline_dns(rep: DiagnosticReport) -> str:
    dns = rep.dns
    if dns.error:
        tail = dns.error if len(dns.error) <= 100 else dns.error[:97] + "…"
        return f"失败：{tail}"
    if not dns.addresses:
        return "未得到可用地址。"
    first = dns.addresses[0]
    more = f" 等共 {len(dns.addresses)} 个" if len(dns.addresses) > 1 else ""
    return f"成功，记录族别 {dns.family}，例：{first}{more}。"


def _gui_oneline_ping(rep: DiagnosticReport) -> str:
    if not rep.user_input.enable_ping:
        return "未启用 ICMP Ping。"
    p = rep.ping
    if p is None:
        return "无 Ping 统计数据。"
    if p.attempted <= 0:
        return "未发起 Ping。"
    if p.received == 0:
        return f"无成功回复（已试 {p.attempted} 次，丢失 {p.lost}）。"
    loss = 100.0 * p.lost / p.attempted
    if p.rtts_ms:
        avg = sum(p.rtts_ms) / len(p.rtts_ms)
        return f"收到 {p.received}/{p.attempted}，丢包约 {loss:.0f}%，平均延迟约 {avg:.0f} ms。"
    return f"收到 {p.received}/{p.attempted}，丢包约 {loss:.0f}%。"


def _gui_oneline_traceroute(rep: DiagnosticReport) -> str:
    if not rep.user_input.enable_traceroute:
        return "未启用路由追踪。"
    tr = rep.traceroute
    if tr is None:
        return "无路由追踪输出。"
    lines = [ln for ln in (tr.outline or "").splitlines() if ln.strip()]
    return lines[0] if lines else "已完成，详见下方「路由追踪」。"


def _gui_oneline_ports(rep: DiagnosticReport) -> str:
    ui = rep.user_input
    if not ui.ports:
        return "未填写端口，未做 TCP 连通性测试。"
    if any(d.code == "tcping_missing" for d in rep.degradations):
        return "已填端口，但缺少 tcping.exe，无法探测。"
    if not rep.ports:
        return "未得到端口探测结果。"
    bad = [p for p in rep.ports if p.failure_class != PortFailureClass.OK]
    if not bad:
        return f"所测 {len(rep.ports)} 个端口均可建立连接。"
    return (
        f"{len(bad)}/{len(rep.ports)} 个端口异常（"
        + "、".join(str(p.port) for p in bad)
        + "）。"
    )


def _gui_lines_network_quality(rep: DiagnosticReport) -> list[str]:
    """明细：仅指标行（整体结论中已含评判档位）。"""
    return list(rep.network_quality.metric_lines)


def _gui_lines_dns(rep: DiagnosticReport) -> list[str]:
    ui = rep.user_input
    dns = rep.dns
    fam_cn = {"ipv4": "IPv4", "ipv6": "IPv6", "mixed": "IPv4 / IPv6 混合"}.get(
        dns.family, dns.family
    )
    lines: list[str] = [
        f"目标主机名：{ui.target_host}",
        f"记录族别：{fam_cn}",
        f"优先 IPv6：{'是' if ui.prefer_ipv6 else '否'}",
        f"解析耗时：{dns.elapsed_ms:.1f} ms",
    ]

    def append_specified() -> None:
        opt_srv = (ui.optional_dns_server or "").strip()
        if not opt_srv or rep.dns_specified is None:
            return
        ds = rep.dns_specified
        fam2 = {"ipv4": "IPv4", "ipv6": "IPv6", "mixed": "IPv4 / IPv6 混合"}.get(
            ds.family, ds.family
        )
        lines.append("")
        lines.append(f"指定 DNS（{opt_srv}）解析：")
        lines.append(f"  记录族别：{fam2}，耗时 {ds.elapsed_ms:.1f} ms")
        if ds.error:
            lines.append(f"  失败：{ds.error}")
        elif ds.addresses:
            lines.append("  地址：" + "、".join(ds.addresses))
        else:
            lines.append("  未得到地址。")

    if dns.error:
        lines.append(f"解析失败：{dns.error}")
        append_specified()
        return lines
    if not dns.addresses:
        lines.append("未得到任何解析地址。")
        append_specified()
        return lines
    lines.append("解析到的地址：" + "、".join(dns.addresses))
    tcp_t = pick_tcp_target(dns, prefer_ipv6=ui.prefer_ipv6)
    if tcp_t:
        lines.append(f"本次 TCP / 抓包使用的 IP：{tcp_t}")
    append_specified()
    return lines


def _gui_lines_ping(rep: DiagnosticReport) -> list[str]:
    if not rep.user_input.enable_ping:
        return [
            "本轮未启用 ICMP Ping。",
            "如需测试，请在左侧「探测选项」中勾选「ICMP Ping」。",
        ]
    p = rep.ping
    if p is None:
        return ["未获取到 Ping 统计数据。"]
    ui = rep.user_input
    mode = (
        f"（长 Ping：最长约 {ui.long_ping_seconds} 秒，由程序结束后统计）"
        if ui.ping_long
        else f"（固定次数：{ui.ping_count} 次）"
    )
    lines = [
        f"探测统计：已发送 {p.attempted}，收到 {p.received}，丢失 {p.lost}。{mode}",
    ]
    if p.rtts_ms:
        avg = sum(p.rtts_ms) / len(p.rtts_ms)
        mn = min(p.rtts_ms)
        mx = max(p.rtts_ms)
        lines.append(f"延迟：平均 {avg:.1f} ms，最小 {mn:.1f} ms，最大 {mx:.1f} ms。")
    elif p.received > 0:
        lines.append("延迟：成功样本中未能解析 RTT 数值。")
    if p.attempted and p.received == 0:
        lines.append(
            "说明：无 ICMP 回复时，常见于对端禁 ping 或防火墙策略，不代表 TCP 端口一定不通。"
        )
    return lines


def _gui_lines_traceroute(rep: DiagnosticReport) -> list[str]:
    ui = rep.user_input
    if not ui.enable_traceroute:
        return [
            "本轮未启用路由追踪。",
            "可在「探测选项」中勾选「路由追踪」，将调用 Windows tracert（或 Linux/macOS 的 traceroute）。",
        ]
    tr = rep.traceroute
    if tr is None:
        return ["未获取到路由追踪输出。"]
    out = list((tr.outline or "").splitlines())
    if tr.command:
        out.insert(0, f"命令：{' '.join(tr.command)}")
    if tr.returncode is not None:
        out.append(f"退出码：{tr.returncode}")
    out.append(f"原始 stdout：{tr.raw_stdout_path.resolve()}")
    return out


def _gui_lines_ports(rep: DiagnosticReport) -> list[str]:
    ui = rep.user_input
    degrad_tcping = any(d.code == "tcping_missing" for d in rep.degradations)
    if not ui.ports:
        return ["未填写 TCP 端口，已跳过端口连通性探测。"]
    if not rep.ports:
        if degrad_tcping:
            return [
                "已填写端口，但未找到 tcping.exe，无法执行探测。",
                "请将 tcping.exe 置于 ThirdParty/tcping/ 后重试。",
            ]
        return ["未能得到端口探测结果。"]
    lines: list[str] = []
    for pr in rep.ports:
        ok_n = sum(1 for s in pr.samples if s.success)
        tot = max(len(pr.samples), 1)
        rtts = [s.rtt_ms for s in pr.samples if s.success and s.rtt_ms is not None]
        verdict = _PORT_CLASS_CN.get(pr.failure_class, pr.failure_class.value)
        if pr.failure_class == PortFailureClass.OK:
            detail = f"{ok_n}/{tot} 次成功"
            if rtts:
                detail += f"，平均延迟 {sum(rtts) / len(rtts):.1f} ms"
            lines.append(f"端口 {pr.port}：{verdict}（{detail}）。目标 {pr.target_used}")
        else:
            lines.append(
                f"端口 {pr.port}：{verdict}（成功 {ok_n}/{tot}）。目标 {pr.target_used}"
            )
    return lines


def _gui_lines_capture(rep: DiagnosticReport) -> list[str]:
    ui = rep.user_input
    c = rep.capture
    if not ui.enable_capture:
        return [
            "本轮未启用抓包。",
            "如需抓包，请勾选「抓包」，并确保本机已安装 Wireshark/tshark 与 Npcap。",
        ]
    if c.ran and c.pcap_path is not None:
        lines = [
            "抓包已完成。",
            f"文件：{c.pcap_path}",
        ]
        if c.notes:
            lines.append(c.notes)
        if c.analysis_summary:
            lines.append("")
            lines.append("（以下为抓包内容的通俗解读，由程序根据统计自动生成）")
            lines.extend(c.analysis_summary.splitlines())
        return lines
    lines: list[str] = ["本次未能完成抓包。"]
    if c.notes:
        lines.append(c.notes)
    for d in rep.degradations:
        if d.code in ("capture_unavailable", "tshark_start_failed") and d.detail:
            lines.append(f"补充说明：{d.detail}")
            break
    return lines


def _gui_lines_bandwidth(rep: DiagnosticReport) -> list[str]:
    ui = rep.user_input
    b = rep.bandwidth
    if ui.bandwidth_mode == "off":
        return [
            "本轮未启用带宽/吞吐抽样。",
            "需要时请在左侧选择「HTTP 抽样下载」或「iperf3」（二选一）。",
        ]
    if b is None:
        return ["未得到带宽抽样结果。"]
    lines = [b.summary]
    if b.megabits_per_second is not None:
        lines.append(f"估算平均速率：约 {b.megabits_per_second:.1f} Mbps")
    if b.bytes_total is not None:
        lines.append(f"传输字节（如适用）：{b.bytes_total}")
    if b.parallel_streams is not None:
        lines.append(f"HTTP 并发连接数：{b.parallel_streams}")
    if b.log_stdout_path:
        lines.append(f"详细日志：{b.log_stdout_path}")
    if not b.ok and b.error:
        lines.append(f"错误：{b.error}")
    return lines


def _any_advanced(rep: DiagnosticReport) -> bool:
    ui = rep.user_input
    return bool(
        (ui.optional_dns_server or "").strip()
        or ui.enable_pathping
        or ui.enable_tcp_traceroute
        or ui.enable_http_tls_probe
        or ui.enable_egress_probe
        or ui.enable_mtu_probe
        or ui.enable_history_compare
    )


def _gui_oneline_advanced(rep: DiagnosticReport) -> str:
    ui = rep.user_input
    bits: list[str] = []
    if (ui.optional_dns_server or "").strip():
        ds = rep.dns_specified
        if ds and not ds.error and ds.addresses:
            bits.append("指定 DNS 解析成功")
        elif ds and ds.error:
            bits.append("指定 DNS 解析失败")
        else:
            bits.append("已请求指定 DNS 对比")
    if ui.enable_pathping and rep.path_quality:
        bits.append("PathPing/mtr 已完成")
    elif ui.enable_pathping:
        bits.append("PathPing/mtr 无输出")
    if ui.enable_tcp_traceroute and rep.tcp_path:
        bits.append("TCP 路径探测已完成")
    elif ui.enable_tcp_traceroute:
        bits.append("TCP 路径探测无输出")
    if ui.enable_http_tls_probe and rep.http_tls:
        h = rep.http_tls
        if h.ok:
            bits.append("HTTPS/TLS 正常")
        else:
            bits.append("HTTPS/TLS 异常或未完整")
    elif ui.enable_http_tls_probe:
        bits.append("HTTPS/TLS 无结果")
    if ui.enable_egress_probe and rep.egress:
        e = rep.egress
        if e.public_ip:
            bits.append(f"出口公网 IP {e.public_ip}")
        else:
            bits.append("出口 IP 未取到")
    elif ui.enable_egress_probe:
        bits.append("出口探测无结果")
    if ui.enable_mtu_probe and rep.mtu:
        m = rep.mtu
        if m.implied_ipv4_mtu is not None:
            bits.append(f"估算 MTU {m.implied_ipv4_mtu}")
        else:
            bits.append("MTU 未估出或已跳过")
    elif ui.enable_mtu_probe:
        bits.append("MTU 无结果")
    if ui.enable_history_compare and rep.history_compare:
        hc = rep.history_compare
        if hc.compared and hc.previous_grade:
            bits.append(f"相对上次档位：{hc.previous_grade} → {rep.network_quality.grade}")
        elif hc.lines:
            bits.append("历史：首次或无更早记录")
    elif ui.enable_history_compare:
        bits.append("历史对比未生成")
    if not bits:
        return "未启用进阶项。"
    return "；".join(bits) + "。"


def _gui_lines_advanced(rep: DiagnosticReport) -> list[str]:
    ui = rep.user_input
    out: list[str] = []
    opt_srv = (ui.optional_dns_server or "").strip()
    if opt_srv:
        ds = rep.dns_specified
        out.append(f"指定 DNS：{opt_srv}")
        if ds is None:
            out.append("  （无独立解析结果）")
        elif ds.error:
            out.append(f"  错误：{ds.error}")
        else:
            out.append(f"  地址：{'、'.join(ds.addresses) if ds.addresses else '（无）'}，{ds.elapsed_ms:.1f} ms")
        out.append("")

    def _shell_block(title: str, sp, enabled: bool) -> None:
        if not enabled:
            return
        if sp is None:
            out.append(f"{title}：未得到结果。")
            out.append("")
            return
        out.append(f"{title}：{sp.summary}")
        out.append(f"  命令：{' '.join(sp.command) if sp.command else '—'}")
        out.append(f"  日志：{sp.raw_stdout_path.resolve()}")
        out.append("")

    _shell_block("路径质量（PathPing/mtr）", rep.path_quality, ui.enable_pathping)
    _shell_block("TCP 路径", rep.tcp_path, ui.enable_tcp_traceroute)

    if ui.enable_http_tls_probe:
        h = rep.http_tls
        if h is None:
            out.append("HTTPS/TLS：无结果。")
        else:
            out.append(f"HTTPS/TLS：URL {h.url}")
            if h.tls_handshake_ms is not None:
                out.append(f"  握手约 {h.tls_handshake_ms:.0f} ms")
            if h.http_status is not None:
                out.append(f"  HTTP 状态：{h.http_status}")
            out.append(f"  证书主体：{h.cert_subject or '—'}，有效期至 {h.cert_not_after or '—'}")
            if h.error:
                out.append(f"  错误：{h.error}")
        out.append("")

    if ui.enable_egress_probe:
        e = rep.egress
        if e is None:
            out.append("出口/代理：无结果。")
        else:
            out.append(f"出口公网 IPv4：{e.public_ip or '（未获取）'}")
            if e.ipify_error:
                out.append(f"  查询：{e.ipify_error}")
            proxy_bits = [
                ("HTTP_PROXY", e.http_proxy),
                ("HTTPS_PROXY", e.https_proxy),
                ("ALL_PROXY", e.all_proxy),
            ]
            for k, v in proxy_bits:
                if v:
                    out.append(f"  {k}={v}")
            if e.winhttp_note:
                out.append(f"  WinHTTP：{e.winhttp_note}")
        out.append("")

    if ui.enable_mtu_probe:
        m = rep.mtu
        if m is None:
            out.append("MTU：无结果。")
        else:
            out.append(f"MTU：{m.summary}")
            if m.implied_ipv4_mtu is not None:
                out.append(f"  推算 IPv4 MTU：{m.implied_ipv4_mtu}")
            if m.raw_log_path:
                out.append(f"  日志：{m.raw_log_path.resolve()}")
        out.append("")

    if ui.enable_history_compare:
        hc = rep.history_compare
        if hc is None:
            out.append("历史对比：未生成（已关闭或未写入）。")
        else:
            out.extend(hc.lines)
        out.append("")

    if not out:
        return ["本轮未启用进阶探测（未勾选进阶项且未填写指定 DNS）。"]
    return out


def _blend_hex(hex_a: str, hex_b: str, t: float) -> str:
    """线性混合两个 #RRGGBB 颜色，t 为 hex_b 的权重（0–1）。"""

    def _rgb(h: str) -> tuple[int, int, int]:
        h = h.strip().lstrip("#")
        if len(h) != 6:
            return (13, 110, 253)
        return tuple(int(h[i : i + 2], 16) for i in (0, 2, 4))  # type: ignore[misc]

    ar, ag, ab = _rgb(hex_a)
    br, bg, bb = _rgb(hex_b)
    t = max(0.0, min(1.0, t))
    r = int(ar + (br - ar) * t)
    g = int(ag + (bg - ag) * t)
    b = int(ab + (bb - ab) * t)
    return f"#{r:02x}{g:02x}{b:02x}"
