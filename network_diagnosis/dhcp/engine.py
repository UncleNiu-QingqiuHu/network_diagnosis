"""DHCP 诊断结论引擎与任务编排。"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import datetime
from threading import Event

from network_diagnosis.arp_monitor import ipv4_interface_network
from network_diagnosis.dhcp.client import (
    evaluate_client_health,
    fetch_dhcp_client_event_log,
    parse_dhcp_client_snapshots,
    pick_client_for_interface,
    run_ipconfig_all_text,
)
from network_diagnosis.dhcp.models import (
    DhcpClientSnapshot,
    DhcpDiagnosisResult,
    DhcpOffer,
    DhcpProbeRound,
    Severity,
    VerdictCode,
)
from network_diagnosis.dhcp.probe import resolve_nmap_exe, run_dhcp_probe_rounds
from network_diagnosis.dhcp.report_md import write_dhcp_diagnosis_report
from network_diagnosis.paths import dhcp_diagnosis_report_dir


def _offers_signature(offer: DhcpOffer) -> tuple[str, str | None, str | None, tuple[str, ...]]:
    return (offer.server_id, offer.router, offer.subnet_mask, offer.dns)


def _all_offers(rounds: list[DhcpProbeRound]) -> list[DhcpOffer]:
    seen: set[str] = set()
    out: list[DhcpOffer] = []
    for r in rounds:
        for o in r.offers:
            if o.server_id in seen:
                continue
            seen.add(o.server_id)
            out.append(o)
    return out


def _is_ha_pair(offers: list[DhcpOffer], whitelist: set[str]) -> bool:
    if len(offers) < 2:
        return False
    if not all(o.server_id in whitelist for o in offers):
        return False
    sigs = {_offers_signature(o) for o in offers}
    routers = {o.router for o in offers if o.router}
    dns_sets = {o.dns for o in offers}
    masks = {o.subnet_mask for o in offers if o.subnet_mask}
    if len(sigs) == 1:
        return True
    if len(routers) <= 1 and len(dns_sets) <= 1 and len(masks) <= 1:
        return True
    return False


def compute_verdict(
    clients: list[DhcpClientSnapshot],
    rounds: list[DhcpProbeRound],
    authorized_servers: tuple[str, ...],
    *,
    probe_ran: bool,
) -> tuple[VerdictCode, Severity, list[str], list[str]]:
    conclusions: list[str] = []
    recommendations: list[str] = []
    whitelist = {s.strip() for s in authorized_servers if s.strip()}

    all_offers = _all_offers(rounds)
    max_distinct = max((r.distinct_server_count for r in rounds), default=0)
    if not max_distinct and all_offers:
        max_distinct = len({o.server_id for o in all_offers})

    client_flags = {f for c in clients for f in c.health_flags}

    if probe_ran:
        if max_distinct >= 2:
            ids = "、".join(o.server_id for o in all_offers)
            if whitelist and _is_ha_pair(all_offers, whitelist):
                conclusions.append(
                    f"探测到 {max_distinct} 个 DHCP 服务器（{ids}），均在白名单且分配选项一致，可能为双机热备。"
                )
                recommendations.append("若网络设计为 DHCP 热备，可忽略；否则请复核第二台服务器身份。")
                return "MULTIPLE_DHCP_SERVERS_HA", "info", conclusions, recommendations
            conclusions.append(f"疑似 DHCP 污染：探测到 {max_distinct} 个不同 Server Identifier（{ids}）。")
            rogue = [o for o in all_offers if whitelist and o.server_id not in whitelist]
            if rogue:
                bad = "、".join(o.server_id for o in rogue)
                conclusions.append(f"以下服务器不在白名单：{bad}。")
                recommendations.append(f"在交换机上定位非法 DHCP 服务器 {bad} 的 MAC/接入端口并隔离。")
            else:
                recommendations.append("在交换机上分别核对各 Server ID 对应设备，确认是否存在私自开启 DHCP 的路由/AP。")
            recommendations.append("可使用 MAC 扫描对非法 Server ID 所在 IP 做 ARP 摸底。")
            return "MULTIPLE_DHCP_SERVERS", "high", conclusions, recommendations

        if max_distinct == 1:
            o = all_offers[0]
            if whitelist and o.server_id not in whitelist:
                conclusions.append(f"发现 DHCP 服务器 {o.server_id}，不在白名单内。")
                recommendations.append("与网管确认该 DHCP 服务器是否为合法设备。")
                return "UNKNOWN_DHCP_SERVER", "medium", conclusions, recommendations
            conclusions.append(f"仅发现 1 个 DHCP 服务器响应（{o.server_id}）。")

        if max_distinct == 0 and probe_ran:
            had_error = any(r.error for r in rounds)
            if not had_error:
                conclusions.append("DHCP 探测未收到 OFFER（可能无 DHCP 服务、跨 VLAN 或需管理员权限运行 Nmap）。")
                recommendations.append("确认本机与 DHCP 服务器在同一广播域；必要时以管理员身份运行本程序并重试。")
                return "NO_DHCP_OFFERS", "medium", conclusions, recommendations

    if "APIPA" in client_flags:
        conclusions.append("本机存在 APIPA 地址（169.254.x.x），通常表示未从 DHCP 获得有效地址。")
        recommendations.append("检查网线/VLAN、DHCP 服务是否启用、作用域是否耗尽。")
    if "LEASE_EXPIRED" in client_flags:
        conclusions.append("本机 DHCP 租约已过期。")
        recommendations.append("尝试 ipconfig /renew 或检查 DHCP 服务器。")
    if "DHCP_SERVER_UNREACHABLE" in client_flags:
        conclusions.append("本机记录的 DHCP 服务器 Ping 不通。")
        recommendations.append("检查三层连通性与 DHCP 服务进程。")
    if "STATIC_ON_DHCP_SCOPE" in client_flags:
        conclusions.append("本机静态 IP 落在 DHCP 作用域内，存在地址冲突风险。")
        recommendations.append("将静态 IP 移出 DHCP 池，或在 DHCP 上保留绑定。")

    if conclusions and not probe_ran:
        return "CLIENT_ISSUES", "medium", conclusions, recommendations
    if conclusions:
        return "CLIENT_ISSUES", "medium", conclusions, recommendations
    if not probe_ran:
        return "PROBE_SKIPPED", "info", ["未执行 DHCP 主动探测（未授权或未找到 Nmap）。"], []
    return "OK", "info", ["本机 DHCP 客户端与 DHCP 服务探测未发现明显异常。"], []


def run_dhcp_diagnosis(
    *,
    interface_ipv4: str,
    authorized_servers: tuple[str, ...],
    scope_cidr: str = "",
    probe_enabled: bool = True,
    probe_rounds: int = 3,
    probe_timeout_sec: int = 10,
    nmap_exe_path: str = "",
    cancel_event: Event | None = None,
    on_progress: Callable[[str], None] | None = None,
    on_round: Callable[[DhcpProbeRound], None] | None = None,
) -> DhcpDiagnosisResult:
    def prog(msg: str) -> None:
        if on_progress is not None:
            on_progress(msg)

    task_id = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:8]
    ts = datetime.now()

    prog("正在读取 ipconfig /all …")
    ipconfig_text, ipconfig_err = run_ipconfig_all_text()
    if ipconfig_err or not ipconfig_text.strip():
        raise RuntimeError(ipconfig_err or "无法读取 ipconfig /all")

    clients_raw = parse_dhcp_client_snapshots(ipconfig_text)
    scope = scope_cidr.strip() or None
    clients = [evaluate_client_health(c, scope_cidr=scope) for c in clients_raw]

    selected = pick_client_for_interface(clients, interface_ipv4)
    netmask = selected.netmask if selected else "—"
    net = ipv4_interface_network(interface_ipv4, netmask) if selected else None
    network_cidr = net.with_prefixlen if net else None

    prog("正在读取 DHCP 客户端事件日志 …")
    events_text, _ev_err = fetch_dhcp_client_event_log()

    rounds: list[DhcpProbeRound] = []
    probe_error: str | None = None
    probe_skipped: str | None = None
    probe_ran = False
    nmap_combined = ""

    if probe_enabled:
        nmap_exe = resolve_nmap_exe(nmap_exe_path)
        if not nmap_exe:
            probe_skipped = "未找到 nmap.exe，已跳过 DHCP 主动探测。请安装 Nmap 或使用「检测 Nmap」。"
            prog(probe_skipped)
        else:
            probe_ran = True
            prog(f"正在执行 DHCP 探测（Nmap broadcast-dhcp-discover，{probe_rounds} 轮）…")
            rounds, probe_error = run_dhcp_probe_rounds(
                nmap_exe=nmap_exe,
                interface_ipv4=interface_ipv4,
                authorized_servers=authorized_servers,
                rounds=probe_rounds,
                round_timeout_sec=probe_timeout_sec,
                cancel_event=cancel_event,
                on_round=on_round,
            )
            nmap_combined = "\n\n".join(
                f"=== 轮次 {r.round_index} ===\n{r.raw_output}" for r in rounds if r.raw_output
            )
    else:
        probe_skipped = "未勾选授权或未启用主动探测。"

    verdict, severity, conclusions, recommendations = compute_verdict(
        clients,
        rounds,
        authorized_servers,
        probe_ran=probe_ran,
    )

    result = DhcpDiagnosisResult(
        task_id=task_id,
        timestamp=ts,
        interface_ipv4=interface_ipv4,
        network_cidr=network_cidr,
        authorized_servers=authorized_servers,
        scope_cidr=scope,
        clients=clients,
        probe_rounds=rounds,
        verdict=verdict,
        severity=severity,
        conclusions=conclusions,
        recommendations=recommendations,
        ipconfig_excerpt=ipconfig_text[:12000],
        event_log_excerpt=events_text,
        nmap_combined_output=nmap_combined,
        probe_error=probe_error,
        probe_skipped_reason=probe_skipped,
    )

    out_dir = dhcp_diagnosis_report_dir(task_id)
    write_dhcp_diagnosis_report(result, out_dir)
    prog(f"报告已写入 {out_dir}")
    return result
