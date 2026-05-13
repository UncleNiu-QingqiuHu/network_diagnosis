"""本机网卡、网关、DNS 等上下文（Windows ipconfig /all）。"""

from __future__ import annotations

import re
from pathlib import Path

from network_diagnosis.model.report import AdapterInfo, LocalContext
from network_diagnosis.probes.subproc_util import read_text_best_effort, run_to_log_files


def _parse_ipconfig(text: str) -> tuple[list[AdapterInfo], str]:
    adapters: list[AdapterInfo] = []
    current: AdapterInfo | None = None

    def flush() -> None:
        nonlocal current
        if current is not None:
            adapters.append(current)
            current = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            continue
        if line.startswith("Windows IP Configuration"):
            continue
        # 适配器节标题（中文/英文环境）
        if re.match(r"^(Ethernet adapter|无线局域网适配器|以太网适配器|WLAN|VMware|蓝牙网络)", line):
            flush()
            name = line.split(":", 1)[0].strip()
            current = AdapterInfo(name=name, description="", enabled=True)
            continue
        if current is None:
            continue
        low = line.lower()
        if "media state" in low or "媒体状态" in line:
            if ". . . . . . . . . . . . . : media disconnected" in low or "媒体已断开连接" in line:
                current.enabled = False
        m = re.search(
            r"(IPv4 Address|IPv4 地址)\s*[\.:]+\s*([0-9.]+)",
            line,
            re.I,
        )
        if m:
            ip = m.group(2).split("%")[0].strip()
            if ip and ip not in current.ipv4:
                current.ipv4.append(ip)
        m = re.search(r"(IPv6 Address|IPv6 地址)\s*[\.:]+\s*([0-9a-fA-F:%]+)", line, re.I)
        if m:
            ip = m.group(2).strip()
            if ip and ip not in current.ipv6:
                current.ipv6.append(ip)
        m = re.search(r"(Default Gateway|默认网关)\s*[\.:]+\s*([0-9.:]+)", line, re.I)
        if m:
            g = m.group(2).strip()
            if g and g not in current.gateways:
                current.gateways.append(g)
        m = re.search(r"(DNS Servers|DNS 服务器)\s*[\.:]+\s*([0-9.:]+)", line, re.I)
        if m:
            d = m.group(2).strip()
            if d and d not in current.dns_servers:
                current.dns_servers.append(d)
        # 续行 DNS
        if re.match(r"^\s{4,}[0-9.:\[]", line) and current.dns_servers:
            token = line.strip()
            if re.match(r"^[0-9.:\[]", token) and token not in current.dns_servers:
                current.dns_servers.append(token)

    flush()
    note = (
        "以下信息来自 ipconfig /all 解析；若存在多网卡、VPN 或代理，"
        "探测路径仅代表当前系统路由选路下的结果。"
    )
    return adapters, note


def collect_local_context(log_dir: Path) -> LocalContext:
    stem = "ipconfig_all"
    r = run_to_log_files(
        ["ipconfig", "/all"],
        log_dir,
        stem,
        timeout_sec=60,
    )
    text = read_text_best_effort(r.stdout_path)
    adapters, note = _parse_ipconfig(text)
    return LocalContext(
        note=note,
        adapters=adapters,
        raw_ipconfig_path=r.stdout_path,
    )
