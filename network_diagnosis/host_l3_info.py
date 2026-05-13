"""本机 IPv4 接口信息（Windows 优先通过 WMI/CIM；可复用出口探测）。"""

from __future__ import annotations

import json
import re
import socket
import subprocess
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class AdapterIPv4Block:
    """一块在网卡上的 IPv4 配置（同一网卡多地址时多条）。"""

    description: str
    mac: str | None
    ipv4: str
    netmask: str
    gateways: tuple[str, ...]
    dns_servers: tuple[str, ...]


def _creationflags_no_window() -> int:
    if sys.platform != "win32":
        return 0
    try:
        return subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
    except AttributeError:
        return 0


_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)


def _is_ipv4(s: str | None) -> bool:
    return bool(s and isinstance(s, str) and _IPV4_RE.match(s.strip()))


def _windows_list_adapters_via_cim() -> list[AdapterIPv4Block] | str:
    ps = (
        "$cfg = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled }; "
        "$cfg | Select-Object Description, MACAddress, IPAddress, IPSubnet, "
        "DefaultIPGateway, DNSServerSearchOrder | ConvertTo-Json -Depth 6 -Compress"
    )
    try:
        pr = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=25,
            creationflags=_creationflags_no_window(),
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"执行 PowerShell 查询失败：{e}"
    raw = (pr.stdout or "").strip()
    if not raw:
        err = (pr.stderr or "").strip()
        return f"未得到 WMI 输出{('：' + err) if err else '。'}"

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        return f"解析 WMI JSON 失败：{e}"

    rows: list[dict]
    if isinstance(data, dict):
        rows = [data]
    elif isinstance(data, list):
        rows = [x for x in data if isinstance(x, dict)]
    else:
        return "WMI 返回格式无法识别。"

    blocks: list[AdapterIPv4Block] = []
    for row in rows:
        desc = str(row.get("Description") or "").strip() or "（未命名网卡）"
        mac = row.get("MACAddress")
        mac_s = str(mac).strip() if mac else None
        if mac_s == "":
            mac_s = None

        ips = row.get("IPAddress") or []
        subs = row.get("IPSubnet") or []
        if not isinstance(ips, list):
            ips = [ips]
        if not isinstance(subs, list):
            subs = [subs]

        gw_raw = row.get("DefaultIPGateway") or []
        if not isinstance(gw_raw, list):
            gw_raw = [gw_raw]
        gateways = tuple(str(x).strip() for x in gw_raw if _is_ipv4(str(x).strip()))

        dns_raw = row.get("DNSServerSearchOrder") or []
        if not isinstance(dns_raw, list):
            dns_raw = [dns_raw]
        dns_servers = tuple(str(x).strip() for x in dns_raw if _is_ipv4(str(x).strip()))

        for i, ip in enumerate(ips):
            sip = str(ip).strip() if ip is not None else ""
            if not _is_ipv4(sip):
                continue
            sm = ""
            if i < len(subs) and subs[i] is not None:
                sm = str(subs[i]).strip()
            if not _is_ipv4(sm):
                sm = "—"
            blocks.append(
                AdapterIPv4Block(
                    description=desc,
                    mac=mac_s,
                    ipv4=sip,
                    netmask=sm,
                    gateways=gateways,
                    dns_servers=dns_servers,
                )
            )

    return blocks


def list_local_ipv4_adapters() -> tuple[list[AdapterIPv4Block], str | None]:
    """
    返回 `(适配器块列表, 提示信息)`。
    非 Windows 下列表为空，提示信息说明限制。
    """
    if sys.platform != "win32":
        return [], "非 Windows 系统：当前未采集网卡列表（可在终端使用系统命令查看）。"
    got = _windows_list_adapters_via_cim()
    if isinstance(got, str):
        return [], got
    return got, None


def local_hostname() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "—"
