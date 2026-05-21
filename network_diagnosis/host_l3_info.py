"""本机 IPv4 接口信息（Windows：优先 ipconfig /all，WMI/CIM 为备选）。"""

from __future__ import annotations

import json
import re
import socket
import subprocess
import sys
from dataclasses import dataclass

from network_diagnosis.arp_monitor import normalize_mac

# CIM 在部分环境（WMI 繁忙、虚拟网卡多、安全软件拦截）易长时间阻塞；超时后回退 ipconfig。
_CIM_TIMEOUT_SEC = 12
_CIM_OPERATION_TIMEOUT_SEC = 8
_IPCONFIG_TIMEOUT_SEC = 35


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


def _decode_output(data: bytes) -> str:
    if sys.platform == "win32":
        encodings = ("gbk", "cp936", "utf-8-sig", "utf-8")
    else:
        encodings = ("utf-8-sig", "utf-8", "gbk", "cp936")
    for enc in encodings:
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _is_adapter_section_header(line: str) -> bool:
    s = line.strip()
    if not s.endswith(":"):
        return False
    if "Windows IP" in s or "主机名" in s or "Host Name" in s.lower():
        return False
    low = s.lower()
    return "adapter" in low or "适配器" in s


def _extract_ipv4_from_value_line(line: str) -> str | None:
    m = re.search(r":\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})", line)
    if not m:
        return None
    ip = m.group(1).strip()
    return ip if _is_ipv4(ip) else None


def _parse_ipconfig_all(text: str) -> list[AdapterIPv4Block]:
    """从 ``ipconfig /all`` 文本解析 IPv4 块（中英文 Windows）。"""
    re_desc = re.compile(r"(?:Description|描述).*[\.:]+\s*(.+)$", re.I)
    re_mac = re.compile(r"(?:Physical Address|物理地址).*[\.:]+\s*([0-9A-Fa-f\-]+)", re.I)
    re_dns = re.compile(r"(?:DNS Servers|DNS 服务器).*[\.:]+\s*([0-9.]+)", re.I)
    re_dns_cont = re.compile(r"^\s{4,}([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s*$")

    blocks: list[AdapterIPv4Block] = []
    title = ""
    desc = ""
    mac: str | None = None
    mask = ""
    gateways: list[str] = []
    dns_servers: list[str] = []
    pending_ips: list[str] = []

    def flush() -> None:
        nonlocal title, desc, mac, mask, gateways, dns_servers, pending_ips
        if not pending_ips:
            title = ""
            desc = ""
            mac = None
            mask = ""
            gateways = []
            dns_servers = []
            return
        name = (desc or title or "（未命名网卡）").strip()
        gw_t = tuple(gateways)
        dns_t = tuple(dns_servers)
        mac_n = normalize_mac(mac) if mac else None
        for ip in pending_ips:
            blocks.append(
                AdapterIPv4Block(
                    description=name,
                    mac=mac_n,
                    ipv4=ip,
                    netmask=mask if _is_ipv4(mask) else "—",
                    gateways=gw_t,
                    dns_servers=dns_t,
                )
            )
        title = ""
        desc = ""
        mac = None
        mask = ""
        gateways = []
        dns_servers = []
        pending_ips = []

    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r")
        if _is_adapter_section_header(line):
            flush()
            title = line.strip()[:-1].strip()
            continue
        if not title:
            continue
        m = re_desc.search(line)
        if m:
            desc = m.group(1).strip()
            continue
        m = re_mac.search(line)
        if m:
            mac = m.group(1).strip()
            continue
        low = line.lower()
        if "ipv4" in low:
            ip = _extract_ipv4_from_value_line(line)
            if ip:
                pending_ips.append(ip)
            continue
        if "subnet mask" in low or "子网掩码" in line:
            ip = _extract_ipv4_from_value_line(line)
            if ip:
                mask = ip
            continue
        if ("default gateway" in low or "默认网关" in line) and ":" in line:
            ip = _extract_ipv4_from_value_line(line)
            if ip and ip not in gateways:
                gateways.append(ip)
            continue
        m = re_dns.search(line)
        if m:
            d = m.group(1).strip()
            if _is_ipv4(d) and d not in dns_servers:
                dns_servers.append(d)
            continue
        m = re_dns_cont.match(line)
        if m:
            d = m.group(1).strip()
            if _is_ipv4(d) and d not in dns_servers:
                dns_servers.append(d)
            continue
        if pending_ips and not mask and re.search(r":\s*255\.", line):
            ip = _extract_ipv4_from_value_line(line)
            if ip and ip.startswith("255."):
                mask = ip

    flush()
    return blocks


def _windows_list_adapters_via_ipconfig() -> list[AdapterIPv4Block] | str:
    try:
        pr = subprocess.run(
            ["ipconfig", "/all"],
            capture_output=True,
            timeout=_IPCONFIG_TIMEOUT_SEC,
            encoding="gbk",
            errors="replace",
            creationflags=_creationflags_no_window(),
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"执行 ipconfig /all 失败：{e}"
    text = (pr.stdout or "") + (pr.stderr or "")
    if not text.strip():
        return "ipconfig /all 无输出。"
    blocks = _parse_ipconfig_all(text)
    if not blocks:
        return "ipconfig /all 未解析到任何 IPv4 地址。"
    return blocks


def _windows_list_adapters_via_cim() -> list[AdapterIPv4Block] | str:
    ps = (
        f"$cfg = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration "
        f"-Filter 'IPEnabled=True' -OperationTimeoutSec {_CIM_OPERATION_TIMEOUT_SEC}; "
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
            timeout=_CIM_TIMEOUT_SEC,
            creationflags=_creationflags_no_window(),
        )
    except subprocess.TimeoutExpired:
        return "WMI/CIM 查询超时"
    except OSError as e:
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
        elif mac_s:
            mac_s = normalize_mac(mac_s)

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

    if not blocks:
        return "WMI 未返回任何 IPv4 地址。"
    return blocks


def list_local_ipv4_adapters() -> tuple[list[AdapterIPv4Block], str | None]:
    """
    返回 `(适配器块列表, 提示信息)`。
    非 Windows 下列表为空，提示信息说明限制。
    """
    if sys.platform != "win32":
        return [], "非 Windows 系统：当前未采集网卡列表（可在终端使用系统命令查看）。"

    ipcfg = _windows_list_adapters_via_ipconfig()
    if isinstance(ipcfg, list):
        return ipcfg, None

    cim = _windows_list_adapters_via_cim()
    if isinstance(cim, list):
        return cim, f"ipconfig /all 不可用（{ipcfg}），已改用 WMI/CIM 读取本机网卡。"

    return [], f"读取本机网卡失败：ipconfig：{ipcfg}；WMI/CIM：{cim}"


def local_hostname() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "—"
