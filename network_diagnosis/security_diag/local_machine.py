"""本机扩展诊断：CPU/GPU、内存、本地用户与密码策略、临时文件清理预览与执行（Windows 为主）。"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from network_diagnosis.security_diag.collect import _decode_console_bytes, _parse_ps_json, _run_powershell


def _markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    if not headers:
        return ""

    def _esc_cell(val: object) -> str:
        return str(val).replace("|", "｜")

    lines = [
        "| " + " | ".join(_esc_cell(h) for h in headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for r in rows:
        pad = list(r) + [""] * (len(headers) - len(r))
        lines.append("| " + " | ".join(_esc_cell(pad[i]) for i in range(len(headers))) + " |")
    return "\n".join(lines) + "\n"


def _nvidia_smi_append() -> str:
    import shutil

    exe = shutil.which("nvidia-smi")
    if not exe:
        return ""
    try:
        r = subprocess.run(
            [
                exe,
                "--query-gpu=name,driver_version,utilization.gpu,memory.used,memory.total,temperature.gpu",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            timeout=25,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,  # type: ignore[arg-type]
        )
        txt = (r.stdout or b"").decode("utf-8", errors="replace").strip()
        if not txt:
            return ""
        hdr = "| GPU | 驱动 | GPU利用率% | 显存已用 MiB | 显存总计 MiB | 温度°C |"
        sep = "| --- | --- | ---:| ---:| ---:| ---:|"
        lines = ["### NVIDIA GPU（nvidia-smi）", "", hdr, sep]
        for ln in txt.splitlines():
            parts = [p.strip() for p in ln.split(",")]
            while len(parts) < 6:
                parts.append("")
            lines.append(f"| {parts[0]} | {parts[1]} | {parts[2]} | {parts[3]} | {parts[4]} | {parts[5]} |")
        return "\n".join(lines) + "\n\n"
    except (OSError, subprocess.TimeoutExpired):
        return ""


def collect_cpu_gpu_markdown() -> str:
    if sys.platform != "win32":
        return "## CPU / GPU\n\n当前实现依赖 Windows WMI/CIM，请在 Windows 上使用。\n"

    ps = r"""
$ProgressPreference='SilentlyContinue'
$ErrorActionPreference='SilentlyContinue'
$proc = @(Get-CimInstance Win32_Processor | ForEach-Object {
  [PSCustomObject]@{
    Name = [string]$_.Name
    Manufacturer = [string]$_.Manufacturer
    NumberOfCores = [int]$_.NumberOfCores
    NumberOfLogicalProcessors = [int]$_.NumberOfLogicalProcessors
    MaxClockMHz = [int]$_.MaxClockSpeed
    LoadPercentage = if ($null -ne $_.LoadPercentage) { [int]$_.LoadPercentage } else { $null }
  }
})
$cores = @(Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor |
  Where-Object { $_.Name -ne '_Total' } |
  ForEach-Object {
    [PSCustomObject]@{
      Index = [string]$_.Name
      PercentProcessorTime = [int]$_.PercentProcessorTime
    }
  } | Sort-Object { try { [int]$_.Index } catch { 999 } })
$gpu = @(Get-CimInstance Win32_VideoController | ForEach-Object {
  [PSCustomObject]@{
    Name = [string]$_.Name
    DriverVersion = [string]$_.DriverVersion
    DriverDate = if ($_.DriverDate) { $_.DriverDate.ToString('yyyy-MM-dd') } else { '' }
    AdapterRAMBytes = if ($_.AdapterRAM -and $_.AdapterRAM -gt 0) { [int64]$_.AdapterRAM } else { $null }
    Status = [string]$_.Status
    VideoModeDescription = [string]$_.VideoModeDescription
  }
})
[PSCustomObject]@{ Processors = $proc; LogicalCores = $cores; VideoControllers = $gpu } |
  ConvertTo-Json -Depth 8 -Compress
"""
    raw = _run_powershell(ps, timeout=120)
    try:
        data = _parse_ps_json(raw)
    except Exception:
        return "## CPU / GPU\n\n采集失败（JSON 解析）：\n\n```\n" + raw[:6000] + "\n```\n"

    lines: list[str] = ["## CPU / GPU", ""]

    if not isinstance(data, dict):
        lines.append("（无结构化数据）\n")
        return "\n".join(lines)

    plist = data.get("Processors") or []
    if isinstance(plist, dict):
        plist = [plist]
    if plist:
        lines.append("### 处理器摘要\n\n")
        hdr = ["型号", "厂商", "物理核心", "逻辑处理器", "最大频率 MHz", "负载 %"]
        rows = []
        for p in plist:
            if not isinstance(p, dict):
                continue
            rows.append(
                [
                    p.get("Name", ""),
                    p.get("Manufacturer", ""),
                    p.get("NumberOfCores", ""),
                    p.get("NumberOfLogicalProcessors", ""),
                    p.get("MaxClockMHz", ""),
                    p.get("LoadPercentage", "—") if p.get("LoadPercentage") is not None else "—",
                ]
            )
        lines.append(_markdown_table(hdr, rows))

    clist = data.get("LogicalCores") or []
    if isinstance(clist, dict):
        clist = [clist]
    if clist:
        lines.append("### 各逻辑处理器占用（Win32_PerfFormattedData_PerfOS_Processor）\n\n")
        lines.append(
            "> 说明：以下为采样时刻的近似利用率；与任务管理器可能存在短时差异。\n\n"
        )
        hdr = ["逻辑 CPU 索引", "利用率 %"]
        rows = [[c.get("Index", ""), str(c.get("PercentProcessorTime", ""))] for c in clist if isinstance(c, dict)]
        lines.append(_markdown_table(hdr, rows))

    vlist = data.get("VideoControllers") or []
    if isinstance(vlist, dict):
        vlist = [vlist]
    if vlist:
        lines.append("### 显示适配器（WMI）\n\n")
        hdr = ["名称", "驱动版本", "驱动日期", "显存(字节)", "状态"]
        rows = []
        for v in vlist:
            if not isinstance(v, dict):
                continue
            ram = v.get("AdapterRAMBytes")
            ram_s = str(ram) if ram is not None else "—"
            rows.append(
                [
                    v.get("Name", ""),
                    v.get("DriverVersion", ""),
                    v.get("DriverDate", ""),
                    ram_s,
                    v.get("Status", ""),
                ]
            )
        lines.append(_markdown_table(hdr, rows))
        lines.append(
            "\n> WMI `AdapterRAM` 在部分独显上可能不准确；独立显卡利用率请以 **nvidia-smi** / "
            "厂商工具为准。\n\n"
        )

    lines.append(_nvidia_smi_append())
    return "".join(lines)


def collect_memory_markdown() -> str:
    if sys.platform != "win32":
        return "## 内存\n\n当前实现依赖 Windows WMI/CIM。\n"

    ps = r"""
$ProgressPreference='SilentlyContinue'
$ErrorActionPreference='SilentlyContinue'
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$sum = @{
  TotalVisibleKB = [int64]$os.TotalVisibleMemorySize
  FreeKB = [int64]$os.FreePhysicalMemory
  TotalPhysicalBytes = [int64]$cs.TotalPhysicalMemory
  VirtualTotalKB = [int64]$os.TotalVirtualMemorySize
  VirtualFreeKB = [int64]$os.FreeVirtualMemory
}
$mods = @(Get-CimInstance Win32_PhysicalMemory | ForEach-Object {
  [PSCustomObject]@{
    CapacityMB = [math]::Round($_.Capacity / 1MB, 0)
    SpeedMHz = if ($_.Speed) { [int]$_.Speed } else { $null }
    Manufacturer = [string]$_.Manufacturer
    PartNumber = ([string]$_.PartNumber).Trim()
    BankLabel = [string]$_.BankLabel
    DeviceLocator = [string]$_.DeviceLocator
  }
})
[PSCustomObject]@{ Summary = $sum; Modules = $mods } | ConvertTo-Json -Depth 8 -Compress
"""
    raw = _run_powershell(ps, timeout=90)
    try:
        data = _parse_ps_json(raw)
    except Exception:
        return "## 内存\n\n采集失败：\n\n```\n" + raw[:6000] + "\n```\n"

    lines = ["## 内存", ""]
    if not isinstance(data, dict):
        return "\n".join(lines) + "（无数据）\n"

    sm = data.get("Summary") or {}
    if isinstance(sm, dict) and sm:
        tv = sm.get("TotalVisibleKB") or 0
        fk = sm.get("FreeKB") or 0
        tp = sm.get("TotalPhysicalBytes") or 0
        used_kb = max(tv - fk, 0)
        pct = round(100.0 * used_kb / tv, 1) if tv else 0.0
        lines.append("### 系统内存概况\n\n")
        lines.append(_markdown_table(
            ["指标", "数值"],
            [
                ["物理内存总量（操作系统可见 MiB）", f"{tv / 1024:.0f}"],
                ["当前空闲（MiB）", f"{fk / 1024:.0f}"],
                ["已用约（MiB）", f"{used_kb / 1024:.0f}"],
                ["已用占比（相对可见内存）", f"{pct}%"],
                ["硬件安装总量（ComputerSystem MiB）", f"{tp / (1024 * 1024):.0f}"],
                ["提交上限/虚拟（KB）", f"{sm.get('VirtualTotalKB', '')}"],
                ["虚拟空闲（KB）", f"{sm.get('VirtualFreeKB', '')}"],
            ],
        ))
        lines.append("\n")

    mods = data.get("Modules") or []
    if isinstance(mods, dict):
        mods = [mods]
    if mods:
        lines.append("### 物理内存条（WMI Win32_PhysicalMemory）\n\n")
        hdr = ["容量 MiB", "速率 MHz", "厂商", "部件号", "插槽 / Bank"]
        rows = []
        for m in mods:
            if not isinstance(m, dict):
                continue
            rows.append(
                [
                    str(m.get("CapacityMB", "")),
                    str(m.get("SpeedMHz", "") if m.get("SpeedMHz") is not None else "—"),
                    m.get("Manufacturer", ""),
                    m.get("PartNumber", ""),
                    " / ".join(
                        x for x in (m.get("DeviceLocator", ""), m.get("BankLabel", "")) if x
                    ),
                ]
            )
        lines.append(_markdown_table(hdr, rows))
        lines.append("\n")

    return "".join(lines)


def _run_whoami_groups() -> str:
    try:
        kwargs: dict[str, Any] = dict(capture_output=True, timeout=25, text=False)
        if sys.platform == "win32":
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
        r = subprocess.run(["whoami", "/groups"], **kwargs)
        return _decode_console_bytes(r.stdout or b"").strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _run_net_accounts() -> str:
    try:
        kwargs: dict[str, Any] = dict(capture_output=True, timeout=25, text=False)
        if sys.platform == "win32":
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
        r = subprocess.run(["cmd", "/c", "net", "accounts"], **kwargs)
        return _decode_console_bytes(r.stdout or b"").strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def collect_users_policies_markdown() -> str:
    if sys.platform != "win32":
        return "## 本地用户与策略\n\n当前实现依赖 Windows。\n"

    ps_domain = r"""
$ProgressPreference='SilentlyContinue'
$cs = Get-CimInstance Win32_ComputerSystem
[PSCustomObject]@{
  Domain = [string]$cs.Domain
  Workgroup = [string]$cs.Workgroup
  PartOfDomain = [bool]$cs.PartOfDomain
} | ConvertTo-Json -Compress
"""
    raw_dom = _run_powershell(ps_domain, timeout=40)

    ps_users = r"""
$ProgressPreference='SilentlyContinue'
$ErrorActionPreference='SilentlyContinue'
if (-not (Get-Command Get-LocalUser -EA SilentlyContinue)) {
  '{"Error":"Get-LocalUser 不可用（需要 PowerShell 5+ / 完整 Windows）"}'
  exit 0
}
@(Get-LocalUser | ForEach-Object {
  [PSCustomObject]@{
    Name = [string]$_.Name
    Enabled = [bool]$_.Enabled
    PrincipalSource = [string]$_.PrincipalSource
    PasswordExpires = if ($null -eq $_.PasswordExpires) { $null } else {
      $_.PasswordExpires.ToString('yyyy-MM-dd HH:mm:ss')
    }
    PasswordRequired = $_.PasswordRequired
    UserMayChangePassword = $_.UserMayChangePassword
    PasswordLastSet = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
    LastLogon = if ($_.LastLogon) { $_.LastLogon.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
    Description = [string]$_.Description
  }
}) | ConvertTo-Json -Depth 6 -Compress
"""
    raw_u = _run_powershell(ps_users, timeout=120)

    lines = ["## 本地用户与密码策略", ""]

    try:
        dom = _parse_ps_json(raw_dom)
    except Exception:
        dom = None
    if isinstance(dom, dict):
        lines.append("### 计算机域 / 工作组\n\n")
        lines.append(
            _markdown_table(
                ["项目", "值"],
                [
                    ["属于域", "是" if dom.get("PartOfDomain") else "否"],
                    ["域 / DNS 域", dom.get("Domain", "")],
                    ["工作组", dom.get("Workgroup", "")],
                ],
            )
        )
        lines.append(
            "\n> 若已加入 **Active Directory**，本地账户策略可能受域 GPO 覆盖；"
            "请以域管理员提供的策略为准。\n\n"
        )

    users_err_snippet = ""
    try:
        udata = _parse_ps_json(raw_u)
    except Exception:
        udata = None
        users_err_snippet = (raw_u or "")[:600]

    if users_err_snippet and udata is None:
        lines.append("### 本地用户\n\n采集失败（非 JSON）：\n\n```\n" + users_err_snippet + "\n```\n\n")
    elif isinstance(udata, dict) and udata.get("Error"):
        lines.append("### 本地用户\n\n采集跳过：" + str(udata.get("Error")) + "\n\n")
    else:
        ulist = udata if isinstance(udata, list) else []
        if isinstance(udata, dict):
            ulist = [udata]
        if ulist:
            lines.append("### 本地用户账户\n\n")
            hdr = [
                "用户名",
                "启用",
                "来源",
                "需密码",
                "密码过期时间",
                "上次设置密码",
                "上次登录",
                "说明",
            ]
            rows = []
            for u in ulist:
                if not isinstance(u, dict):
                    continue
                pe = u.get("PasswordExpires")
                pe_s = str(pe) if pe else "永不过期 / 不适用"
                rows.append(
                    [
                        u.get("Name", ""),
                        "是" if u.get("Enabled") else "否",
                        u.get("PrincipalSource", ""),
                        "是" if u.get("PasswordRequired") else "否",
                        pe_s,
                        u.get("PasswordLastSet") or "—",
                        u.get("LastLogon") or "—",
                        (u.get("Description") or "")[:80],
                    ]
                )
            lines.append(_markdown_table(hdr, rows))
            lines.append(
                "\n> **提示**：`密码过期时间` 为空通常表示「密码永不过期」或模板账户；"
                "敏感字段在部分版本需提升权限才能完整读取。\n\n"
            )

    na = _run_net_accounts()
    lines.append("### 本地密码策略摘要（`net accounts`）\n\n")
    lines.append("```\n" + (na or "（无法执行 net accounts）")[:8000] + "\n```\n\n")

    wg = _run_whoami_groups()
    if wg:
        lines.append("### 当前用户组令牌（`whoami /groups` 节选）\n\n")
        lines.append("```\n" + wg[:12000] + "\n```\n\n")

    lines.append(
        "### 组策略（GPO）说明\n\n"
        "- 精细策略请在 **`gpedit.msc`**（本地）或由域下发的 GPO 中查看。\n"
        "- 密码复杂度、锁定阈值等常以 **「计算机配置 → Windows 设置 → 安全设置 → 帐户策略」** 为准。\n\n"
    )

    return "".join(lines)


def _safe_user_temp_roots() -> list[Path]:
    seen: set[Path] = set()
    out: list[Path] = []
    for key in ("TEMP", "TMP"):
        v = os.environ.get(key)
        if not v:
            continue
        try:
            p = Path(v).resolve()
        except OSError:
            continue
        if p.is_dir() and p not in seen:
            seen.add(p)
            out.append(p)
    loc = os.environ.get("LOCALAPPDATA")
    if loc:
        try:
            p = (Path(loc) / "Temp").resolve()
            if p.is_dir() and p not in seen:
                seen.add(p)
                out.append(p)
        except OSError:
            pass
    return out


def _windows_system_temp() -> Path | None:
    root = os.environ.get("SystemRoot", r"C:\Windows")
    try:
        p = (Path(root) / "Temp").resolve()
        return p if p.is_dir() else None
    except OSError:
        return None


def _scan_dir_stats(root: Path, *, max_files: int) -> tuple[int, int, bool]:
    """返回 (文件数, 总字节, 是否截断)。"""
    n = 0
    total = 0
    truncated = False
    try:
        root_r = root.resolve()
    except OSError:
        return 0, 0, False

    for dirpath, _, filenames in os.walk(root_r, topdown=True):
        for fn in filenames:
            if n >= max_files:
                truncated = True
                return n, total, truncated
            fp = Path(dirpath) / fn
            try:
                if fp.is_file():
                    total += fp.stat().st_size
                    n += 1
            except OSError:
                continue
    return n, total, truncated


def _is_under(child: Path, root: Path) -> bool:
    try:
        child.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def junk_cleanup_preview_markdown() -> str:
    if sys.platform != "win32":
        return "## 临时文件清理\n\n当前清理路径逻辑针对 Windows。\n"

    lines = ["## 临时文件清理（预览）", ""]
    lines.append(
        "> 预览仅统计**常规临时目录**中的文件大小；不包含浏览器缓存、回收站整盘回收（避免误删）。\n"
        "> **默认执行清理**仅处理当前用户 `TEMP` / `LocalAppData\\Temp`，不包含 `Windows\\Temp`。\n\n"
    )

    hdr = ["路径", "文件数（上限内）", "约占用", "截断"]
    rows = []
    max_scan = 120_000

    for p in _safe_user_temp_roots():
        cnt, sz, trunc = _scan_dir_stats(p, max_files=max_scan)
        rows.append([str(p), str(cnt), f"{sz / (1024 * 1024):.1f} MiB", "是" if trunc else "否"])

    sys_t = _windows_system_temp()
    if sys_t:
        cnt, sz, trunc = _scan_dir_stats(sys_t, max_files=max_scan)
        rows.append(
            [str(sys_t) + "（默认不清理）", str(cnt), f"{sz / (1024 * 1024):.1f} MiB", "是" if trunc else "否"]
        )

    lines.append(_markdown_table(hdr, rows))
    lines.append(
        "\n点击 **执行清理（用户 TEMP）** 将删除上表中「默认清理范围内」目录中的文件（跳过锁定的系统文件）。\n\n"
    )
    return "".join(lines)


def junk_cleanup_execute_markdown() -> str:
    if sys.platform != "win32":
        return "## 清理结果\n\n不支持当前平台。\n"

    roots = _safe_user_temp_roots()
    deleted = 0
    freed = 0
    errors: list[str] = []

    for root in roots:
        try:
            root_r = root.resolve()
        except OSError:
            continue
        for dirpath, _, filenames in os.walk(root_r, topdown=False):
            for fn in filenames:
                fp = Path(dirpath) / fn
                try:
                    if not fp.is_file():
                        continue
                    if not _is_under(fp, root_r):
                        continue
                    sz = fp.stat().st_size
                    fp.unlink()
                    deleted += 1
                    freed += sz
                except OSError as e:
                    errors.append(f"{fp}: {e}")

    freed_mib = freed / (1024 * 1024)
    lines = ["## 临时文件清理（已执行）", ""]
    lines.append(
        _markdown_table(
            ["统计", "值"],
            [["删除文件数", str(deleted)], ["释放约（MiB）", f"{freed_mib:.2f}"]],
        )
    )
    lines.append("\n")
    if errors:
        lines.append("### 无法删除（节选）\n\n```\n")
        lines.append("\n".join(errors[:80]))
        if len(errors) > 80:
            lines.append(f"\n… 另有 {len(errors) - 80} 条 …")
        lines.append("\n```\n")
    return "".join(lines)
