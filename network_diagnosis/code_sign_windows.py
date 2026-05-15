"""Windows Authenticode 签名辅助：查找 signtool、PFX 签名、一键生成自签名代码签名证书。"""

from __future__ import annotations

import base64
import locale
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CODE_SIGN_CONTACT_EMAIL = "contact@qingqiuhu.net"


def normalize_code_sign_subject(subject: str) -> str:
    """若主题 DN 中尚无邮箱类组件，则追加 ``E=contact@qingqiuhu.net``。"""
    s = subject.strip()
    if not s:
        s = "CN=Qingqiuhu Self-Signed Code Signing"
    low = s.casefold()
    em = CODE_SIGN_CONTACT_EMAIL.casefold()
    if em in low:
        return s
    if re.search(r"(^|,)\s*(e|emailaddress)=", low):
        return s
    return f"{s}, E={CODE_SIGN_CONTACT_EMAIL}"


def _decode_windows_console_output(raw: bytes | None) -> str:
    """解码子进程输出：优先 UTF-8，中文 Windows 下常见为 GBK/cp936。"""
    if not raw:
        return ""
    for enc in ("utf-8-sig", "utf-8"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    if sys.platform == "win32":
        for enc in ("gbk", "cp936"):
            try:
                return raw.decode(enc)
            except (UnicodeDecodeError, LookupError):
                continue
        try:
            return raw.decode("mbcs")
        except UnicodeDecodeError:
            pass
    pref = locale.getpreferredencoding(False)
    if pref:
        try:
            return raw.decode(pref)
        except (UnicodeDecodeError, LookupError):
            pass
    return raw.decode("utf-8", errors="replace")


def _run_capture_decoded(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, capture_output=True)
    out = _decode_windows_console_output(proc.stdout)
    err = _decode_windows_console_output(proc.stderr)
    return subprocess.CompletedProcess(cmd, proc.returncode, stdout=out, stderr=err)


def find_signtool_exe() -> Path | None:
    """在 PATH 与常见 Windows SDK 安装路径下查找 ``signtool.exe``。"""
    w = shutil.which("signtool")
    if w:
        return Path(w)
    pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    roots = [Path(pf86) / "Windows Kits" / "10" / "bin", Path(pf) / "Windows Kits" / "10" / "bin"]
    for root in roots:
        if not root.is_dir():
            continue
        try:
            versions = sorted([p for p in root.iterdir() if p.is_dir()], reverse=True)
        except OSError:
            continue
        for ver in versions:
            for arch in ("x64", "x86", "arm64"):
                cand = ver / arch / "signtool.exe"
                if cand.is_file():
                    return cand
    return None


def sign_pe(
    exe_path: Path,
    pfx_path: Path,
    password: str,
    *,
    timestamp_url: str | None,
    signtool: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """使用 PFX 对 PE 文件签名；若 ``timestamp_url`` 非空则附加 RFC3161 时间戳。"""
    tool = signtool or find_signtool_exe()
    if tool is None:
        raise FileNotFoundError("未找到 signtool.exe，请安装 Windows SDK 签名工具或将 signtool 加入 PATH。")
    exe_path = exe_path.resolve()
    pfx_path = pfx_path.resolve()
    cmd: list[str] = [
        str(tool),
        "sign",
        "/v",
        "/fd",
        "SHA256",
        "/f",
        str(pfx_path),
        "/p",
        password,
    ]
    if timestamp_url:
        ts = timestamp_url.strip()
        if ts:
            cmd.extend(["/tr", ts, "/td", "SHA256"])
    cmd.append(str(exe_path))
    return _run_capture_decoded(cmd)


def verify_pe(exe_path: Path, *, signtool: Path | None = None) -> subprocess.CompletedProcess[str]:
    tool = signtool or find_signtool_exe()
    if tool is None:
        raise FileNotFoundError("未找到 signtool.exe，请安装 Windows SDK 签名工具或将 signtool 加入 PATH。")
    cmd = [str(tool), "verify", "/pa", "/v", str(exe_path.resolve())]
    return _run_capture_decoded(cmd)


def generate_self_signed_code_signing_pfx(
    output_dir: Path,
    password: str,
    subject: str,
) -> tuple[bool, str, Path | None, Path | None]:
    """使用 **.NET CertificateRequest** 在内存中生成 **代码签名** 自签名证书并导出 PFX/CER。

    不依赖 ``Cert:`` 证书驱动器，亦不在本地证书存储中保留证书（部分环境无法加载
    ``Microsoft.PowerShell.Security`` / PKI 模块时仍可用）。
    ``subject`` 建议形如 ``CN=组织或工具名称``；生成前会规范化并附带联系邮箱（DN ``E=`` 及 SAN，若运行库支持）。
    返回 ``(成功, 日志文本, pfx路径, cer路径)``。
    """
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    pfx_path = output_dir / "codesign-selfsigned.pfx"
    cer_path = output_dir / "codesign-selfsigned-public.cer"

    pwd_b64 = base64.b64encode(password.encode("utf-8")).decode("ascii")
    subject_dn = normalize_code_sign_subject(subject)
    sub_b64 = base64.b64encode(subject_dn.encode("utf-8")).decode("ascii")
    pfx_lit = str(pfx_path.resolve()).replace("'", "''")
    cer_lit = str(cer_path.resolve()).replace("'", "''")

    # 双花括号供 str.format 转义为单层花括号，供 PowerShell 使用。
    ps_template = """$ErrorActionPreference = 'Stop'
$pwdPlain = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{pwd_b64}'))
$subjectDnStr = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{sub_b64}'))
$pfxPath = '{pfx}'
$cerPath = '{cer}'
$rsa = $null
$cert = $null
try {{
    try {{
        $rsa = [System.Security.Cryptography.RSA]::Create(4096)
    }} catch {{
        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider(4096)
    }}
    $dn = New-Object System.Security.Cryptography.X509Certificates.X500DistinguishedName($subjectDnStr)
    $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        $dn,
        $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $codeSignOid = New-Object System.Security.Cryptography.Oid('1.3.6.1.5.5.7.3.3')
    $oidColl = New-Object System.Security.Cryptography.OidCollection
    [void]$oidColl.Add($codeSignOid)
    $eku = New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($oidColl, $false)
    [void]$req.CertificateExtensions.Add($eku)
    $keyUsage = New-Object System.Security.Cryptography.X509Certificates.X509KeyUsageExtension(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature,
        $true
    )
    [void]$req.CertificateExtensions.Add($keyUsage)
    try {{
        $san = New-Object System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder
        [void]$san.AddEmailAddress('{contact_email}')
        [void]$req.CertificateExtensions.Add($san.Build())
    }} catch {{ }}
    $bc = New-Object System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension($false, $false, 0, $false)
    [void]$req.CertificateExtensions.Add($bc)
    $notBefore = [DateTimeOffset]::UtcNow.AddMinutes(-1)
    $notAfter = $notBefore.AddYears(10)
    $cert = $req.CreateSelfSigned($notBefore, $notAfter)
    $pfxBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $pwdPlain)
    [System.IO.File]::WriteAllBytes($pfxPath, $pfxBytes)
    $cerBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    [System.IO.File]::WriteAllBytes($cerPath, $cerBytes)
}} finally {{
    if ($null -ne $cert) {{ $cert.Dispose() }}
    if ($null -ne $rsa) {{ $rsa.Dispose() }}
}}
"""
    ps = ps_template.format(
        pwd_b64=pwd_b64,
        sub_b64=sub_b64,
        pfx=pfx_lit,
        cer=cer_lit,
        contact_email=CODE_SIGN_CONTACT_EMAIL.replace("'", "''"),
    )
    fd, tmp_ps1 = tempfile.mkstemp(suffix=".ps1", prefix="qqhu-codesign-")
    os.close(fd)
    tmp_path = Path(tmp_ps1)
    try:
        tmp_path.write_text(ps, encoding="utf-8-sig")
        proc = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(tmp_path),
            ],
            capture_output=True,
        )
        stdout_txt = _decode_windows_console_output(proc.stdout)
        stderr_txt = _decode_windows_console_output(proc.stderr)
        lines: list[str] = []
        if stdout_txt:
            lines.append(stdout_txt.strip())
        if stderr_txt:
            lines.append(stderr_txt.strip())
        msg = "\n".join(x for x in lines if x)
        if proc.returncode != 0:
            return False, msg or f"PowerShell 退出码 {proc.returncode}", None, None
        if not pfx_path.is_file() or not cer_path.is_file():
            return False, msg + "\n未检测到输出文件。", None, None
        return True, msg, pfx_path, cer_path
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
