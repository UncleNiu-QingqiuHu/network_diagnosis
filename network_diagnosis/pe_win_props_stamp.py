"""在 Windows 下向 PE（exe/dll）写入 VERSIONINFO，以便「属性 → 详细信息」显示版本等字段。

使用 Win32 ``BeginUpdateResource`` / ``UpdateResource`` / ``EndUpdateResource``（ctypes），无额外依赖。
写入必须在 **Authenticode 签名之前** 完成，否则会破坏签名哈希。
"""

from __future__ import annotations

import ctypes
import struct
from collections.abc import Iterable
from pathlib import Path

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

BeginUpdateResourceW = kernel32.BeginUpdateResourceW
BeginUpdateResourceW.argtypes = [ctypes.c_wchar_p, ctypes.c_bool]
BeginUpdateResourceW.restype = ctypes.c_void_p

UpdateResourceW = kernel32.UpdateResourceW
UpdateResourceW.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_uint16,
    ctypes.c_void_p,
    ctypes.c_uint32,
]
UpdateResourceW.restype = ctypes.c_bool

EndUpdateResourceW = kernel32.EndUpdateResourceW
EndUpdateResourceW.argtypes = [ctypes.c_void_p, ctypes.c_bool]
EndUpdateResourceW.restype = ctypes.c_bool


def _pad_dword(data: bytes) -> bytes:
    pad = (4 - len(data) % 4) % 4
    return data + b"\0" * pad


def _utf16z(s: str) -> bytes:
    return (s + "\0").encode("utf-16-le")


def _pack_string_entry(key: str, value: str) -> bytes:
    """MSDN VS_VERSIONINFO 下的 String 子块（wType=1 文本）。"""
    key_b = _utf16z(key)
    val_b = _utf16z(value)
    key_b = _pad_dword(key_b)
    val_b = _pad_dword(val_b)
    value_len_words = len(val_b) // 2
    body = key_b + val_b
    total = 6 + len(body)
    return struct.pack("<HHH", total, value_len_words, 1) + body


def _pack_string_table(lang_hex: str, pairs: Iterable[tuple[str, str]]) -> bytes:
    """StringTable：szKey 为 8 位十六进制语言标识（如 080404b0）。"""
    children = b"".join(_pack_string_entry(k, v) for k, v in pairs)
    key_b = _pad_dword(_utf16z(lang_hex))
    total = 6 + len(key_b) + len(children)
    return struct.pack("<HHH", total, 0, 1) + key_b + children


def _pack_string_file_info(lang_hex: str, pairs: Iterable[tuple[str, str]]) -> bytes:
    st = _pack_string_table(lang_hex, pairs)
    key_b = _pad_dword(_utf16z("StringFileInfo"))
    total = 6 + len(key_b) + len(st)
    return struct.pack("<HHH", total, 0, 1) + key_b + st


def _pack_var_file_info() -> bytes:
    """Translation：与 StringTable 080404b0 对齐（简体中文 Unicode 代码页）。"""
    key_b = _pad_dword(_utf16z("VarFileInfo"))
    inner_key = _pad_dword(_utf16z("Translation"))
    value = struct.pack("<HH", 0x0804, 0x04B0)
    inner_body = inner_key + _pad_dword(value)
    inner_total = 6 + len(inner_body)
    inner = struct.pack("<HHH", inner_total, 4, 0) + inner_body
    total = 6 + len(key_b) + len(inner)
    return struct.pack("<HHH", total, 0, 1) + key_b + inner


def _vs_fixed_fileinfo(file_ver: tuple[int, int, int, int], prod_ver: tuple[int, int, int, int]) -> bytes:
    """VS_FIXEDFILEINFO，52 字节。"""
    sig = 0xFEEF04BD
    struct_ver = 0x0001_0000
    f_ms = (file_ver[0] << 16) | (file_ver[1] & 0xFFFF)
    f_ls = (file_ver[2] << 16) | (file_ver[3] & 0xFFFF)
    p_ms = (prod_ver[0] << 16) | (prod_ver[1] & 0xFFFF)
    p_ls = (prod_ver[2] << 16) | (prod_ver[3] & 0xFFFF)
    return struct.pack(
        "<13I",
        sig,
        struct_ver,
        f_ms,
        f_ls,
        p_ms,
        p_ls,
        0x3F,
        0,
        0x40004,
        1,
        0,
        0,
        0,
    )


def _parse_version_quad(version: str) -> tuple[int, int, int, int]:
    base = version.strip().split("-")[0].split("+")[0].strip()
    parts: list[int] = []
    for tok in base.replace(",", ".").split("."):
        t = tok.strip()
        if t.isdigit():
            parts.append(int(t))
        elif parts:
            break
    while len(parts) < 4:
        parts.append(0)
    return tuple(parts[:4])  # type: ignore[return-value]


def build_versioninfo_resource_blob(
    *,
    file_version: str,
    product_version: str,
    product_name: str,
    file_description: str,
    copyright_line: str,
    original_filename: str,
    company_name: str = "Qingqiuhu",
) -> bytes:
    """构造 VS_VERSIONINFO 资源字节块（含 VS_FIXEDFILEINFO + StringFileInfo + VarFileInfo）。"""
    fv = _parse_version_quad(file_version)
    pv = _parse_version_quad(product_version)
    fixed = _vs_fixed_fileinfo(fv, pv)

    pairs: list[tuple[str, str]] = [
        ("CompanyName", company_name),
        ("FileDescription", file_description),
        ("FileVersion", file_version),
        ("InternalName", Path(original_filename).stem),
        ("LegalCopyright", copyright_line),
        ("OriginalFilename", original_filename),
        ("ProductName", product_name),
        ("ProductVersion", product_version),
    ]
    sfi = _pack_string_file_info("080404b0", pairs)
    vfi = _pack_var_file_info()
    children = sfi + vfi

    root_key = _pad_dword(_utf16z("VS_VERSION_INFO"))
    value_len = len(fixed)
    core_after_hdr = root_key + fixed + children
    total_no_pad = 6 + len(core_after_hdr)
    tail_pad = (4 - total_no_pad % 4) % 4
    root_len = total_no_pad + tail_pad
    root_header = struct.pack("<HHH", root_len, value_len, 0)
    out = root_header + core_after_hdr + b"\0" * tail_pad
    assert struct.unpack_from("<H", out, 0)[0] == len(out)
    assert len(out) % 4 == 0
    return out


def stamp_pe_details_properties(
    exe_path: Path,
    *,
    file_version: str,
    product_version: str,
    product_name: str,
    file_description: str,
    copyright_line: str,
    original_filename: str | None = None,
) -> tuple[bool, str]:
    """向 PE 写入 RT_VERSION（详细信息页字段）。成功返回 ``(True, "")``。"""
    exe_path = exe_path.resolve()
    if not exe_path.is_file():
        return False, "目标文件不存在。"
    if original_filename is None:
        original_filename = exe_path.name

    blob = build_versioninfo_resource_blob(
        file_version=file_version,
        product_version=product_version,
        product_name=product_name,
        file_description=file_description,
        copyright_line=copyright_line,
        original_filename=original_filename,
    )

    buf = ctypes.create_string_buffer(blob)
    path_w = str(exe_path)

    h = BeginUpdateResourceW(path_w, False)
    if not h:
        return False, f"BeginUpdateResource 失败（errno={ctypes.get_last_error()}）。"

    def _discard_update() -> None:
        EndUpdateResourceW(h, True)

    p_type = ctypes.c_void_p(16)
    p_name = ctypes.c_void_p(1)
    lang = 0x0804
    if not UpdateResourceW(h, p_type, p_name, lang, ctypes.addressof(buf), len(blob)):
        _discard_update()
        return False, f"UpdateResource 失败（errno={ctypes.get_last_error()}）。"
    if not EndUpdateResourceW(h, False):
        _discard_update()
        return False, f"EndUpdateResource 失败（errno={ctypes.get_last_error()}）。"
    return True, ""


def format_version_display(version: str) -> str:
    """将 ``2.0.2`` 规范为 ``2.0.2.0`` 供详细信息展示。"""
    q = _parse_version_quad(version)
    return ".".join(str(x) for x in q)
