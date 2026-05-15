"""在 Windows 下向 PE（exe/dll）写入 VERSIONINFO，以便「属性 → 详细信息」显示版本等字段。

使用 Win32 ``BeginUpdateResource`` / ``UpdateResource`` / ``EndUpdateResource``（ctypes），无额外依赖。
写入必须在 **Authenticode 签名之前** 完成，否则会破坏签名哈希。

**GUI「数字签名」页不再调用本模块**；发布版「详细信息」请以 Nuitka/PyInstaller 构建参数为准。本文件保留供脚本或特殊后处理使用。

与多数链接工具一致：内含 ``040904b0``（语言 ID ``0x0409`` + Unicode 代码页 ``04b0`` 组成的 **StringTable 键**，与字符串是否中文无关）的字符串块；并在 ``UpdateResource`` 时枚举
文件中已有的 ``RT_VERSION`` 语言条目并写入，再与常用槽 ``0x0409`` / ``0x0804`` 合并——避免仅写入一侧而资源管理器仍读到另一侧空块。不使用 ``lang=0`` 作为更新目标（易致版本块无法被 ``GetFileVersionInfo`` 解析）。
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

LoadLibraryExW = kernel32.LoadLibraryExW
LoadLibraryExW.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_ulong]
LoadLibraryExW.restype = ctypes.c_void_p

FreeLibrary = kernel32.FreeLibrary
FreeLibrary.argtypes = [ctypes.c_void_p]
FreeLibrary.restype = ctypes.c_bool

LONG_PTR_RES = ctypes.c_ssize_t


def _windows_module_handle_as_int(load_result: object) -> int:
    """兼容 ``LoadLibraryEx`` 等在 ctypes 中返回 ``c_void_p`` 或原生 ``int``（视版本/绑定而定）。"""
    if load_result is None:
        return 0
    if isinstance(load_result, ctypes.c_void_p):
        v = load_result.value
        if v is None:
            return 0
        try:
            return int(v)
        except (TypeError, ValueError):
            return 0
    if isinstance(load_result, int):
        return load_result
    try:
        return int(load_result)
    except (TypeError, ValueError):
        return 0


def _pad_dword(data: bytes) -> bytes:
    pad = (4 - len(data) % 4) % 4
    return data + b"\0" * pad


def _utf16z(s: str) -> bytes:
    return (s + "\0").encode("utf-16-le")


def _unpack_lang_hex(lang_hex: str) -> tuple[int, int]:
    """StringTable szKey（8 位十六进制）→ (LANGID, 代码页后缀，如 Unicode 常用 04b0)。"""
    s = lang_hex.strip().lower()
    if len(s) != 8 or any(c not in "0123456789abcdef" for c in s):
        raise ValueError("lang_hex 须为 8 位十六进制，例如 040904b0。")
    return int(s[:4], 16), int(s[4:], 16)


def _existing_rt_version_langids(pe_path: Path) -> set[int]:
    """枚举 PE 中 ``RT_VERSION`` / ``1`` 已有的语言条目（常与常用槽合并后再写入）。

    若当前 Python 位数与 exe 不符（WOW64），``LoadLibraryEx`` / ``EnumResourceLanguages`` 常失败，
    此时返回 **空集合**，仅靠后续 ``_version_resource_stamp_lang_candidates`` 的固定列表兜底，
    **不得**误认为「只能写 ``0x0409``」。
    """
    LOAD_LIBRARY_AS_DATAFILE = 0x00000002
    LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020
    RT_RES = 16
    RES_ID = 1

    ENUMRESLANGPROC = ctypes.WINFUNCTYPE(
        ctypes.c_bool,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint16,
        LONG_PTR_RES,
    )

    EnumResourceLanguagesW = kernel32.EnumResourceLanguagesW
    EnumResourceLanguagesW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ENUMRESLANGPROC,
        LONG_PTR_RES,
    ]
    EnumResourceLanguagesW.restype = ctypes.c_bool

    collected: list[int] = []

    @ENUMRESLANGPROC
    def _lang_cb(_hmod: ctypes.c_void_p, _tp: ctypes.c_void_p, _nm: ctypes.c_void_p, lang_id: int, _lp: int) -> bool:
        collected.append(int(lang_id))
        return True

    # ``LoadLibraryExW`` 在实际运行中可能返回 ``c_void_p`` 或原生 ``int``，统一成整数再 ``c_void_p(addr)``。
    h_mod: ctypes.c_void_p | None = None
    for load_flags in (LOAD_LIBRARY_AS_DATAFILE, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE):
        hm = LoadLibraryExW(str(pe_path.resolve()), None, load_flags)
        addr = _windows_module_handle_as_int(hm)
        if addr != 0:
            h_mod = ctypes.c_void_p(addr)
            break
    if h_mod is None or _windows_module_handle_as_int(h_mod) == 0:
        return set()
    try:
        ok = EnumResourceLanguagesW(h_mod, ctypes.c_void_p(RT_RES), ctypes.c_void_p(RES_ID), _lang_cb, 0)
        if ok and collected:
            return set(collected)
    finally:
        FreeLibrary(h_mod)
    return set()


def _version_resource_stamp_lang_candidates(pe_path: Path) -> list[int]:
    """``UpdateResource`` 要写入的 **RT_VERSION 语言 ID**（与属性页「语言」不是同一概念）。

    合并：PE 内已有条目 ∪ ``0x0409``（常见 en-US 资源槽）∪ ``0x0804``（常见 zh-CN 槽）。
    不再写入 ``lang=0``（中性）及一批欧/日槽：减少无效更新；若某发行版使用其它 LANGID，依赖
    ``_existing_rt_version_langids`` 枚举结果仍会覆盖到。
    """
    base = _existing_rt_version_langids(pe_path)
    base |= {0x0409, 0x0804}
    return sorted(x for x in base if x < 0xFFFF and x != 0)


def _ver_query_value_string(pe_block, sub_block: str) -> str | None:
    VerQueryValueW = ctypes.windll.version.VerQueryValueW
    VerQueryValueW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    VerQueryValueW.restype = ctypes.c_bool
    pv = ctypes.c_void_p()
    ln = ctypes.c_uint32()
    ok = VerQueryValueW(pe_block, sub_block, ctypes.byref(pv), ctypes.byref(ln))
    if not ok or not pv.value or ln.value < 2:
        return None
    return ctypes.wstring_at(pv)


def verify_pe_stamp_readable_by_os(pe_path: Path, *, lang_table_key_hex: str = "040904b0") -> tuple[bool, str]:
    """用与资源管理器相同的数据源校验：能否通过 ``GetFileVersionInfo`` / ``VerQueryValue`` 读到字段。"""
    ver = ctypes.windll.version
    gfs = ver.GetFileVersionInfoSizeW
    gfi = ver.GetFileVersionInfoW
    gfs.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint32)]
    gfs.restype = ctypes.c_uint32
    gfi.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    gfi.restype = ctypes.c_bool

    tbl = "\\StringFileInfo\\" + lang_table_key_hex.strip().lower() + "\\"

    pw = str(pe_path.resolve())
    _wh = ctypes.c_uint32()
    nbytes = gfs(pw, ctypes.byref(_wh))
    if nbytes == 0:
        return False, f"GetFileVersionInfoSizeW 返回 0（errno={ctypes.get_last_error()}）。"

    buf = ctypes.create_string_buffer(nbytes)
    if not gfi(pw, 0, ctypes.c_uint32(nbytes), ctypes.addressof(buf)):
        return False, f"GetFileVersionInfoW 失败（errno={ctypes.get_last_error()}）。"

    probe = (
        tbl + "ProductName",
        tbl + "FileDescription",
        tbl + "FileVersion",
    )
    for pb in probe:
        s = _ver_query_value_string(buf, pb)
        if s and str(s).strip():
            snip = str(s).strip().replace("\n", " ")
            end = "" if len(snip) <= 48 else "…"
            return True, f"OS 可读（{pb.rsplit('\\', 1)[-1]}）：{snip[:48]}{end}"
    return False, (
        "无法在版本块中找到可读的 StringFileInfo 字符串（已试 ProductName/FileDescription/FileVersion）。"
        "若资源管理器亦为空白，则可能 VERSIONINFO 二进制结构仍不规范。"
    )


def _pack_string_entry(key: str, value: str) -> bytes:
    """MSDN VS_VERSIONINFO 下的 String 子块（wType=1 文本）。"""
    key_b = _utf16z(key)
    val_b = _utf16z(value)
    key_b = _pad_dword(key_b)
    val_b = _pad_dword(val_b)
    # wValueLength 为 Value  WCHAR 个数，一般不含末尾的 null（与 MSVC / Windows 外壳习惯一致）。
    nwchar = len(val_b) // 2
    value_len_words = max(0, nwchar - 1)
    body = key_b + val_b
    total = 6 + len(body)
    return struct.pack("<HHH", total, value_len_words, 1) + body


def _pack_string_table(lang_hex: str, pairs: Iterable[tuple[str, str]]) -> bytes:
    """StringTable：szKey 为 8 位十六进制语言标识（如 040904b0）。"""
    children = b"".join(_pack_string_entry(k, v) for k, v in pairs)
    key_b = _pad_dword(_utf16z(lang_hex))
    total = 6 + len(key_b) + len(children)
    return struct.pack("<HHH", total, 0, 1) + key_b + children


def _pack_string_file_info(lang_hex: str, pairs: Iterable[tuple[str, str]]) -> bytes:
    st = _pack_string_table(lang_hex, pairs)
    key_b = _pad_dword(_utf16z("StringFileInfo"))
    total = 6 + len(key_b) + len(st)
    return struct.pack("<HHH", total, 0, 1) + key_b + st


def _pack_var_file_info(lang_hex: str) -> bytes:
    """Translation：必须与 StringTable 的 szKey 一致；常见为 unicode 代码页后缀 ``04b0``。"""
    lang_id, codepage = _unpack_lang_hex(lang_hex)
    key_b = _pad_dword(_utf16z("VarFileInfo"))
    inner_key = _pad_dword(_utf16z("Translation"))
    value = struct.pack("<HH", lang_id, codepage)
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
    string_table_key: str = "040904b0",
) -> bytes:
    """构造 VS_VERSIONINFO 资源字节块（含 VS_FIXEDFILEINFO + StringFileInfo + VarFileInfo）。

    ``string_table_key`` 默认 ``040904b0``（en-US + Unicode 代码页），与多数链接器生成的
    VERSION 资源语言槽一致；字符串仍为 UTF-16，可用中文等非英文文案。
    """
    fv = _parse_version_quad(file_version)
    pv = _parse_version_quad(product_version)
    fixed = _vs_fixed_fileinfo(fv, pv)

    key_norm = string_table_key.strip().lower()
    _unpack_lang_hex(key_norm)

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
    sfi = _pack_string_file_info(key_norm, pairs)
    vfi = _pack_var_file_info(key_norm)
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
    """向 PE 写入 RT_VERSION。

    成功返回 ``(True, 人类可读校验摘要)`` （含操作系统 ``VerQueryValue`` 自检）。
    失败返回 ``(False, 错误说明）``——若 UpdateResource 成功但自检失败也会判为失败，以避免「静默写坏」。"""
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

    lang_ids = _version_resource_stamp_lang_candidates(exe_path)

    h = BeginUpdateResourceW(path_w, False)
    if not h:
        return False, f"BeginUpdateResource 失败（errno={ctypes.get_last_error()}）。"

    def _discard_update() -> None:
        EndUpdateResourceW(h, True)

    p_type = ctypes.c_void_p(16)
    p_name = ctypes.c_void_p(1)
    for lang in lang_ids:
        if not UpdateResourceW(h, p_type, p_name, lang, ctypes.addressof(buf), len(blob)):
            _discard_update()
            return False, f"UpdateResource 失败（lang=0x{lang:04X}，errno={ctypes.get_last_error()}）。"
    if not EndUpdateResourceW(h, False):
        _discard_update()
        return False, f"EndUpdateResource 失败（errno={ctypes.get_last_error()}）。"

    ok_rd, vrf = verify_pe_stamp_readable_by_os(exe_path)
    lang_note = "(" + ",".join(f"0x{x:04X}" for x in lang_ids) + ")"
    if not ok_rd:
        return False, f"{vrf} 虽已提交资源更新，但校验未通过。已尝试的语言槽 {lang_note}（共 {len(lang_ids)} 个）。"
    return True, f"{vrf} 已覆盖 {len(lang_ids)} 个语言槽：{lang_note}。"


def format_version_display(version: str) -> str:
    """将 ``2.0.2`` 规范为 ``2.0.2.0`` 供详细信息展示。"""
    q = _parse_version_quad(version)
    return ".".join(str(x) for x in q)
