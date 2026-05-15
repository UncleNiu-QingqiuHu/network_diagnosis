"""DNS-01：主机名拆分（RR / SubDomain）与根域名推断。"""

from __future__ import annotations


def normalize_domains(domains: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in domains:
        d = raw.strip().lower().rstrip(".")
        if not d or d in seen:
            continue
        seen.add(d)
        out.append(d)
    return out


def guess_apex(domains: list[str]) -> str:
    """根据首个域名粗略推断解析托管的根域名（常见 *.com/.cn；多级后缀可能不准）。"""
    if not domains:
        raise ValueError("域名列表为空")
    first = domains[0].lower().rstrip(".")
    if first.startswith("*."):
        first = first[2:]
    parts = first.split(".")
    if len(parts) < 2:
        return first
    return ".".join(parts[-2:])


def rr_from_challenge_fqdn(challenge_fqdn: str, apex: str) -> str:
    """将 `_acme-challenge.xxx.example.com` 转为相对 apex 的 RR / SubDomain 前缀。"""
    fqdn = challenge_fqdn.rstrip(".").lower()
    apex_n = apex.rstrip(".").lower()
    if fqdn == apex_n:
        raise ValueError(f"无效的 ACME DNS 主机名：{challenge_fqdn!r}")
    suf = "." + apex_n
    if not fqdn.endswith(suf):
        raise ValueError(f"主机名 {fqdn} 不属于根域名 {apex_n}，请核对「DNS 根域名」是否与云平台解析一致")
    return fqdn[: -len(suf)]
