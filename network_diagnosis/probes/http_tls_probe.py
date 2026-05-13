"""HTTPS 握手耗时、证书信息与 HEAD 状态码（诊断辅助）。"""

from __future__ import annotations

import socket
import ssl
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

from network_diagnosis.model.report import HttpTlsProbeResult


def _fmt_rdn(tup: tuple) -> str:
    if not tup:
        return ""
    parts: list[str] = []
    for item in tup:
        if isinstance(item, tuple) and len(item) == 2:
            parts.append(f"{item[0]}={item[1]}")
    return ", ".join(parts)


def probe_https(host: str) -> HttpTlsProbeResult:
    host = host.strip().rstrip(".")
    url = f"https://{host}/"
    parsed = urlparse(url)
    hn = parsed.hostname
    if not hn:
        return HttpTlsProbeResult(
            url=url,
            ok=False,
            tls_handshake_ms=None,
            http_status=None,
            tls_version=None,
            cert_subject="",
            cert_issuer="",
            cert_not_after="",
            error="无法从主机名构造 HTTPS URL。",
        )
    port = parsed.port or 443
    ctx = ssl.create_default_context()
    tls_ms: float | None = None
    ver: str | None = None
    subj = iss = na = ""
    try:
        t0 = time.perf_counter()
        with socket.create_connection((hn, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hn) as ssock:
                tls_ms = (time.perf_counter() - t0) * 1000.0
                ver = ssock.version()
                cert = ssock.getpeercert()
                if cert:
                    subj = _fmt_rdn(cert.get("subject", ()))
                    iss = _fmt_rdn(cert.get("issuer", ()))
                    na = str(cert.get("notAfter") or "")
    except (OSError, ssl.SSLError, TimeoutError) as e:
        return HttpTlsProbeResult(
            url=url,
            ok=False,
            tls_handshake_ms=tls_ms,
            http_status=None,
            tls_version=ver,
            cert_subject=subj,
            cert_issuer=iss,
            cert_not_after=na,
            error=str(e),
        )

    status: int | None = None
    try:
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "QQHU-NetworkDiagnosis/1.1"})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            status = resp.status
    except urllib.error.HTTPError as e:
        status = e.code
    except (urllib.error.URLError, OSError):
        pass

    return HttpTlsProbeResult(
        url=url,
        ok=True,
        tls_handshake_ms=tls_ms,
        http_status=status,
        tls_version=ver,
        cert_subject=subj or "—",
        cert_issuer=iss or "—",
        cert_not_after=na or "—",
        error="",
    )
