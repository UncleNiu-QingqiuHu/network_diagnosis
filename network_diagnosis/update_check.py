"""GitHub Releases 版本检查（启动时可选静默检查 + 关于页手动检查）。"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from network_diagnosis.version import APP_VERSION

# GitHub API 要求 ``User-Agent``；HTTP 头必须用 latin-1，不得含中文等非 ASCII。
_HTTP_USER_AGENT = f"qqhu-network-diagnosis/{APP_VERSION}"

# GitHub REST：未带 Token 时按 **出口公网 IP** 约 60 次/小时（``/repos/.../releases/latest``）。
# 用户分散在各运营商一般无感；同一企业 NAT 下大量客户端「同时冷启动」可能触达限频，可考虑延长检查间隔或自有 manifest。
NETWORK_FAILURE_HINT = (
    "网络异常或暂时无法连接 GitHub。"
    "请检查本机网络、代理或防火墙设置后稍后再试。"
)
GITHUB_RATE_LIMIT_HINT = (
    "已达到 GitHub 接口访问频次上限（常见于短时间内请求过多），请稍后再试，"
    "或使用浏览器打开 Release 页面手动查看。"
)
GITHUB_SERVER_BUSY_HINT = "GitHub 服务暂时不可用或繁忙，请稍后再试。"
GENERIC_FETCH_HINT = "无法获取 Release 信息，请稍后重试。"

# 与本仓库 Release 对应（浏览器分发页与 REST latest）
GITHUB_RELEASES_WEB = "https://github.com/UncleNiu-QingqiuHu/network_diagnosis/releases"
GITHUB_API_RELEASE_LATEST = (
    "https://api.github.com/repos/UncleNiu-QingqiuHu/network_diagnosis/releases/latest"
)

# 发行资产命名约定（仅替换标签中的版本号）：与 Release tag 路径一致，例如
# …/download/v2.0.1/qqhu-network-workbench-v2.0.1-win64.zip
GITHUB_DOWNLOAD_ZIP_BASE = (
    "https://github.com/UncleNiu-QingqiuHu/network_diagnosis/releases/download"
)


def release_tag_for_asset_urls(api_tag_name: str) -> str:
    """与仓库打包命名对齐：路径与文件名中段均为 ``vMAJOR.MINOR.PATCH``（API 若无 ``v`` 前缀则补上）。"""
    t = api_tag_name.strip()
    if not t:
        return t
    if not t.lower().startswith("v"):
        return f"v{t}"
    return t


def win64_zip_download_url(api_tag_name: str) -> str:
    slug = release_tag_for_asset_urls(api_tag_name)
    return (
        f"{GITHUB_DOWNLOAD_ZIP_BASE}/{slug}/qqhu-network-workbench-{slug}-win64.zip"
    )


def _normalize_version_token(raw: str) -> str:
    s = raw.strip()
    if s.lower().startswith("v"):
        s = s[1:].strip()
    # 发行标签常见 v2.0.0-rc1，与 APP_VERSION 比较时只看主版本段
    if "-" in s:
        s = s.split("-", 1)[0].strip()
    if "+" in s:
        s = s.split("+", 1)[0].strip()
    return s


def version_tuple_for_compare(v: str) -> tuple[int, ...]:
    """与 ``APP_VERSION`` 风格一致：点分整数段，不足补 0；非法段在遇到首个非数字 token 时截断。"""
    base = _normalize_version_token(v).replace(",", ".")
    parts: list[int] = []
    for tok in base.split("."):
        t = tok.strip()
        if t.isdigit():
            parts.append(int(t))
        elif parts:
            break
    while len(parts) < 4:
        parts.append(0)
    return tuple(parts[:8])


def is_remote_newer_than_current(remote_tag_or_version: str, current: str = APP_VERSION) -> bool | None:
    """若任一侧无法解析为可比较元组则返回 ``None``。"""
    rt = version_tuple_for_compare(remote_tag_or_version)
    ct = version_tuple_for_compare(current)
    return rt > ct


@dataclass(frozen=True)
class GithubLatestReleaseInfo:
    fetched_ok: bool
    error_detail: str | None = None
    #: 面向用户的简短中文说明（网络 / 限流等）；弹窗优先展示；技术细节仍放在 ``error_detail`` 供日志与排查。
    user_hint: str | None = None
    tag_name: str | None = None
    release_title: str | None = None
    html_url: str | None = None
    download_zip_url: str | None = None
    is_newer_than_running: bool | None = None


def fetch_latest_release_info(*, timeout_sec: float = 12.0) -> GithubLatestReleaseInfo:
    """调用 GitHub ``releases/latest`` JSON API。"""
    ua = _HTTP_USER_AGENT[:200]
    req = Request(
        GITHUB_API_RELEASE_LATEST,
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": ua[:200],
        },
        method="GET",
    )
    try:
        with urlopen(req, timeout=timeout_sec) as resp:  # noqa: S310 — 固定官方 API HTTPS
            raw = resp.read()
    except HTTPError as e:
        detail = e.reason or ""
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")[:400]
        except OSError:
            pass
        msg = f"HTTP {e.code}: {detail}".strip()
        if body:
            msg = f"{msg}\n{body}"

        hint: str | None = None
        low = body.lower()
        if e.code == 429 or (e.code == 403 and "rate limit" in low):
            hint = GITHUB_RATE_LIMIT_HINT
        elif e.code >= 500:
            hint = GITHUB_SERVER_BUSY_HINT
        elif e.code in (408, 504):
            hint = NETWORK_FAILURE_HINT
        elif 400 <= e.code < 500:
            hint = GENERIC_FETCH_HINT

        return GithubLatestReleaseInfo(fetched_ok=False, error_detail=msg, user_hint=hint)
    except TimeoutError as e:
        return GithubLatestReleaseInfo(
            fetched_ok=False,
            error_detail=str(e),
            user_hint=NETWORK_FAILURE_HINT,
        )
    except URLError as e:
        return GithubLatestReleaseInfo(
            fetched_ok=False,
            error_detail=str(e.reason or e),
            user_hint=NETWORK_FAILURE_HINT,
        )
    except OSError as e:
        return GithubLatestReleaseInfo(
            fetched_ok=False,
            error_detail=str(e),
            user_hint=NETWORK_FAILURE_HINT,
        )

    try:
        data: dict[str, Any] = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        return GithubLatestReleaseInfo(
            fetched_ok=False,
            error_detail=f"解析 JSON 失败：{e}",
            user_hint=GENERIC_FETCH_HINT,
        )

    tag = data.get("tag_name")
    if not isinstance(tag, str) or not tag.strip():
        return GithubLatestReleaseInfo(
            fetched_ok=False,
            error_detail="响应中缺少 tag_name。",
            user_hint=GENERIC_FETCH_HINT,
        )

    title = data.get("name")
    title_s = title.strip() if isinstance(title, str) else None
    html = data.get("html_url")
    html_s = html.strip() if isinstance(html, str) and html.strip() else GITHUB_RELEASES_WEB

    newer = is_remote_newer_than_current(tag)
    zip_url = win64_zip_download_url(tag)
    return GithubLatestReleaseInfo(
        fetched_ok=True,
        tag_name=tag.strip(),
        release_title=title_s,
        html_url=html_s,
        download_zip_url=zip_url,
        is_newer_than_running=newer,
    )
