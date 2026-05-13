"""HTTP(S) 并行抽样下载，估算平均吞吐（Mbps，仅供参考）。"""

from __future__ import annotations

import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from network_diagnosis.model.report import BandwidthProbeResult

_DEFAULT_UA = "QQHU-NetworkDiagnosis/1.0 (bandwidth sampling)"


def run_http_bandwidth(
    url: str,
    parallel: int,
    duration_sec: int,
    report_dir: Path,
) -> BandwidthProbeResult:
    parallel = max(1, min(32, parallel))
    duration_sec = max(3, min(300, duration_sec))
    stem = "bandwidth_http"

    def worker() -> tuple[int, str | None]:
        local = 0
        err: str | None = None
        try:
            req = urllib.request.Request(url, headers={"User-Agent": _DEFAULT_UA})
            with urllib.request.urlopen(req, timeout=min(60, duration_sec + 15)) as resp:
                while time.monotonic() < deadline:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    local += len(chunk)
        except (urllib.error.URLError, OSError, ValueError) as e:
            err = str(e)
        except Exception as e:  # noqa: BLE001 — 汇总为探测失败说明
            err = f"{type(e).__name__}: {e}"
        return local, err

    deadline = 0.0
    threads: list[threading.Thread] = []
    results: list[tuple[int, str | None]] = []
    lock = threading.Lock()

    def run_one() -> None:
        got = worker()
        with lock:
            results.append(got)

    t_wall0 = time.monotonic()
    deadline = t_wall0 + float(duration_sec)
    for _ in range(parallel):
        th = threading.Thread(target=run_one, daemon=True)
        threads.append(th)
        th.start()
    for th in threads:
        th.join()
    elapsed = max(time.monotonic() - t_wall0, 1e-3)

    total_bytes = sum(r[0] for r in results)
    errs = [r[1] for r in results if r[1]]
    mbps = (total_bytes * 8.0) / elapsed / 1_000_000.0

    log_path = report_dir / f"{stem}_summary.txt"
    log_lines = [
        f"url={url}",
        f"parallel={parallel}",
        f"duration_s={duration_sec}",
        f"wall_elapsed_s={elapsed:.3f}",
        f"total_bytes={total_bytes}",
        f"avg_mbps={mbps:.3f}",
    ]
    if errs:
        log_lines.append("thread_errors:")
        log_lines.extend(f"  - {e}" for e in errs[:12])
    log_path.write_text("\n".join(log_lines) + "\n", encoding="utf-8")

    if total_bytes <= 0 and errs:
        return BandwidthProbeResult(
            mode="http",
            ok=False,
            summary="HTTP 抽样下载失败（各连接均出错）。",
            megabits_per_second=None,
            bytes_total=0,
            duration_sec=elapsed,
            parallel_streams=parallel,
            target_label=url,
            error="; ".join(errs[:3]),
            log_stdout_path=log_path,
            log_stderr_path=None,
            command=None,
        )

    summary = (
        f"HTTP 并行×{parallel}，约 {elapsed:.1f} s 内共下载 {total_bytes // 1024} KiB，"
        f"平均约 {mbps:.1f} Mbps（仅反映到该 URL 的抽样）。"
    )
    if errs:
        summary += f" 部分连接异常：{errs[0][:120]}"

    return BandwidthProbeResult(
        mode="http",
        ok=True,
        summary=summary,
        megabits_per_second=mbps,
        bytes_total=total_bytes,
        duration_sec=elapsed,
        parallel_streams=parallel,
        target_label=url,
        error="; ".join(errs[:3]) if errs else "",
        log_stdout_path=log_path,
        log_stderr_path=None,
        command=None,
    )
