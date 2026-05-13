"""子进程封装：避免 stdout/stderr 管道阻塞，统一 Windows 编码与无控制台窗口。"""

from __future__ import annotations

import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class RunResult:
    argv: list[str]
    returncode: int | None
    stdout_path: Path
    stderr_path: Path
    duration_sec: float


def _creationflags() -> int:
    if sys.platform == "win32":
        try:
            return subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
        except AttributeError:
            return 0
    return 0


def run_to_log_files(
    argv: list[str],
    log_dir: Path,
    log_stem: str,
    *,
    timeout_sec: float | None = None,
    env: dict[str, str] | None = None,
) -> RunResult:
    log_dir.mkdir(parents=True, exist_ok=True)
    out_path = log_dir / f"{log_stem}.stdout.log"
    err_path = log_dir / f"{log_stem}.stderr.log"
    t0 = time.perf_counter()
    with out_path.open("wb") as fo, err_path.open("wb") as fe:
        proc = subprocess.Popen(  # noqa: S603
            argv,
            stdout=fo,
            stderr=fe,
            env=env,
            creationflags=_creationflags(),
        )
        try:
            rc = proc.wait(timeout=timeout_sec)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=30)
            rc = proc.returncode
    return RunResult(
        argv=list(argv),
        returncode=rc,
        stdout_path=out_path,
        stderr_path=err_path,
        duration_sec=time.perf_counter() - t0,
    )


def read_text_best_effort(path: Path, max_bytes: int = 512_000) -> str:
    if not path.is_file():
        return ""
    data = path.read_bytes()[:max_bytes]
    for enc in ("utf-8-sig", "utf-8", "gbk", "cp936"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")
