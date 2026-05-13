"""PathPing（Windows）或 mtr 报告模式（Unix），观察路径丢包/延迟。"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

from network_diagnosis.model.report import ShellProbeResult
from network_diagnosis.probes.subproc_util import read_text_best_effort, run_to_log_files


def _stub(log_dir: Path, msg: str) -> ShellProbeResult:
    p = log_dir / "path_quality_skip.txt"
    p.write_text(msg + "\n", encoding="utf-8")
    return ShellProbeResult(
        kind="skip",
        summary=msg,
        command=[],
        raw_stdout_path=p,
        raw_stderr_path=p,
        returncode=None,
    )


def _outline(text: str, tool: str) -> str:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    head = "\n".join(lines[:25])
    return f"工具：{tool}。\n输出前 25 行预览：\n{head}" if head else f"{tool} 无可用输出。"


def run_path_quality(host: str, log_dir: Path) -> ShellProbeResult:
    if sys.platform == "win32":
        argv = ["pathping", "-n", "-q", "10", "-p", "200", "-w", "3000", host]
        r = run_to_log_files(argv, log_dir, "pathping", timeout_sec=420.0)
        text = read_text_best_effort(r.stdout_path)
        return ShellProbeResult(
            kind="pathping",
            summary=_outline(text, "pathping"),
            command=list(r.argv),
            raw_stdout_path=r.stdout_path,
            raw_stderr_path=r.stderr_path,
            returncode=r.returncode,
        )
    mtr = shutil.which("mtr")
    if mtr:
        argv = [mtr, "--report", "--report-cycles", "10", "--no-dns", host]
        r = run_to_log_files(argv, log_dir, "mtr", timeout_sec=200.0)
        text = read_text_best_effort(r.stdout_path)
        return ShellProbeResult(
            kind="mtr",
            summary=_outline(text, "mtr"),
            command=list(r.argv),
            raw_stdout_path=r.stdout_path,
            raw_stderr_path=r.stderr_path,
            returncode=r.returncode,
        )
    return _stub(log_dir, "非 Windows 且未在 PATH 中找到 mtr，已跳过 PathPing/mtr。")
