"""tshark 抓包：探测、选网卡、起止子进程。"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

from network_diagnosis.probes.subproc_util import read_text_best_effort, run_to_log_files


def tshark_version_line(tshark: Path, log_dir: Path) -> str | None:
    r = run_to_log_files([str(tshark), "-v"], log_dir, "tshark_version", timeout_sec=30)
    out = read_text_best_effort(r.stdout_path)
    for line in out.splitlines():
        if "TShark" in line or "tshark" in line.lower():
            return line.strip()[:500]
    err = read_text_best_effort(r.stderr_path)
    blob = (out + err).strip()
    return blob.splitlines()[0][:500] if blob else None


def pick_capture_interface_index(tshark: Path, log_dir: Path) -> str:
    r = run_to_log_files([str(tshark), "-D"], log_dir, "tshark_list_if", timeout_sec=30)
    text = read_text_best_effort(r.stdout_path)
    fallback = "1"
    for line in text.splitlines():
        m = re.match(r"^(\d+)\.\s*", line)
        if not m:
            continue
        idx = m.group(1)
        if "loopback" in line.lower():
            continue
        return idx
    return fallback


def _creationflags() -> int:
    if sys.platform == "win32":
        try:
            return subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
        except AttributeError:
            return 0
    return 0


class TsharkCaptureSession:
    def __init__(self) -> None:
        self._proc: subprocess.Popen[bytes] | None = None
        self._stdout_f = None
        self._stderr_f = None

    def start(
        self,
        tshark: Path,
        iface_idx: str,
        pcap_path: Path,
        capture_filter: str,
        log_dir: Path,
    ) -> tuple[Path, Path]:
        log_dir.mkdir(parents=True, exist_ok=True)
        out_log = log_dir / "tshark_capture.stdout.log"
        err_log = log_dir / "tshark_capture.stderr.log"
        argv = [
            str(tshark),
            "-i",
            iface_idx,
            "-w",
            str(pcap_path),
            "-f",
            capture_filter,
        ]
        self._stdout_f = out_log.open("wb")
        self._stderr_f = err_log.open("wb")
        self._proc = subprocess.Popen(  # noqa: S603
            argv,
            stdout=self._stdout_f,
            stderr=self._stderr_f,
            creationflags=_creationflags(),
        )
        return out_log, err_log

    def stop(self) -> int | None:
        proc = self._proc
        if proc is None:
            return None
        proc.terminate()
        try:
            proc.wait(timeout=45)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=20)
        rc = proc.returncode
        self._proc = None
        if self._stdout_f:
            self._stdout_f.close()
            self._stdout_f = None
        if self._stderr_f:
            self._stderr_f.close()
            self._stderr_f = None
        return rc
