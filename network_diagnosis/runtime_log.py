"""GUI 进程运行日志：写入 ``logs/app.log``，按自然日午夜轮转。

``setup_runtime_logging`` 成功后会安装主线程 / 工作线程未捕获异常钩子（日志器 ``qingqiuhu.crash``）。

其它模块请使用 ``logging.getLogger("qingqiuhu." + __name__)`` 或 ``get_logger(__name__)``，
勿重复挂载文件 Handler（``setup_runtime_logging`` 已为幂等）。
"""

from __future__ import annotations

import logging
import logging.handlers
import sys
import threading
from pathlib import Path

from network_diagnosis.paths import ensure_logs_dir

PKG_LOGGER_NAME = "qingqiuhu"
_APP_HANDLER_MARK = "_qingqiuhu_file_rotating"
_hooks_installed = False


def install_exception_hooks() -> None:
    """将主线程 / 工作线程未捕获异常写入 ``qingqiuhu.crash``（幂等）。"""
    global _hooks_installed
    if _hooks_installed:
        return
    crash_log = logging.getLogger(f"{PKG_LOGGER_NAME}.crash")
    prev_sys_hook = sys.excepthook

    def sys_excepthook(exc_type: type[BaseException] | None, exc: BaseException | None, tb) -> None:
        if exc_type is not None:
            crash_log.error("未捕获异常（主线程）", exc_info=(exc_type, exc, tb))
        prev_sys_hook(exc_type, exc, tb)

    sys.excepthook = sys_excepthook

    if hasattr(threading, "excepthook"):

        def threading_excepthook(args: threading.ExceptHookArgs) -> None:  # type: ignore[attr-defined]
            crash_log.error(
                "未捕获异常（线程 name=%s）",
                getattr(args.thread, "name", ""),
                exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
            )

        threading.excepthook = threading_excepthook  # type: ignore[attr-defined]

    _hooks_installed = True


def setup_runtime_logging(*, backup_days: int = 90) -> Path | None:
    """初始化按日切割的文件日志；成功返回日志目录，失败返回 ``None``（不打断程序）。"""
    pkg_log = logging.getLogger(PKG_LOGGER_NAME)
    for h in pkg_log.handlers:
        if getattr(h, _APP_HANDLER_MARK, False):
            install_exception_hooks()
            try:
                return ensure_logs_dir()
            except OSError:
                return None

    try:
        log_dir = ensure_logs_dir()
        path = log_dir / "app.log"
        fh = logging.handlers.TimedRotatingFileHandler(
            path,
            when="midnight",
            interval=1,
            backupCount=max(1, int(backup_days)),
            encoding="utf-8",
            utc=False,
        )
        fh.setLevel(logging.DEBUG)
        fh.suffix = "%Y-%m-%d"
        setattr(fh, _APP_HANDLER_MARK, True)
        fh.setFormatter(
            logging.Formatter(
                "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        pkg_log.setLevel(logging.DEBUG)
        pkg_log.addHandler(fh)
        pkg_log.propagate = False
        install_exception_hooks()
        return log_dir
    except OSError:
        return None


def get_logger(name: str | None = None) -> logging.Logger:
    """返回 ``qingqiuhu`` 子日志器；传入 ``__name__`` 时会自动加上包前缀。"""
    if not name or name == PKG_LOGGER_NAME:
        return logging.getLogger(PKG_LOGGER_NAME)
    if name.startswith(PKG_LOGGER_NAME + "."):
        return logging.getLogger(name)
    return logging.getLogger(f"{PKG_LOGGER_NAME}.{name}")
