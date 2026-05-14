"""GUI 进程运行日志：写入 ``logs/app.log``，按自然日午夜轮转。

其它模块请使用 ``logging.getLogger("qingqiuhu." + __name__)`` 或 ``get_logger(__name__)``，
勿重复挂载文件 Handler（``setup_runtime_logging`` 已为幂等）。
"""

from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

from network_diagnosis.paths import ensure_logs_dir

PKG_LOGGER_NAME = "qingqiuhu"
_APP_HANDLER_MARK = "_qingqiuhu_file_rotating"


def setup_runtime_logging(*, backup_days: int = 90) -> Path | None:
    """初始化按日切割的文件日志；成功返回日志目录，失败返回 ``None``（不打断程序）。"""
    pkg_log = logging.getLogger(PKG_LOGGER_NAME)
    for h in pkg_log.handlers:
        if getattr(h, _APP_HANDLER_MARK, False):
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
