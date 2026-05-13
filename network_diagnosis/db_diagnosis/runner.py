"""单次完整诊断编排。"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from network_diagnosis.db_diagnosis.collect import collect_full
from network_diagnosis.db_diagnosis.connection import open_database_connection
from network_diagnosis.db_diagnosis.markdown_report import write_report_file
from network_diagnosis.db_diagnosis.model import DbDiagnosisReport
from network_diagnosis.paths import db_diagnosis_report_dir


@dataclass
class DbConnectConfig:
    engine: str
    host: str
    port: int
    user: str
    password: str
    database: str


def run_full_diagnosis(cfg: DbConnectConfig) -> DbDiagnosisReport:
    task_id = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
    out_dir = db_diagnosis_report_dir(task_id)
    started = datetime.now()
    conn = None
    errors: list[str] = []
    sections: dict[str, str] = {}
    version_line = ""
    try:
        conn = open_database_connection(
            cfg.engine,
            cfg.host,
            cfg.port,
            cfg.user,
            cfg.password,
            cfg.database,
            timeout_sec=12,
        )
        sections, version_line, errors = collect_full(cfg.engine, conn)
    except Exception as e:
        errors.append(str(e))
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception as e:
                errors.append(f"关闭连接：{e}")

    finished = datetime.now()
    ts = started.strftime("%Y%m%d-%H%M%S")
    md_path = out_dir / f"db-diagnosis_{ts}.md"
    report = DbDiagnosisReport(
        task_id=task_id,
        engine=cfg.engine,
        started_at=started,
        finished_at=finished,
        version_line=version_line,
        sections=sections,
        errors=errors,
        report_dir=out_dir,
        markdown_path=md_path,
    )
    host_hint = cfg.host if cfg.engine.lower() != "sqlite" else "(SQLite 文件)"
    db_hint = cfg.database or cfg.host
    write_report_file(report, host_hint=host_hint, db_hint=db_hint)
    return report
