"""按引擎建立数据库连接（只读会话偏好由调用方控制）。"""

from __future__ import annotations

import sqlite3
from typing import Any


def open_database_connection(
    engine: str,
    host: str,
    port: int,
    user: str,
    password: str,
    database: str,
    *,
    timeout_sec: int = 10,
) -> Any:
    eng = engine.strip().lower()
    if eng == "sqlite":
        path = (host or database or "").strip()
        if not path:
            raise ValueError("SQLite 请填写「数据库路径」（主机栏或库名栏）。")
        return sqlite3.connect(path, timeout=float(timeout_sec), isolation_level=None, check_same_thread=False)

    if eng == "mysql":
        try:
            import pymysql
        except ImportError as e:
            raise RuntimeError("缺少 PyMySQL，请执行：pip install pymysql") from e
        return pymysql.connect(
            host=(host or "127.0.0.1").strip(),
            port=int(port or 3306),
            user=user,
            password=password,
            database=(database or "").strip() or None,
            connect_timeout=timeout_sec,
            read_timeout=max(timeout_sec * 2, 15),
            charset="utf8mb4",
        )

    if eng in ("postgresql", "postgres"):
        try:
            import psycopg
        except ImportError as e:
            raise RuntimeError("缺少 psycopg，请执行：pip install psycopg[binary]") from e
        if not (database or "").strip():
            raise ValueError("PostgreSQL 请填写数据库名（库名）。")
        return psycopg.connect(
            host=(host or "127.0.0.1").strip(),
            port=int(port or 5432),
            dbname=database.strip(),
            user=user,
            password=password,
            connect_timeout=timeout_sec,
            autocommit=True,
        )

    if eng in ("sqlserver", "mssql"):
        try:
            import pyodbc
        except ImportError as e:
            raise RuntimeError("缺少 pyodbc，请执行：pip install pyodbc 并安装 Microsoft ODBC Driver for SQL Server") from e
        if not (database or "").strip():
            raise ValueError("SQL Server 请填写数据库名（库名）。")
        srv = (host or "127.0.0.1").strip()
        if port and port != 1433:
            server = f"{srv},{port}"
        else:
            server = srv
        drivers = [
            "ODBC Driver 18 for SQL Server",
            "ODBC Driver 17 for SQL Server",
            "SQL Server",
        ]
        last_err: Exception | None = None
        for drv in drivers:
            try:
                conn_s = (
                    f"DRIVER={{{drv}}};SERVER={server};DATABASE={database.strip()};"
                    f"UID={user};PWD={password};TrustServerCertificate=yes;"
                )
                return pyodbc.connect(conn_s, timeout=timeout_sec)
            except Exception as e:
                last_err = e
                continue
        raise RuntimeError(f"无法连接 SQL Server（ODBC）。最后错误：{last_err}") from last_err

    if eng == "oracle":
        try:
            import oracledb
        except ImportError as e:
            raise RuntimeError("缺少 python-oracledb，请执行：pip install oracledb") from e
        if not (database or "").strip():
            raise ValueError("Oracle 请填写 Service Name / PDB 服务名（库名栏）。")
        return oracledb.connect(
            user=user,
            password=password,
            host=(host or "127.0.0.1").strip(),
            port=int(port or 1521),
            service_name=database.strip(),
        )

    raise ValueError(f"不支持的引擎：{engine}")
