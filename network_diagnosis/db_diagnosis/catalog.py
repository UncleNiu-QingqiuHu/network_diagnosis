"""在数据库实例上枚举可见库名（供 GUI 下拉选择）。"""

from __future__ import annotations

from typing import Any

_EXCLUDE_MYSQL = frozenset({"information_schema", "performance_schema", "mysql", "sys"})


def list_database_names(
    engine: str,
    host: str,
    port: int,
    user: str,
    password: str,
    *,
    timeout_sec: int = 15,
) -> list[str]:
    """返回实例上当前账号可见的逻辑库名列表（已排序、去重）。

    - **MySQL**：``SHOW DATABASES``（剔除常见系统库）。
    - **PostgreSQL**：先连 ``postgres``，失败则尝试 ``template1``，再查询 ``pg_database``。
    - **SQL Server**：连 ``master``，查询 ``sys.databases``。
    - **SQLite / Oracle**：不适用（由界面禁用枚举）。
    """
    eng = engine.strip().lower()
    if eng == "sqlite":
        raise ValueError("SQLite 请直接在「主机 / 路径」或「库名」栏填写数据库文件路径。")
    if eng == "oracle":
        raise ValueError("Oracle 使用 Service Name 连接，无法在无目标服务的前提下枚举；请手动填写。")

    if eng == "mysql":
        return _list_mysql(host, port, user, password, timeout_sec=timeout_sec)
    if eng in ("postgresql", "postgres"):
        return _list_postgresql(host, port, user, password, timeout_sec=timeout_sec)
    if eng in ("sqlserver", "mssql"):
        return _list_sqlserver(host, port, user, password, timeout_sec=timeout_sec)

    raise ValueError(f"不支持的引擎：{engine}")


def _list_mysql(host: str, port: int, user: str, password: str, *, timeout_sec: int) -> list[str]:
    try:
        import pymysql
    except ImportError as e:
        raise RuntimeError("缺少 PyMySQL，请执行：pip install pymysql") from e

    conn = pymysql.connect(
        host=(host or "127.0.0.1").strip(),
        port=int(port or 3306),
        user=user,
        password=password,
        database=None,
        connect_timeout=timeout_sec,
        read_timeout=max(timeout_sec * 2, 15),
        charset="utf8mb4",
    )
    try:
        with conn.cursor() as cur:
            cur.execute("SHOW DATABASES")
            rows = cur.fetchall()
        names: list[str] = []
        for row in rows:
            if not row:
                continue
            n = row[0]
            if isinstance(n, bytes):
                n = n.decode("utf-8", errors="replace")
            if isinstance(n, str) and n and n not in _EXCLUDE_MYSQL:
                names.append(n)
        return sorted(set(names), key=str.casefold)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _list_postgresql(host: str, port: int, user: str, password: str, *, timeout_sec: int) -> list[str]:
    try:
        import psycopg
    except ImportError as e:
        raise RuntimeError("缺少 psycopg，请执行：pip install psycopg[binary]") from e

    last_err: Exception | None = None
    conn: Any = None
    for dbname in ("postgres", "template1"):
        try:
            conn = psycopg.connect(
                host=(host or "127.0.0.1").strip(),
                port=int(port or 5432),
                dbname=dbname,
                user=user,
                password=password,
                connect_timeout=timeout_sec,
                autocommit=True,
            )
            break
        except Exception as e:
            last_err = e
            conn = None
    if conn is None:
        raise RuntimeError(
            "无法在 postgres / template1 上建立连接以枚举库名（权限或网络原因）。"
            f" 最后错误：{last_err}"
        ) from last_err
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY datname"
            )
            rows = cur.fetchall()
        names = [str(r[0]) for r in rows if r and r[0]]
        return sorted(set(names), key=str.casefold)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _list_sqlserver(host: str, port: int, user: str, password: str, *, timeout_sec: int) -> list[str]:
    try:
        import pyodbc
    except ImportError as e:
        raise RuntimeError(
            "缺少 pyodbc，请执行：pip install pyodbc 并安装 Microsoft ODBC Driver for SQL Server"
        ) from e

    srv = (host or "127.0.0.1").strip()
    server = f"{srv},{port}" if port and port != 1433 else srv
    drivers = [
        "ODBC Driver 18 for SQL Server",
        "ODBC Driver 17 for SQL Server",
        "SQL Server",
    ]
    last_err: Exception | None = None
    conn: Any = None
    for drv in drivers:
        try:
            conn_s = (
                f"DRIVER={{{drv}}};SERVER={server};DATABASE=master;"
                f"UID={user};PWD={password};TrustServerCertificate=yes;"
            )
            conn = pyodbc.connect(conn_s, timeout=timeout_sec)
            break
        except Exception as e:
            last_err = e
            conn = None
    if conn is None:
        raise RuntimeError(f"无法连接 SQL Server（master）。最后错误：{last_err}") from last_err
    try:
        cur = conn.cursor()
        cur.execute("SELECT name FROM sys.databases ORDER BY name")
        rows = cur.fetchall()
        names = [str(r[0]) for r in rows if r and r[0]]
        return sorted(set(names), key=str.casefold)
    finally:
        try:
            conn.close()
        except Exception:
            pass
