"""引擎相关的采集与格式化。"""

from __future__ import annotations

from datetime import datetime
from typing import Any


def _cursor_columns(cur: Any) -> list[str]:
    if not cur.description:
        return []
    return [d[0] for d in cur.description]


def sql_to_markdown_table(rows: list[tuple], columns: list[str], max_rows: int = 50) -> str:
    if not rows:
        return "_（无行）_\n"
    show = rows[:max_rows]
    head = "| " + " | ".join(str(c) for c in columns) + " |"
    sep = "| " + " | ".join("---" for _ in columns) + " |"
    body = "\n".join("| " + " | ".join(str(v) if v is not None else "" for v in r) + " |" for r in show)
    tail = ""
    if len(rows) > max_rows:
        tail = f"\n\n_（仅显示前 {max_rows} 行，共 {len(rows)} 行）_\n"
    return head + "\n" + sep + "\n" + body + tail


def fetch_all(conn: Any, engine: str, sql: str) -> tuple[list[tuple], list[str], str | None]:
    eng = engine.lower()
    err: str | None = None
    try:
        if eng in ("postgresql", "postgres"):
            with conn.cursor() as cur:
                cur.execute(sql)
                cols = _cursor_columns(cur)
                rows = list(cur.fetchall())
                return rows, cols, None
        cur = conn.cursor()
        try:
            cur.execute(sql)
            cols = _cursor_columns(cur)
            rows = list(cur.fetchall())
            return rows, cols, None
        finally:
            try:
                cur.close()
            except Exception:
                pass
    except Exception as e:
        return [], [], str(e)


def collect_full_sqlite(conn: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    rows, cols, err = fetch_all(conn, "sqlite", "SELECT sqlite_version() AS version")
    if err:
        out["SQLite 版本"] = f"错误：`{err}`"
    else:
        out["SQLite 版本"] = sql_to_markdown_table(rows, cols)

    lines: list[str] = []
    for pragma, q in [
        ("page_count", "PRAGMA page_count"),
        ("page_size", "PRAGMA page_size"),
        ("journal_mode", "PRAGMA journal_mode"),
        ("foreign_keys", "PRAGMA foreign_keys"),
    ]:
        r2, c2, e2 = fetch_all(conn, "sqlite", q)
        if e2:
            lines.append(f"- {pragma}：错误 `{e2}`")
        elif r2:
            lines.append(f"- {pragma}：`{r2[0][0]}`")
    out["PRAGMA 摘要"] = "\n".join(lines) if lines else "_（无）_"

    r3, c3, e3 = fetch_all(conn, "sqlite", "SELECT COUNT(*) AS n FROM sqlite_master WHERE type='table'")
    if not e3 and r3:
        out["对象统计"] = f"- 用户表数量（近似）：`{r3[0][0]}`\n"
    else:
        out["对象统计"] = f"无法统计：`{e3}`\n"

    r4, _, e4 = fetch_all(conn, "sqlite", "PRAGMA quick_check")
    if e4:
        out["完整性 (quick_check)"] = f"错误：`{e4}`"
    else:
        bad = [str(x[0]) for x in r4 if str(x[0]).lower() != "ok"]
        if bad:
            out["完整性 (quick_check)"] = "\n".join(f"- `{b}`" for b in bad[:30])
            if len(bad) > 30:
                out["完整性 (quick_check)"] += f"\n\n_… 另有 {len(bad) - 30} 条问题行_"
        else:
            out["完整性 (quick_check)"] = "`ok`（抽查通过；大库仍建议备份后做离线校验）。"

    return out


def collect_full_mysql(conn: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    r, c, e = fetch_all(conn, "mysql", "SELECT VERSION() AS version")
    out["版本"] = sql_to_markdown_table(r, c) if not e else f"`{e}`"

    r2, c2, e2 = fetch_all(
        conn,
        "mysql",
        "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_status "
        "WHERE VARIABLE_NAME IN ('Threads_connected','Threads_running','Uptime','Questions','Queries')",
    )
    if e2:
        r2, c2, e2 = fetch_all(
            conn,
            "mysql",
            "SHOW GLOBAL STATUS WHERE Variable_name IN "
            "('Threads_connected','Threads_running','Uptime','Questions','Queries')",
        )
    out["连接与状态（节选）"] = (
        sql_to_markdown_table(r2, c2) if not e2 else f"无法读取：`{e2}`（可能无 performance_schema 权限，可授予 PROCESS）"
    )

    r3, c3, e3 = fetch_all(
        conn,
        "mysql",
        "SELECT table_schema AS db, "
        "ROUND(SUM(data_length+index_length)/1024/1024,2) AS size_mb "
        "FROM information_schema.tables "
        "WHERE table_schema NOT IN ('mysql','information_schema','performance_schema','sys') "
        "GROUP BY table_schema ORDER BY SUM(data_length+index_length) DESC LIMIT 15",
    )
    out["库级占用 Top"] = sql_to_markdown_table(r3, c3) if not e3 else f"`{e3}`"

    r4, c4, e4 = fetch_all(
        conn,
        "mysql",
        "SELECT ID, USER, HOST, DB, COMMAND, TIME, STATE, LEFT(INFO,120) AS info_preview "
        "FROM information_schema.processlist ORDER BY TIME DESC LIMIT 20",
    )
    out["进程列表（Top 20 最长）"] = sql_to_markdown_table(r4, c4, max_rows=20) if not e4 else f"`{e4}`"
    return out


def collect_full_postgresql(conn: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    r, c, e = fetch_all(conn, "postgresql", "SELECT version() AS v")
    out["版本"] = sql_to_markdown_table(r, c) if not e else f"`{e}`"

    r2, c2, e2 = fetch_all(
        conn,
        "postgresql",
        "SELECT d.datname, pg_size_pretty(pg_database_size(d.oid)) AS size_pretty, "
        "(SELECT count(*) FROM pg_stat_activity s WHERE s.datid = d.oid) AS backends "
        "FROM pg_database d WHERE d.datistemplate = false ORDER BY pg_database_size(d.oid) DESC LIMIT 15",
    )
    out["数据库大小与连接数"] = sql_to_markdown_table(r2, c2) if not e2 else f"`{e2}`"

    r3, c3, e3 = fetch_all(
        conn,
        "postgresql",
        "SELECT state, wait_event_type, count(*) AS n FROM pg_stat_activity "
        "GROUP BY state, wait_event_type ORDER BY n DESC",
    )
    out["会话状态分布"] = sql_to_markdown_table(r3, c3) if not e3 else f"`{e3}`"

    r4, c4, e4 = fetch_all(
        conn,
        "postgresql",
        "SELECT pid, usename, application_name, client_addr, state, wait_event_type, "
        "wait_event, query_start, SUBSTRING(query FROM 1 FOR 160) AS q FROM pg_stat_activity "
        "WHERE state <> 'idle' OR wait_event IS NOT NULL ORDER BY query_start NULLS LAST LIMIT 25",
    )
    out["活跃会话（节选）"] = sql_to_markdown_table(r4, c4, max_rows=25) if not e4 else f"`{e4}`"
    return out


def collect_full_sqlserver(conn: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    r, c, e = fetch_all(conn, "sqlserver", "SELECT @@VERSION AS version")
    out["版本"] = sql_to_markdown_table(r, c) if not e else f"`{e}`"

    r2, c2, e2 = fetch_all(
        conn,
        "sqlserver",
        "SELECT COUNT(*) AS user_sessions FROM sys.dm_exec_sessions WHERE is_user_process = 1",
    )
    out["用户会话数"] = sql_to_markdown_table(r2, c2) if not e2 else f"`{e2}`"

    r3, c3, e3 = fetch_all(
        conn,
        "sqlserver",
        "SELECT TOP 20 wait_type, waiting_tasks_count, wait_time_ms "
        "FROM sys.dm_os_wait_stats WHERE wait_type NOT LIKE 'SLEEP%' "
        "ORDER BY wait_time_ms DESC",
    )
    out["等待统计 Top 20"] = sql_to_markdown_table(r3, c3, max_rows=20) if not e3 else f"`{e3}`"

    r4, c4, e4 = fetch_all(
        conn,
        "sqlserver",
        "SELECT TOP (25) s.session_id, s.login_name, s.host_name, s.program_name, "
        "r.status, r.command, r.wait_type, r.cpu_time, r.total_elapsed_time, "
        "SUBSTRING(t.text, 1, 200) AS stmt "
        "FROM sys.dm_exec_sessions s "
        "LEFT JOIN sys.dm_exec_requests r ON s.session_id = r.session_id "
        "OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) t "
        "WHERE s.is_user_process = 1 ORDER BY r.total_elapsed_time DESC",
    )
    out["会话与请求（节选）"] = sql_to_markdown_table(r4, c4, max_rows=25) if not e4 else f"`{e4}`"
    return out


def collect_full_oracle(conn: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    r, c, e = fetch_all(conn, "oracle", "SELECT banner FROM v$version WHERE banner LIKE 'Oracle%' AND ROWNUM = 1")
    if e or not r:
        r, c, e = fetch_all(conn, "oracle", "SELECT banner FROM v$version WHERE ROWNUM = 1")
    out["版本"] = sql_to_markdown_table(r, c) if not e else f"`{e}`"

    r2, c2, e2 = fetch_all(
        conn,
        "oracle",
        "SELECT * FROM ("
        "SELECT username, COUNT(*) AS n FROM v$session WHERE username IS NOT NULL "
        "GROUP BY username ORDER BY COUNT(*) DESC) WHERE ROWNUM <= 20",
    )
    out["按用户会话数"] = sql_to_markdown_table(r2, c2) if not e2 else f"`{e2}`"

    r3, c3, e3 = fetch_all(
        conn,
        "oracle",
        "SELECT * FROM (SELECT event, COUNT(*) AS n FROM v$session WHERE username IS NOT NULL "
        "GROUP BY event ORDER BY COUNT(*) DESC) WHERE ROWNUM <= 20",
    )
    out["等待事件分布（节选）"] = sql_to_markdown_table(r3, c3) if not e3 else f"`{e3}`"
    return out


def collect_full(engine: str, conn: Any) -> tuple[dict[str, str], str, list[str]]:
    eng = engine.lower()
    errors: list[str] = []
    version_line = ""
    sections: dict[str, str] = {}

    try:
        if eng == "sqlite":
            sections = collect_full_sqlite(conn)
            r, _, e = fetch_all(conn, "sqlite", "SELECT sqlite_version()")
            if r:
                version_line = f"SQLite {r[0][0]}"
        elif eng == "mysql":
            sections = collect_full_mysql(conn)
            r, _, e = fetch_all(conn, "mysql", "SELECT VERSION()")
            if r:
                version_line = str(r[0][0])
        elif eng in ("postgresql", "postgres"):
            sections = collect_full_postgresql(conn)
            r, _, e = fetch_all(conn, "postgresql", "SELECT version()")
            if r:
                version_line = str(r[0][0])[:200]
        elif eng in ("sqlserver", "mssql"):
            sections = collect_full_sqlserver(conn)
            r, _, e = fetch_all(conn, "sqlserver", "SELECT CAST(SERVERPROPERTY('ProductVersion') AS VARCHAR(64))")
            if r:
                version_line = f"SQL Server {r[0][0]}"
            else:
                r2, _, _ = fetch_all(conn, "sqlserver", "SELECT @@VERSION")
                if r2:
                    version_line = str(r2[0][0]).split("\n")[0][:200]
        elif eng == "oracle":
            sections = collect_full_oracle(conn)
            r, _, e = fetch_all(conn, "oracle", "SELECT banner FROM v$version WHERE ROWNUM = 1")
            if r:
                version_line = str(r[0][0])[:200]
        else:
            errors.append(f"未知引擎：{engine}")
    except Exception as e:
        errors.append(str(e))

    return sections, version_line, errors


def monitor_lines(engine: str, conn: Any) -> list[str]:
    """单次轻量快照，供实时刷新。"""
    eng = engine.lower()
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [f"**采样时间** {ts}", ""]

    if eng == "sqlite":
        r, _, e = fetch_all(conn, "sqlite", "PRAGMA page_count")
        r2, _, e2 = fetch_all(conn, "sqlite", "PRAGMA page_size")
        if not e and not e2 and r and r2:
            pages = int(r[0][0])
            ps = int(r2[0][0])
            lines.append(f"- 页数 × 页大小 ≈ **{pages * ps / 1024 / 1024:.2f} MiB**（粗略）")
        je, _, _ = fetch_all(conn, "sqlite", "PRAGMA journal_mode")
        if je:
            lines.append(f"- journal_mode：`{je[0][0]}`")

    elif eng == "mysql":
        r, _, e = fetch_all(
            conn,
            "mysql",
            "SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='Threads_connected'",
        )
        if e:
            r, _, _ = fetch_all(conn, "mysql", "SHOW GLOBAL STATUS LIKE 'Threads_connected'")
        if r:
            lines.append(f"- Threads_connected：`{r[0][0]}`")
        r2, _, _ = fetch_all(
            conn,
            "mysql",
            "SELECT COUNT(*) FROM information_schema.processlist WHERE command <> 'Sleep'",
        )
        if r2:
            lines.append(f"- 非 Sleep 连接数：`{r2[0][0]}`")

    elif eng in ("postgresql", "postgres"):
        r, _, _ = fetch_all(conn, "postgresql", "SELECT count(*) FROM pg_stat_activity")
        if r:
            lines.append(f"- pg_stat_activity 总行数：`{r[0][0]}`")
        r2, _, _ = fetch_all(
            conn,
            "postgresql",
            "SELECT count(*) FROM pg_stat_activity WHERE state = 'active'",
        )
        if r2:
            lines.append(f"- active：`{r2[0][0]}`")

    elif eng in ("sqlserver", "mssql"):
        r, _, _ = fetch_all(
            conn,
            "sqlserver",
            "SELECT COUNT(*) FROM sys.dm_exec_sessions WHERE is_user_process = 1",
        )
        if r:
            lines.append(f"- 用户会话：`{r[0][0]}`")
        r2, _, _ = fetch_all(
            conn,
            "sqlserver",
            "SELECT COUNT(*) FROM sys.dm_exec_requests WHERE session_id IS NOT NULL",
        )
        if r2:
            lines.append(f"- dm_exec_requests（节选计数）：`{r2[0][0]}`")

    elif eng == "oracle":
        r, _, _ = fetch_all(conn, "oracle", "SELECT COUNT(*) FROM v$session WHERE username IS NOT NULL")
        if r:
            lines.append(f"- 有用户名会话：`{r[0][0]}`")

    else:
        lines.append(f"- （未实现引擎 `{engine}` 的监控快照）")

    return lines


# Oracle 12c 前无 FETCH FIRST — might fail on old Oracle. User base might be 19c+. If error, full collect shows.
