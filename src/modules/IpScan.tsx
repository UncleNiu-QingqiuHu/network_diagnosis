import { useEffect, useMemo, useRef, useState } from "react";
import { revealItemInDir } from "@tauri-apps/plugin-opener";
import { cancelScan, exportIpScanCsv, onIpScanProgress, startIpScan } from "../lib/api";
import type { IpScanProgress, IpScanReport, ProbeMethod } from "../lib/types";

/** 表格一次性渲染的行数上限：/20 这种范围下全量渲染会把界面拖死，超出提示导出 CSV。 */
const MAX_ROWS = 500;

const METHOD_LABEL: Record<ProbeMethod, string> = {
  icmp: "ICMP",
  tcp: "TCP",
  none: "无响应",
};

export default function IpScan() {
  const [input, setInput] = useState("192.168.1.0/24");
  const [count, setCount] = useState(1);
  const [timeoutMs, setTimeoutMs] = useState(800);
  const [concurrency, setConcurrency] = useState(64);
  const [tcpText, setTcpText] = useState("");

  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<IpScanProgress | null>(null);
  const [report, setReport] = useState<IpScanReport | null>(null);
  const [csvPath, setCsvPath] = useState("");
  const [error, setError] = useState("");

  const [onlyAlive, setOnlyAlive] = useState(true);
  const [query, setQuery] = useState("");

  const unlistenRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    let cancelled = false;
    void onIpScanProgress((p) => setProgress(p)).then((fn) => {
      if (cancelled) fn();
      else unlistenRef.current = fn;
    });
    return () => {
      cancelled = true;
      unlistenRef.current?.();
    };
  }, []);

  function parseTcpPorts(): number[] {
    return tcpText
      .split(/[,，\s]+/)
      .map((s) => s.trim())
      .filter(Boolean)
      .map((s) => {
        const n = Number(s);
        if (!Number.isInteger(n) || n < 1 || n > 65535) {
          throw new Error(`兜底端口无效：${s}`);
        }
        return n;
      });
  }

  async function start() {
    setError("");
    setReport(null);
    setCsvPath("");
    setProgress(null);
    setRunning(true);
    try {
      if (!input.trim()) throw new Error("请填写扫描范围。");
      const r = await startIpScan({
        input: input.trim(),
        count,
        timeoutMs,
        concurrency,
        tcpPorts: parseTcpPorts(),
      });
      setReport(r);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning(false);
      setProgress(null);
    }
  }

  async function stop() {
    try {
      await cancelScan();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function exportCsv() {
    if (!report) return;
    try {
      const p = await exportIpScanCsv(report);
      setCsvPath(p);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function revealFile(path: string) {
    try {
      await revealItemInDir(path);
    } catch {
      await navigator.clipboard.writeText(path).catch(() => undefined);
      setError("无法定位文件，路径已复制到剪贴板。");
    }
  }

  const rows = useMemo(() => {
    if (!report) return [];
    const q = query.trim();
    return report.hosts.filter((h) => {
      if (onlyAlive && !h.alive) return false;
      if (q && !h.ip.includes(q)) return false;
      return true;
    });
  }, [report, onlyAlive, query]);

  const shown = rows.slice(0, MAX_ROWS);
  const pct = progress && progress.total > 0 ? (progress.done / progress.total) * 100 : 0;

  return (
    <div className="stack">
      <section className="card">
        <div className="card-head">
          <span className="card-title">扫描范围</span>
          <span className="card-hint">原生 ICMP 并发探测，不依赖 ping 命令与外部程序</span>
        </div>

        <div className="form-row">
          <div className="field" style={{ flex: "1 1 280px" }}>
            <label htmlFor="scan-input">网段 / 区间 / 单个 IP</label>
            <input
              id="scan-input"
              className="input mono"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && !running && void start()}
              placeholder="192.168.1.0/24 或 192.168.1.10-50"
              disabled={running}
            />
          </div>
          {running ? (
            <button className="btn" onClick={() => void stop()} type="button">
              取消扫描
            </button>
          ) : (
            <button className="btn primary" onClick={() => void start()} type="button">
              开始扫描
            </button>
          )}
        </div>

        <div className="form-row" style={{ marginTop: 12 }}>
          <div className="field" style={{ width: 120 }}>
            <label htmlFor="scan-count">每 IP 发包</label>
            <input
              id="scan-count"
              className="input mono"
              value={count}
              onChange={(e) => setCount(Number(e.target.value) || 1)}
              disabled={running}
            />
          </div>
          <div className="field" style={{ width: 130 }}>
            <label htmlFor="scan-timeout">超时（ms）</label>
            <input
              id="scan-timeout"
              className="input mono"
              value={timeoutMs}
              onChange={(e) => setTimeoutMs(Number(e.target.value) || 800)}
              disabled={running}
            />
          </div>
          <div className="field" style={{ width: 110 }}>
            <label htmlFor="scan-conc">并发数</label>
            <input
              id="scan-conc"
              className="input mono"
              value={concurrency}
              onChange={(e) => setConcurrency(Number(e.target.value) || 64)}
              disabled={running}
            />
          </div>
          <div className="field" style={{ flex: "1 1 200px" }}>
            <label htmlFor="scan-tcp">TCP 兜底端口</label>
            <input
              id="scan-tcp"
              className="input mono"
              value={tcpText}
              onChange={(e) => setTcpText(e.target.value)}
              placeholder="445, 3389（可选）"
              disabled={running}
            />
          </div>
        </div>

        {running && (
          <div className="scan-progress">
            <div className="scan-bar">
              <div className="scan-bar-fill" style={{ width: `${pct}%` }} />
            </div>
            <div className="scan-progress-line">
              <span className="spin" />
              <span className="mono">
                {progress ? `${progress.done} / ${progress.total}` : "准备中…"}
              </span>
              <span className="scan-progress-sep" />
              <span>
                存活 <b>{progress?.alive ?? 0}</b>
              </span>
              {progress?.current && <span className="muted-cell">{progress.current}</span>}
            </div>
          </div>
        )}

        {error && (
          <div className="alert error" style={{ marginTop: 14 }}>
            {error}
          </div>
        )}
      </section>

      {report && (
        <>
          {report.warnings.length > 0 && (
            <div className="alert warn">
              {report.warnings.map((w) => (
                <div key={w}>{w}</div>
              ))}
            </div>
          )}

          <section className="card">
            <div className="card-head">
              <span className="card-title">扫描结果</span>
              <span className="card-hint">
                {report.scopeDesc} ·{(report.durationMs / 1000).toFixed(1)} s
                {report.cancelled ? " · 已取消" : ""}
              </span>
            </div>

            <div className="result-grid compact">
              <Cell k="地址总数" v={String(report.total)} />
              <Cell k="存活主机" v={String(report.aliveCount)} />
              <Cell
                k="存活率"
                v={report.total ? `${((report.aliveCount / report.total) * 100).toFixed(0)}%` : "—"}
              />
              <Cell k="耗时" v={`${(report.durationMs / 1000).toFixed(1)} s`} />
            </div>

            {report.aliveCount === 0 && !report.cancelled && (
              <div className="alert warn" style={{ marginTop: 12 }}>
                全部地址无响应。若目标确实在线，通常是网络禁用了 ICMP：
                在「TCP 兜底端口」里填一个该主机会开放的端口（如 445、3389、80）后重新扫描。
              </div>
            )}

            <div className="table-toolbar">
              <label className="check">
                <input
                  type="checkbox"
                  checked={onlyAlive}
                  onChange={(e) => setOnlyAlive(e.target.checked)}
                />
                <span>仅显示存活</span>
              </label>
              <input
                className="input mono"
                style={{ width: 180 }}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="按 IP 过滤"
              />
              <span className="muted-cell">
                {rows.length} / {report.hosts.length} 条
              </span>
              <div style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
                <button className="btn" onClick={() => void exportCsv()} type="button">
                  导出 CSV
                </button>
              </div>
            </div>

            {csvPath && (
              <div className="report-bar" style={{ marginTop: 10 }}>
                <div style={{ minWidth: 0 }}>
                  <div className="cell-k">CSV 已导出</div>
                  <div className="kv-v mono" style={{ marginTop: 4 }}>
                    {csvPath}
                  </div>
                </div>
                <button className="btn" onClick={() => void revealFile(csvPath)} type="button">
                  打开所在目录
                </button>
              </div>
            )}

            {rows.length === 0 ? (
              <div className="empty" style={{ marginTop: 12 }}>
                {onlyAlive ? "没有存活主机，取消勾选「仅显示存活」可查看全部" : "没有匹配的记录"}
              </div>
            ) : (
              <>
                <table className="table" style={{ marginTop: 12 }}>
                  <thead>
                    <tr>
                      <th>IP 地址</th>
                      <th>状态</th>
                      <th>判定</th>
                      <th>RTT</th>
                      <th>丢包</th>
                      <th>端口</th>
                    </tr>
                  </thead>
                  <tbody>
                    {shown.map((h) => (
                      <tr key={h.ip}>
                        <td className="mono">{h.ip}</td>
                        <td>
                          <span className={`tag ${h.alive ? "ok" : "muted"}`}>
                            {h.alive ? "存活" : "无响应"}
                          </span>
                        </td>
                        <td className="mono">{METHOD_LABEL[h.method]}</td>
                        <td className="mono">
                          {h.rttMs === null ? "—" : `${h.rttMs.toFixed(1)} ms`}
                        </td>
                        <td className="mono">{h.lossPercent.toFixed(0)}%</td>
                        <td className="mono">{h.openPort ?? "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {rows.length > MAX_ROWS && (
                  <p className="compare-summary">
                    共 {rows.length} 条，表格仅显示前 {MAX_ROWS} 条；完整结果请导出 CSV。
                  </p>
                )}
              </>
            )}
          </section>
        </>
      )}
    </div>
  );
}

function Cell({ k, v }: { k: string; v: string }) {
  return (
    <div className="cell">
      <span className="cell-k">{k}</span>
      <span className="cell-v">{v}</span>
    </div>
  );
}
