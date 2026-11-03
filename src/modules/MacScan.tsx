import { useEffect, useMemo, useRef, useState } from "react";
import { revealItemInDir } from "@tauri-apps/plugin-opener";
import {
  cancelScan,
  exportMacScanCsv,
  onMacScanProgress,
  runMacScan,
} from "../lib/api";
import type { ArpState, MacScanProgress, MacScanReport } from "../lib/types";

/** 表格一次性渲染上限，超出提示导出 CSV。 */
const MAX_ROWS = 500;

/** 上次使用的探测范围，存在本地避免每次重填。 */
const PROBE_INPUT_KEY = "qqhu.macscan.probeInput";

const STATE_LABEL: Record<ArpState, string> = {
  reachable: "可达",
  stale: "陈旧",
  permanent: "静态",
  incomplete: "不完整",
  other: "其它",
};

const STATE_TONE: Record<ArpState, string> = {
  reachable: "ok",
  stale: "muted",
  permanent: "info",
  incomplete: "warn",
  other: "muted",
};

export default function MacScan() {
  const [probeEnabled, setProbeEnabled] = useState(true);
  // 记住上次用的范围：本机网段不会经常变，记下来省得每次重填
  const [probeInput, setProbeInput] = useState(
    () => localStorage.getItem(PROBE_INPUT_KEY) ?? "192.168.1.0/24",
  );
  const [timeoutMs, setTimeoutMs] = useState(600);
  const [concurrency, setConcurrency] = useState(64);

  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<MacScanProgress | null>(null);
  const [report, setReport] = useState<MacScanReport | null>(null);
  const [csvPath, setCsvPath] = useState("");
  const [error, setError] = useState("");

  const [query, setQuery] = useState("");
  const [onlyOnline, setOnlyOnline] = useState(false);

  const unlistenRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    let cancelled = false;
    void onMacScanProgress((p) => setProgress(p)).then((fn) => {
      if (cancelled) fn();
      else unlistenRef.current = fn;
    });
    return () => {
      cancelled = true;
      unlistenRef.current?.();
    };
  }, []);

  async function start() {
    setError("");
    setReport(null);
    setCsvPath("");
    setProgress(null);
    setRunning(true);
    try {
      if (probeEnabled && !probeInput.trim()) {
        throw new Error("已启用主动探测，请填写探测范围。");
      }
      if (probeEnabled) {
        localStorage.setItem(PROBE_INPUT_KEY, probeInput.trim());
      }
      const r = await runMacScan({
        probeInput: probeEnabled ? probeInput.trim() : null,
        concurrency,
        timeoutMs,
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
      setCsvPath(await exportMacScanCsv(report));
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
    const q = query.trim().toLowerCase();
    return report.entries.filter((e) => {
      if (onlyOnline && e.alive !== true) return false;
      if (!q) return true;
      return (
        e.ip.includes(q) ||
        e.mac.toLowerCase().includes(q) ||
        e.vendor.toLowerCase().includes(q) ||
        e.interface.toLowerCase().includes(q)
      );
    });
  }, [report, query, onlyOnline]);

  const shown = rows.slice(0, MAX_ROWS);
  const pct = progress && progress.total > 0 ? (progress.done / progress.total) * 100 : 0;
  const onlineCount = report?.entries.filter((e) => e.alive === true).length ?? 0;

  return (
    <div className="stack">
      <section className="card">
        <div className="card-head">
          <span className="card-title">扫描方式</span>
          <span className="card-hint">本机 ARP 邻居表，无需管理员权限</span>
        </div>

        <label className="check" style={{ marginBottom: 12 }}>
          <input
            type="checkbox"
            checked={probeEnabled}
            onChange={(e) => setProbeEnabled(e.target.checked)}
            disabled={running}
          />
          <span>主动探测后再读表（更完整：先探活触发 ARP 解析）</span>
        </label>

        <div className="form-row">
          {probeEnabled && (
            <div className="field" style={{ flex: "1 1 260px" }}>
              <label htmlFor="mac-probe">探测范围</label>
              <input
                id="mac-probe"
                className="input mono"
                value={probeInput}
                onChange={(e) => setProbeInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && !running && void start()}
                placeholder="192.168.1.0/24"
                disabled={running}
              />
            </div>
          )}
          {probeEnabled && (
            <>
              <div className="field" style={{ width: 130 }}>
                <label htmlFor="mac-timeout">超时（ms）</label>
                <input
                  id="mac-timeout"
                  className="input mono"
                  value={timeoutMs}
                  onChange={(e) => setTimeoutMs(Number(e.target.value) || 600)}
                  disabled={running}
                />
              </div>
              <div className="field" style={{ width: 110 }}>
                <label htmlFor="mac-conc">并发数</label>
                <input
                  id="mac-conc"
                  className="input mono"
                  value={concurrency}
                  onChange={(e) => setConcurrency(Number(e.target.value) || 64)}
                  disabled={running}
                />
              </div>
            </>
          )}
          {running ? (
            <button className="btn" onClick={() => void stop()} type="button">
              取消
            </button>
          ) : (
            <button className="btn primary" onClick={() => void start()} type="button">
              开始扫描
            </button>
          )}
        </div>

        {running && (
          <div className="scan-progress">
            <div className="scan-bar">
              <div className="scan-bar-fill" style={{ width: `${pct}%` }} />
            </div>
            <div className="scan-progress-line">
              <span className="spin" />
              <span>{progress?.message ?? "准备中…"}</span>
              {progress && progress.total > 0 && (
                <>
                  <span className="scan-progress-sep" />
                  <span className="mono">
                    {progress.done} / {progress.total}
                  </span>
                </>
              )}
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
              <span className="card-title">邻居表</span>
              <span className="card-hint">
                采集于 {report.collectedAt}
                {report.probed > 0 && ` · 探测 ${report.probedAlive}/${report.probed} 在线`}
              </span>
            </div>

            <div className="result-grid compact">
              <Cell k="条目数" v={String(report.entries.length)} />
              <Cell
                k="已知厂商"
                v={`${report.entries.filter((e) => e.vendor).length} / ${report.entries.length}`}
              />
              <Cell k="在线条目" v={report.probed > 0 ? String(onlineCount) : "—"} />
            </div>

            {report.probed > 0 && onlineCount === 0 && report.entries.length > 0 && (
              <p className="compare-summary">
                探测到 {report.probedAlive} 台在线，但没有一条对得上邻居表 ——
                若探测范围不是本机所在网段，跨网段通信不经过 ARP，邻居表不会因此增加条目。
                请把范围改成本机网段（如当前网卡地址所在的 /24）。
              </p>
            )}

            <div className="table-toolbar">
              <label className="check">
                <input
                  type="checkbox"
                  checked={onlyOnline}
                  onChange={(e) => setOnlyOnline(e.target.checked)}
                  disabled={report.probed === 0}
                  title={report.probed === 0 ? "需启用主动探测才能判断在线状态" : ""}
                />
                <span>仅显示在线</span>
              </label>
              <input
                className="input"
                style={{ width: 200 }}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="按 IP / MAC / 厂商过滤"
              />
              <span className="muted-cell">
                {rows.length} / {report.entries.length} 条
              </span>
              <div style={{ marginLeft: "auto" }}>
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
                {report.entries.length === 0
                  ? "邻居表为空，勾选「主动探测」先扫一遍网段可填充"
                  : "没有匹配的记录"}
              </div>
            ) : (
              <>
                <table className="table" style={{ marginTop: 12 }}>
                  <thead>
                    <tr>
                      <th>IP 地址</th>
                      <th>MAC 地址</th>
                      <th>厂商</th>
                      <th>接口</th>
                      <th>状态</th>
                      <th>在线</th>
                    </tr>
                  </thead>
                  <tbody>
                    {shown.map((e) => (
                      <tr key={`${e.ip}-${e.mac}`}>
                        <td className="mono">{e.ip}</td>
                        <td className="mono">{e.mac}</td>
                        <td>{vendorText(e.vendor, e.mac, e.randomized)}</td>
                        <td className="muted-cell">{e.interface || "—"}</td>
                        <td>
                          <span className={`tag ${STATE_TONE[e.state]}`}>
                            {STATE_LABEL[e.state]}
                          </span>
                        </td>
                        <td>
                          {e.alive === null ? (
                            <span className="muted-cell">—</span>
                          ) : (
                            <span className={`tag ${e.alive ? "ok" : "bad"}`}>
                              {e.alive ? "在线" : "离线"}
                            </span>
                          )}
                        </td>
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

            <p className="compare-summary">
              厂商来自内置 OUI 库，未收录的前缀显示 6 位前缀原值。把 IEEE 的
              <code> oui.csv </code>放到程序目录的 <code>config/oui.csv</code> 可补齐全量数据，
              下次扫描即生效。
            </p>
          </section>
        </>
      )}
    </div>
  );
}

/** 厂商未知时给出 OUI 前缀便于自查；随机化地址单独标注。 */
function vendorText(vendor: string, mac: string, randomized: boolean) {
  if (vendor) return vendor;
  if (randomized) return <span className="muted-cell">本地随机地址</span>;
  const oui = mac.split(":").slice(0, 3).join("").toUpperCase();
  return <span className="muted-cell mono">OUI {oui}</span>;
}

function Cell({ k, v }: { k: string; v: string }) {
  return (
    <div className="cell">
      <span className="cell-k">{k}</span>
      <span className="cell-v">{v}</span>
    </div>
  );
}
