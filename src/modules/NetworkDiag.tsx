import { useEffect, useRef, useState } from "react";
import { revealItemInDir } from "@tauri-apps/plugin-opener";
import { onDiagnosisProgress, runDiagnosis } from "../lib/api";
import type { DiagnosisOutcome, Grade, OverallStatus, PortFailureClass } from "../lib/types";

const GRADE_LABEL: Record<Grade, string> = {
  excellent: "极佳",
  normal: "正常",
  poor: "较差",
  congested: "堵塞",
  unknown: "未知",
};

const STATUS_TONE: Record<OverallStatus, string> = {
  ok: "ok",
  degraded: "warn",
  failed: "bad",
};

const FAILURE_LABEL: Record<PortFailureClass, string> = {
  ok: "开放",
  timeout: "超时",
  refused: "拒绝",
  unreachable: "不可达",
  error: "错误",
  unknown: "未知",
};

export default function NetworkDiag() {
  const [target, setTarget] = useState("192.168.60.62");
  const [portsText, setPortsText] = useState("443");
  const [enablePing, setEnablePing] = useState(true);
  const [pingCount, setPingCount] = useState(4);
  const [samples, setSamples] = useState(3);

  const [running, setRunning] = useState(false);
  const [phase, setPhase] = useState("");
  const [error, setError] = useState("");
  const [outcome, setOutcome] = useState<DiagnosisOutcome | null>(null);

  const report = outcome?.report ?? null;

  const unlistenRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    let cancelled = false;
    void onDiagnosisProgress((msg) => setPhase(msg)).then((fn) => {
      if (cancelled) fn();
      else unlistenRef.current = fn;
    });
    return () => {
      cancelled = true;
      unlistenRef.current?.();
    };
  }, []);

  function parsePorts(): number[] {
    return portsText
      .split(/[,，\s]+/)
      .map((s) => s.trim())
      .filter(Boolean)
      .map((s) => {
        const n = Number(s);
        if (!Number.isInteger(n) || n < 1 || n > 65535) {
          throw new Error(`端口无效：${s}`);
        }
        return n;
      });
  }

  async function start() {
    setError("");
    setOutcome(null);
    setPhase("");
    setRunning(true);
    try {
      const ports = parsePorts();
      if (!target.trim()) throw new Error("请填写诊断目标。");
      const r = await runDiagnosis({
        target: target.trim(),
        ports,
        enablePing,
        pingCount,
        samplesPerPort: samples,
      });
      setOutcome(r);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning(false);
      setPhase("");
    }
  }

  async function revealReport() {
    if (!outcome) return;
    try {
      await revealItemInDir(outcome.reportPath);
    } catch {
      await navigator.clipboard.writeText(outcome.reportPath).catch(() => undefined);
      setError("无法定位文件，报告路径已复制到剪贴板。");
    }
  }

  return (
    <div className="stack">
      <section className="card">
        <div className="card-head">
          <span className="card-title">诊断目标</span>
          <span className="card-hint">原生 ICMP + TCP 探测，不依赖系统命令</span>
        </div>

        <div className="form-row">
          <div className="field" style={{ flex: "1 1 240px" }}>
            <label htmlFor="target">域名或 IP</label>
            <input
              id="target"
              className="input mono"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && !running && void start()}
              placeholder="example.com 或 192.168.1.1"
            />
          </div>
          <div className="field" style={{ flex: "1 1 200px" }}>
            <label htmlFor="ports">端口（逗号分隔，可留空）</label>
            <input
              id="ports"
              className="input mono"
              value={portsText}
              onChange={(e) => setPortsText(e.target.value)}
              placeholder="443, 80, 22"
            />
          </div>
          <button className="btn primary" onClick={() => void start()} disabled={running} type="button">
            {running ? "诊断中…" : "开始诊断"}
          </button>
        </div>

        <div className="form-row" style={{ marginTop: 12, alignItems: "center" }}>
          <label className="check">
            <input type="checkbox" checked={enablePing} onChange={(e) => setEnablePing(e.target.checked)} />
            <span>启用 ICMP</span>
          </label>
          <div className="field" style={{ width: 110 }}>
            <label htmlFor="pingCount">发包数</label>
            <input
              id="pingCount"
              className="input mono"
              value={pingCount}
              onChange={(e) => setPingCount(Number(e.target.value) || 1)}
              disabled={!enablePing}
            />
          </div>
          <div className="field" style={{ width: 130 }}>
            <label htmlFor="samples">每端口样本</label>
            <input
              id="samples"
              className="input mono"
              value={samples}
              onChange={(e) => setSamples(Number(e.target.value) || 1)}
            />
          </div>
        </div>

        {running && (
          <div className="progress-line">
            <span className="spin" />
            <span>{phase || "准备中…"}</span>
          </div>
        )}

        {error && (
          <div className="alert error" style={{ marginTop: 14 }}>
            {error}
          </div>
        )}
      </section>

      {report?.summary && (
        <section className="card">
          <div className="card-head">
            <span className="card-title">结论</span>
            <span className={`tag ${STATUS_TONE[report.summary.overall]}`}>
              {GRADE_LABEL[report.summary.grade]}
            </span>
          </div>
          <div className={`headline ${STATUS_TONE[report.summary.overall]}`}>{report.summary.headline}</div>
          <ul className="bullets">
            {report.summary.bullets.map((b) => (
              <li key={b}>{b}</li>
            ))}
          </ul>
          {report.summary.actions.length > 0 && (
            <div className="actions">
              <span className="actions-title">建议</span>
              <ul className="bullets">
                {report.summary.actions.map((a) => (
                  <li key={a}>{a}</li>
                ))}
              </ul>
            </div>
          )}
        </section>
      )}

      {outcome?.compare && (
        <section className="card">
          <div className="card-head">
            <span className="card-title">与上次诊断对比</span>
            <span className="card-hint">
              上次 {new Date(outcome.compare.previousFinishedAt).toLocaleString()}
            </span>
          </div>
          <div className="result-grid">
            <Cell
              k="档位变化"
              v={`${GRADE_LABEL[outcome.compare.previousGrade]} → ${GRADE_LABEL[outcome.compare.currentGrade]}`}
            />
            <Cell k="丢包变化" v={delta(outcome.compare.lossDelta, "%")} />
            <Cell k="平均时延变化" v={delta(outcome.compare.latencyDeltaMs, " ms")} />
            <Cell k="抖动变化" v={delta(outcome.compare.jitterDeltaMs, " ms")} />
          </div>
          <p className="compare-summary">{outcome.compare.summary}</p>
        </section>
      )}

      {outcome && (
        <section className="card report-bar">
          <div style={{ minWidth: 0 }}>
            <div className="cell-k">技术报告已生成</div>
            <div className="kv-v mono" style={{ marginTop: 4 }}>
              {outcome.reportPath}
            </div>
          </div>
          <button className="btn" onClick={() => void revealReport()} type="button">
            打开所在目录
          </button>
        </section>
      )}

      {report && (
        <div className="diag-grid">
          <section className="card">
            <div className="card-head">
              <span className="card-title">域名解析</span>
            </div>
            {report.dns ? (
              report.dns.error ? (
                <div className="alert error">{report.dns.error}</div>
              ) : (
                <div className="kv">
                  <div className="kv-row">
                    <span className="kv-k">地址</span>
                    <span className="kv-v">{report.dns.addresses.join(", ")}</span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-k">耗时</span>
                    <span className="kv-v">{report.dns.elapsedMs} ms</span>
                  </div>
                </div>
              )
            ) : (
              <div className="empty">未执行</div>
            )}
          </section>

          <section className="card">
            <div className="card-head">
              <span className="card-title">ICMP</span>
              {report.ping && (
                <span className="card-hint">
                  {report.ping.received}/{report.ping.attempted} 通
                </span>
              )}
            </div>
            {report.ping && report.ping.attempted > 0 ? (
              <>
                <div className="result-grid">
                  <Cell k="丢包率" v={`${(100 * report.ping.lost / report.ping.attempted).toFixed(0)}%`} />
                  <Cell k="平均" v={fmt(report.ping.avgMs, "ms")} />
                  <Cell k="最小" v={fmt(report.ping.minMs, "ms")} />
                  <Cell k="最大" v={fmt(report.ping.maxMs, "ms")} />
                </div>
                <RttBars rtts={report.ping.samples.map((s) => s.rttMs)} />
              </>
            ) : (
              <div className="empty">未启用或目标不响应 ICMP</div>
            )}
          </section>
        </div>
      )}

      {report && report.ports.length > 0 && (
        <section className="card">
          <div className="card-head">
            <span className="card-title">端口探测</span>
            <span className="card-hint">{report.ports.length} 个端口</span>
          </div>
          <table className="table">
            <thead>
              <tr>
                <th>端口</th>
                <th>状态</th>
                <th>成功率</th>
                <th>平均 RTT</th>
                <th>说明</th>
              </tr>
            </thead>
            <tbody>
              {report.ports.map((p) => {
                const rtts = p.samples.filter((s) => s.success && s.rttMs !== null).map((s) => s.rttMs as number);
                const avg = rtts.length ? rtts.reduce((a, b) => a + b, 0) / rtts.length : null;
                const detail = p.samples.find((s) => !s.success)?.detail ?? "";
                return (
                  <tr key={p.port}>
                    <td className="mono">{p.port}</td>
                    <td>
                      <span className={`tag ${p.failureClass === "ok" ? "ok" : "bad"}`}>
                        {FAILURE_LABEL[p.failureClass]}
                      </span>
                    </td>
                    <td className="mono">{Math.round(p.successRate * 100)}%</td>
                    <td className="mono">{avg === null ? "—" : `${avg.toFixed(1)} ms`}</td>
                    <td className="muted-cell">{detail}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </section>
      )}

      {report?.quality && (
        <section className="card">
          <div className="card-head">
            <span className="card-title">质量指标</span>
          </div>
          <ul className="bullets">
            {report.quality.metricLines.map((l) => (
              <li key={l}>{l}</li>
            ))}
          </ul>
        </section>
      )}

      {report?.degradations.length ? (
        <section className="card">
          <div className="card-head">
            <span className="card-title">降级事件</span>
          </div>
          <ul className="bullets">
            {report.degradations.map((d) => (
              <li key={d.code}>
                {d.message}
                {d.detail ? `：${d.detail}` : ""}
              </li>
            ))}
          </ul>
        </section>
      ) : null}
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

function fmt(v: number | null, unit: string) {
  return v === null ? "—" : `${v.toFixed(1)} ${unit}`;
}

function delta(v: number | null, unit: string) {
  if (v === null) return "—";
  if (Math.abs(v) < 0.05) return "持平";
  return `${v > 0 ? "+" : "-"}${Math.abs(v).toFixed(1)}${unit}`;
}

function RttBars({ rtts }: { rtts: (number | null)[] }) {
  const valid = rtts.filter((v): v is number => v !== null);
  if (valid.length === 0) return null;
  const max = Math.max(...valid, 1);
  const w = 14;
  const gap = 6;
  const h = 44;
  const width = rtts.length * (w + gap);

  return (
    <div style={{ marginTop: 12 }}>
      <div className="cell-k" style={{ marginBottom: 6 }}>
        RTT 序列
      </div>
      <svg width={Math.min(width, 420)} height={h + 4} role="img" aria-label="RTT 序列">
        {rtts.map((v, i) => {
          const bh = v === null ? 3 : Math.max(3, (v / max) * h);
          return (
            <rect
              key={i}
              x={i * (w + gap)}
              y={h - bh}
              width={w}
              height={bh}
              rx={2}
              fill={v === null ? "var(--danger)" : "var(--accent)"}
              opacity={v === null ? 0.5 : 0.85}
            />
          );
        })}
      </svg>
    </div>
  );
}
