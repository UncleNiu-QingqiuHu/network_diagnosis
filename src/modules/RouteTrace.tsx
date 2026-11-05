import { useEffect, useRef, useState } from "react";
import { localNetwork, onTraceProgress, probeMtu, traceRoute } from "../lib/api";
import type { MtuProbe, MtuReport, TraceHop, TraceReport } from "../lib/types";

const TARGET_KEY = "qqhu.trace.target";
const MTU_KEY = "qqhu.mtu.target";

const MTU_OUTCOME_LABEL: Record<string, string> = {
  ok: "通过",
  "too-big": "超出路径 MTU",
  "too-big-local": "本机接口拒绝发送",
  unreachable: "不可达",
  timeout: "超时",
  "send-error": "发送失败",
};

function fmtRtt(v: number | null): string {
  if (v == null) return "—";
  return v < 1 ? "<1 ms" : `${v.toFixed(1)} ms`;
}

export default function RouteTrace() {
  // ---------------- 路径追踪 ----------------
  const [target, setTarget] = useState(() => localStorage.getItem(TARGET_KEY) ?? "");
  const [maxHops, setMaxHops] = useState(30);
  const [timeoutMs, setTimeoutMs] = useState(1200);
  const [tracing, setTracing] = useState(false);
  const [liveHops, setLiveHops] = useState<TraceHop[]>([]);
  const [trace, setTrace] = useState<TraceReport | null>(null);
  const [traceError, setTraceError] = useState("");

  // ---------------- MTU 探测 ----------------
  const [mtuTarget, setMtuTarget] = useState(() => localStorage.getItem(MTU_KEY) ?? "");
  const [mtuBusy, setMtuBusy] = useState(false);
  const [mtu, setMtu] = useState<MtuReport | null>(null);
  const [mtuError, setMtuError] = useState("");

  const unlistenRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    let cancelled = false;
    void onTraceProgress((p) => {
      setLiveHops((prev) => {
        // 事件可能重放同一条，按 ttl 去重
        if (prev.some((h) => h.ttl === p.hop.ttl)) return prev;
        return [...prev, p.hop];
      });
    }).then((fn) => {
      if (cancelled) fn();
      else unlistenRef.current = fn;
    });
    return () => {
      cancelled = true;
      unlistenRef.current?.();
    };
  }, []);

  // MTU 探测的默认目标是本机网关：公网目标常屏蔽 ICMP，网关一定能回
  useEffect(() => {
    let cancelled = false;
    void localNetwork()
      .then((net) => {
        if (cancelled || !net.gateway) return;
        setMtuTarget((cur) => cur || net.gateway!);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, []);

  async function runTrace(t?: string) {
    const host = (t ?? target).trim();
    if (!host) {
      setTraceError("请填写目标域名或 IP。");
      return;
    }
    if (t) setTarget(t);
    localStorage.setItem(TARGET_KEY, host);

    setTraceError("");
    setTrace(null);
    setLiveHops([]);
    setTracing(true);
    try {
      const r = await traceRoute(host, maxHops, timeoutMs);
      setTrace(r);
    } catch (e) {
      setTraceError(e instanceof Error ? e.message : String(e));
    } finally {
      setTracing(false);
    }
  }

  async function runMtu(t?: string) {
    const host = (t ?? mtuTarget).trim();
    if (!host) {
      setMtuError("请填写目标域名或 IP。");
      return;
    }
    if (t) setMtuTarget(t);
    localStorage.setItem(MTU_KEY, host);

    setMtuError("");
    setMtu(null);
    setMtuBusy(true);
    try {
      setMtu(await probeMtu(host, timeoutMs));
    } catch (e) {
      setMtuError(e instanceof Error ? e.message : String(e));
    } finally {
      setMtuBusy(false);
    }
  }

  const hops = trace?.hops ?? liveHops;
  const reachedHop = hops.find((h) => h.reached);

  return (
    <div className="stack">
      <section className="card">
        <div className="card-head">
          <span className="card-title">路径追踪</span>
          <span className="card-hint">
            逐跳递增 TTL 发送 ICMP，定位在哪一跳开始不通
          </span>
        </div>

        <div className="form-row">
          <div className="field" style={{ flex: "1 1 240px" }}>
            <label htmlFor="trace-target">目标</label>
            <input
              id="trace-target"
              className="input mono"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && !tracing && void runTrace()}
              placeholder="www.example.com 或 114.114.114.114"
            />
          </div>
          <div className="field" style={{ width: 110 }}>
            <label htmlFor="trace-hops">最大跳数</label>
            <input
              id="trace-hops"
              className="input mono"
              value={maxHops}
              onChange={(e) => setMaxHops(Number(e.target.value) || 30)}
            />
          </div>
          <div className="field" style={{ width: 120 }}>
            <label htmlFor="trace-timeout">超时 (ms)</label>
            <input
              id="trace-timeout"
              className="input mono"
              value={timeoutMs}
              onChange={(e) => setTimeoutMs(Number(e.target.value) || 1200)}
            />
          </div>
          <button className="btn primary" onClick={() => void runTrace()} disabled={tracing} type="button">
            {tracing ? "追踪中…" : "开始追踪"}
          </button>
        </div>

        {traceError && (
          <div className="alert error" style={{ marginTop: 14 }}>
            {traceError}
          </div>
        )}

        {hops.length > 0 && (
          <>
            {tracing && (
              <div className="scan-progress" style={{ marginTop: 12 }}>
                <div className="scan-progress-line">
                  <span>已探测 {hops.length} 跳</span>
                </div>
              </div>
            )}

            {trace && (
              <div className="result-grid compact" style={{ marginTop: 12 }}>
                <Cell k="目标" v={trace.resolvedIp} />
                <Cell k="状态" v={trace.completed ? "已到达目标" : "未到达"} em={!trace.completed} />
                <Cell k="有效跳数" v={String(trace.hops.filter((h) => h.addr).length)} />
                <Cell k="耗时" v={`${(trace.durationMs / 1000).toFixed(1)} s`} />
              </div>
            )}

            <table className="table" style={{ marginTop: 12 }}>
              <thead>
                <tr>
                  <th style={{ width: 60 }}>跳</th>
                  <th>地址</th>
                  <th style={{ width: 110 }}>RTT</th>
                  <th style={{ width: 200 }}>备注</th>
                </tr>
              </thead>
              <tbody>
                {hops.map((h) => (
                  <tr key={h.ttl}>
                    <td className="mono">{h.ttl}</td>
                    <td className="mono">
                      {h.addr ? (
                        <span className={h.reached ? "cell-v em" : ""}>{h.addr}</span>
                      ) : (
                        <span className="muted-cell">* 无响应</span>
                      )}
                    </td>
                    <td className="mono">{fmtRtt(h.rttMs)}</td>
                    <td className="muted-cell">
                      {h.reached ? "目标" : (h.note ?? "")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}

        {trace?.warnings.length ? (
          <div className="alert warn" style={{ marginTop: 12 }}>
            {trace.warnings.map((w) => (
              <div key={w}>· {w}</div>
            ))}
          </div>
        ) : null}

        {reachedHop?.rttMs != null && trace?.completed && (
          <div className="alert info" style={{ marginTop: 12 }}>
            已在第 {reachedHop.ttl} 跳到达目标，往返 {fmtRtt(reachedHop.rttMs)}。
          </div>
        )}
      </section>

      <section className="card">
        <div className="card-head">
          <span className="card-title">路径 MTU 探测</span>
          <span className="card-hint">
            带 DF 标志二分探测，排查「网页能开但大文件卡住」一类的分片问题
          </span>
        </div>

        <div className="form-row">
          <div className="field" style={{ flex: "1 1 260px" }}>
            <label htmlFor="mtu-target">目标</label>
            <input
              id="mtu-target"
              className="input mono"
              value={mtuTarget}
              onChange={(e) => setMtuTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && !mtuBusy && void runMtu()}
              placeholder="通常填网关或目标服务器地址"
            />
          </div>
          <button className="btn primary" onClick={() => void runMtu()} disabled={mtuBusy} type="button">
            {mtuBusy ? "探测中…" : "探测 MTU"}
          </button>
          {/* 用路径追踪页面的目标一键带入，少打一次字 */}
          <button
            className="btn"
            type="button"
            disabled={mtuBusy || !target.trim()}
            onClick={() => {
              setMtuTarget(target.trim());
              void runMtu(target.trim());
            }}
          >
            用上方目标
          </button>
        </div>

        {mtuError && (
          <div className="alert error" style={{ marginTop: 14 }}>
            {mtuError}
          </div>
        )}

        {mtu && (
          <>
            <div className={`alert ${mtu.pathMtu === 1500 ? "ok" : mtu.pathMtu < 1500 ? "warn" : "info"}`} style={{ marginTop: 14 }}>
              <strong>路径 MTU：{mtu.pathMtu} 字节</strong>
              <span style={{ marginLeft: 8 }}>{mtu.summary}</span>
            </div>

            {mtu.warnings.length > 0 && (
              <div className="alert warn" style={{ marginTop: 12 }}>
                {mtu.warnings.map((w) => (
                  <div key={w}>· {w}</div>
                ))}
              </div>
            )}

            <table className="table" style={{ marginTop: 12 }}>
              <thead>
                <tr>
                  <th style={{ width: 90 }}>MTU</th>
                  <th style={{ width: 90 }}>载荷</th>
                  <th style={{ width: 160 }}>结果</th>
                  <th style={{ width: 100 }}>RTT</th>
                  <th>下一跳 MTU</th>
                </tr>
              </thead>
              <tbody>
                {mtu.probes.map((p, i) => (
                  <MtuRow key={`${p.mtu}-${i}`} probe={p} />
                ))}
              </tbody>
            </table>
          </>
        )}
      </section>
    </div>
  );
}

function MtuRow({ probe }: { probe: MtuProbe }) {
  const tone = probe.passed ? "ok" : probe.outcome === "timeout" ? "warn" : "bad";
  return (
    <tr>
      <td className="mono">{probe.mtu}</td>
      <td className="mono muted-cell">{probe.mtu - 28}</td>
      <td>
        <span className={`tag ${tone}`}>{MTU_OUTCOME_LABEL[probe.outcome] ?? probe.outcome}</span>
      </td>
      <td className="mono">{fmtRtt(probe.rttMs)}</td>
      <td className="mono muted-cell">{probe.nextHopMtu ?? "—"}</td>
    </tr>
  );
}

function Cell({ k, v, em }: { k: string; v: string; em?: boolean }) {
  return (
    <div className="cell">
      <span className="cell-k">{k}</span>
      <span className={`cell-v${em ? " em" : ""}`}>{v}</span>
    </div>
  );
}
