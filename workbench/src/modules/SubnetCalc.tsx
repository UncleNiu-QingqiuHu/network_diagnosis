import { useState } from "react";
import { subnetCalc, subnetFromCidr, subnetSubdivide } from "../lib/api";
import type { SubnetCalcResult } from "../lib/types";

type Mode = "prefix" | "netmask";

const PRESETS = ["192.168.1.10/24", "10.20.30.40/22", "172.16.5.9/255.255.0.0", "203.0.113.7/30"];

export default function SubnetCalc() {
  const [ip, setIp] = useState("192.168.1.10");
  const [mode, setMode] = useState<Mode>("prefix");
  const [prefix, setPrefix] = useState("24");
  const [netmask, setNetmask] = useState("255.255.255.0");
  const [result, setResult] = useState<SubnetCalcResult | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const [parent, setParent] = useState("192.168.1.0/24");
  const [child, setChild] = useState("26");
  const [tree, setTree] = useState("");

  async function run() {
    setBusy(true);
    setError("");
    try {
      const p = mode === "prefix" ? Number(prefix) : null;
      if (p !== null && (!Number.isInteger(p) || p < 0 || p > 32)) {
        throw new Error("前缀长度须在 0–32 之间。");
      }
      const r = await subnetCalc(ip, p, mode === "netmask" ? netmask : null);
      setResult(r);
    } catch (e) {
      setResult(null);
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function runCombo(text: string) {
    setBusy(true);
    setError("");
    try {
      setResult(await subnetFromCidr(text));
    } catch (e) {
      setResult(null);
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function runSubdivide() {
    setError("");
    setTree("");
    try {
      const c = Number(child);
      if (!Number.isInteger(c) || c < 0 || c > 32) throw new Error("子网前缀须在 0–32 之间。");
      setTree(await subnetSubdivide(parent, c, 64));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div className="stack">
      <section className="card">
        <div className="card-head">
          <span className="card-title">按主机地址计算所属网段</span>
          <div className="segmented">
            <button className={mode === "prefix" ? "on" : ""} onClick={() => setMode("prefix")} type="button">
              前缀
            </button>
            <button className={mode === "netmask" ? "on" : ""} onClick={() => setMode("netmask")} type="button">
              点分掩码
            </button>
          </div>
        </div>

        <div className="form-row">
          <div className="field" style={{ flex: "1 1 200px" }}>
            <label htmlFor="ip">IPv4 地址</label>
            <input
              id="ip"
              className="input mono"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && void run()}
              placeholder="192.168.1.10"
            />
          </div>

          {mode === "prefix" ? (
            <div className="field" style={{ width: 110 }}>
              <label htmlFor="prefix">前缀长度</label>
              <input
                id="prefix"
                className="input mono"
                value={prefix}
                onChange={(e) => setPrefix(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && void run()}
                placeholder="24"
              />
            </div>
          ) : (
            <div className="field" style={{ flex: "1 1 180px" }}>
              <label htmlFor="mask">子网掩码</label>
              <input
                id="mask"
                className="input mono"
                value={netmask}
                onChange={(e) => setNetmask(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && void run()}
                placeholder="255.255.255.0"
              />
            </div>
          )}

          <button className="btn primary" onClick={() => void run()} disabled={busy} type="button">
            {busy ? "计算中…" : "计算"}
          </button>
        </div>

        <div className="form-row" style={{ marginTop: 12, gap: 8 }}>
          {PRESETS.map((p) => (
            <button
              key={p}
              className="btn"
              style={{ height: 26, padding: "0 10px", fontSize: 11, fontFamily: "var(--mono)" }}
              onClick={() => void runCombo(p)}
              type="button"
            >
              {p}
            </button>
          ))}
        </div>

        {error && (
          <div className="alert error" style={{ marginTop: 14 }}>
            {error}
          </div>
        )}
      </section>

      {result && (
        <section className="card">
          <div className="card-head">
            <span className="card-title">计算结果</span>
            <span className="card-hint">输入 {result.inputInterface}</span>
          </div>
          <div className="result-grid">
            <Cell k="网络地址 (CIDR)" v={result.networkCidr} em />
            <Cell k="网络地址" v={result.networkAddress} />
            <Cell k="广播地址" v={result.broadcastAddress} />
            <Cell k="子网掩码" v={result.netmask} />
            <Cell k="反掩码 (wildcard)" v={result.wildcardMask} />
            <Cell k="前缀长度" v={`/${result.prefixLen}`} />
            <Cell k="地址总数" v={result.totalAddresses.toLocaleString()} />
            <Cell k="可用主机数" v={result.usableHosts.toLocaleString()} em />
            <Cell k="首个可用地址" v={result.firstHost} />
            <Cell k="末个可用地址" v={result.lastHost} />
            <Cell k="网段属性" v={result.scopeNote} note />
            <Cell k="输入地址角色" v={result.hostRoleNote} note />
          </div>
        </section>
      )}

      <section className="card">
        <div className="card-head">
          <span className="card-title">等长子网划分</span>
          <span className="card-hint">最多列出 64 条</span>
        </div>
        <div className="form-row">
          <div className="field" style={{ flex: "1 1 220px" }}>
            <label htmlFor="parent">父网 CIDR</label>
            <input
              id="parent"
              className="input mono"
              value={parent}
              onChange={(e) => setParent(e.target.value)}
              placeholder="192.168.1.0/24"
            />
          </div>
          <div className="field" style={{ width: 130 }}>
            <label htmlFor="child">子网前缀</label>
            <input
              id="child"
              className="input mono"
              value={child}
              onChange={(e) => setChild(e.target.value)}
              placeholder="26"
            />
          </div>
          <button className="btn" onClick={() => void runSubdivide()} type="button">
            划分
          </button>
        </div>
        <div style={{ marginTop: 14 }}>
          {tree ? <pre className="pre">{tree}</pre> : <div className="empty">填写父网与目标前缀后点击「划分」</div>}
        </div>
      </section>
    </div>
  );
}

function Cell({ k, v, em, note }: { k: string; v: string; em?: boolean; note?: boolean }) {
  return (
    <div className="cell">
      <span className="cell-k">{k}</span>
      <span className={`cell-v${em ? " em" : ""}${note ? " cell-note" : ""}`}>{v}</span>
    </div>
  );
}
