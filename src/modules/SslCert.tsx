import { useState } from "react";
import { sslCheck } from "../lib/api";
import type { CertInfo, CertStatus, SslCheckReport } from "../lib/types";

const INPUT_KEY = "qqhu.ssl.input";

const STATUS_LABEL: Record<CertStatus, string> = {
  valid: "有效",
  expiringSoon: "即将过期",
  expired: "已过期",
  notYetValid: "尚未生效",
};

const STATUS_TONE: Record<CertStatus, string> = {
  valid: "ok",
  expiringSoon: "warn",
  expired: "bad",
  notYetValid: "warn",
};

const PRESETS = ["example.com", "www.baidu.com", "www.qq.com"];

function fmtTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString("zh-CN", { hour12: false });
}

function shortName(subject: string): string {
  // 证书主体通常很长，优先取 CN，取不到再退回完整串
  const cn = /CN=([^,]+)/.exec(subject);
  return cn ? cn[1] : subject;
}

export default function SslCert() {
  const [input, setInput] = useState(() => localStorage.getItem(INPUT_KEY) ?? "");
  const [timeoutMs, setTimeoutMs] = useState(8000);
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState<SslCheckReport | null>(null);
  const [error, setError] = useState("");
  const [expanded, setExpanded] = useState<number | null>(0);

  async function run(target?: string) {
    const host = (target ?? input).trim();
    if (!host) {
      setError("请填写域名或 IP。");
      return;
    }
    if (target) setInput(target);
    localStorage.setItem(INPUT_KEY, host);

    setBusy(true);
    setError("");
    setReport(null);
    setExpanded(0);
    try {
      const r = await sslCheck(host, timeoutMs);
      setReport(r);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const leaf = report?.chain[0];
  const verdict = report
    ? !report.trusted
      ? { tone: "error" as const, text: "证书链不被本机信任" }
      : leaf && leaf.status === "expired"
        ? { tone: "error" as const, text: "服务器证书已过期" }
        : !report.hostnameMatched
          ? { tone: "warn" as const, text: "证书与主机名不匹配" }
          : leaf && leaf.status === "expiringSoon"
            ? { tone: "warn" as const, text: `证书即将过期，剩余 ${leaf.daysRemaining} 天` }
            : { tone: "ok" as const, text: `证书有效，剩余 ${leaf?.daysRemaining ?? 0} 天` }
    : null;

  return (
    <div className="stack">
      <section className="card">
        <div className="card-head">
          <span className="card-title">检查站点证书</span>
          <span className="card-hint">使用本机系统根证书校验信任链</span>
        </div>

        <div className="form-row">
          <div className="field" style={{ flex: "1 1 260px" }}>
            <label htmlFor="target">域名或 IP</label>
            <input
              id="target"
              className="input mono"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && void run()}
              placeholder="example.com 或 https://example.com:8443"
            />
          </div>
          <div className="field" style={{ width: 120 }}>
            <label htmlFor="ssl-timeout">超时 (ms)</label>
            <input
              id="ssl-timeout"
              className="input mono"
              value={timeoutMs}
              onChange={(e) => setTimeoutMs(Number(e.target.value) || 8000)}
            />
          </div>
          <button className="btn primary" onClick={() => void run()} disabled={busy} type="button">
            {busy ? "检查中…" : "检查"}
          </button>
        </div>

        <div className="form-row" style={{ marginTop: 12, gap: 8 }}>
          {PRESETS.map((p) => (
            <button
              key={p}
              className="btn"
              style={{ height: 26, padding: "0 10px", fontSize: 11, fontFamily: "var(--mono)" }}
              onClick={() => void run(p)}
              disabled={busy}
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

      {report && leaf && (
        <>
          <div className={`alert ${verdict!.tone}`}>
            <strong>{verdict!.text}</strong>
            <span style={{ marginLeft: 8, opacity: 0.8 }}>
              {report.host}:{report.port} · {report.remoteIp} · {report.tlsVersion} ·{" "}
              {report.durationMs} ms
            </span>
          </div>

          {report.warnings.length > 0 && (
            <div className="alert warn">
              {report.warnings.map((w) => (
                <div key={w}>· {w}</div>
              ))}
            </div>
          )}

          <section className="card">
            <div className="card-head">
              <span className="card-title">服务器证书</span>
              <span className={`tag ${STATUS_TONE[leaf.status]}`}>{STATUS_LABEL[leaf.status]}</span>
            </div>

            <div className="result-grid">
              <Cell k="主体 (Subject)" v={shortName(leaf.subject)} em />
              <Cell k="签发者 (Issuer)" v={shortName(leaf.issuer)} />
              <Cell k="生效时间" v={fmtTime(leaf.notBefore)} />
              <Cell k="到期时间" v={fmtTime(leaf.notAfter)} />
              <Cell k="剩余天数" v={`${leaf.daysRemaining} 天`} em={leaf.daysRemaining < 30} />
              <Cell
                k="主机名匹配"
                v={report.hostnameMatched ? "匹配" : "不匹配"}
                em={!report.hostnameMatched}
              />
              <Cell k="信任链" v={report.trusted ? "已信任" : "未通过"} em={!report.trusted} />
              <Cell k="TLS 版本" v={report.tlsVersion} />
              <Cell k="加密套件" v={report.cipherSuite} note />
              <Cell k="签名算法" v={leaf.signatureAlgorithm} />
              <Cell
                k="公钥"
                v={`${leaf.keyAlgorithm}${leaf.keyBits ? ` ${leaf.keyBits} 位` : ""}`}
              />
              <Cell k="序列号" v={leaf.serial} note />
            </div>

            <div style={{ marginTop: 12 }}>
              <div className="card-hint" style={{ marginBottom: 6 }}>
                覆盖域名 (SAN) · 共 {leaf.sans.length} 条
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {leaf.sans.length === 0 ? (
                  <span className="muted-cell">无 SAN 扩展，仅依赖 CN</span>
                ) : (
                  leaf.sans.map((s) => (
                    <span key={s} className="tag">
                      {s}
                    </span>
                  ))
                )}
              </div>
            </div>

            <div style={{ marginTop: 12 }}>
              <div className="card-hint" style={{ marginBottom: 6 }}>
                SHA-256 指纹
              </div>
              <div className="pre mono">{leaf.sha256Fingerprint}</div>
            </div>
          </section>

          <section className="card">
            <div className="card-head">
              <span className="card-title">证书链</span>
              <span className="card-hint">
                共 {report.chain.length} 张 · 点击查看详情
              </span>
            </div>

            <table className="table">
              <thead>
                <tr>
                  <th style={{ width: 60 }}>层级</th>
                  <th>主体</th>
                  <th>签发者</th>
                  <th style={{ width: 130 }}>到期时间</th>
                  <th style={{ width: 90 }}>状态</th>
                </tr>
              </thead>
              <tbody>
                {report.chain.map((c, i) => (
                  <ChainRow
                    key={`${c.sha256Fingerprint}-${i}`}
                    cert={c}
                    index={i}
                    open={expanded === i}
                    onToggle={() => setExpanded(expanded === i ? null : i)}
                  />
                ))}
              </tbody>
            </table>
          </section>
        </>
      )}
    </div>
  );
}

function ChainRow({
  cert,
  index,
  open,
  onToggle,
}: {
  cert: CertInfo;
  index: number;
  open: boolean;
  onToggle: () => void;
}) {
  const label = index === 0 ? "服务器" : cert.isCa ? `中间 ${index}` : `链 ${index}`;
  return (
    <>
      <tr onClick={onToggle} style={{ cursor: "pointer" }}>
        <td>
          <span className="tag">{label}</span>
        </td>
        <td className="mono" style={{ fontSize: 11 }}>
          {shortName(cert.subject)}
        </td>
        <td className="mono muted-cell" style={{ fontSize: 11 }}>
          {shortName(cert.issuer)}
        </td>
        <td className="mono" style={{ fontSize: 11 }}>
          {new Date(cert.notAfter).toLocaleDateString("zh-CN")}
        </td>
        <td>
          <span className={`tag ${STATUS_TONE[cert.status]}`}>{STATUS_LABEL[cert.status]}</span>
        </td>
      </tr>
      {open && (
        <tr>
          <td colSpan={5} style={{ paddingTop: 0 }}>
            <div className="result-grid" style={{ marginTop: 8 }}>
              <Cell k="完整主体" v={cert.subject} note />
              <Cell k="完整签发者" v={cert.issuer} note />
              <Cell k="生效时间" v={fmtTime(cert.notBefore)} />
              <Cell k="到期时间" v={fmtTime(cert.notAfter)} />
              <Cell k="签名算法" v={cert.signatureAlgorithm} />
              <Cell k="序列号" v={cert.serial} note />
              <Cell k="CA" v={cert.isCa ? "是" : "否"} />
              <Cell k="自签名" v={cert.selfSigned ? "是" : "否"} />
            </div>
            <div className="pre mono" style={{ marginTop: 8 }}>
              {cert.sha256Fingerprint}
            </div>
          </td>
        </tr>
      )}
    </>
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
