import { useCallback, useEffect, useRef, useState } from "react";
import { revealItemInDir } from "@tauri-apps/plugin-opener";
import {
  acmeCertText,
  acmeDeleteCert,
  acmeDirOf,
  acmeExportPfx,
  acmeIssue,
  acmeOverview,
  onAcmeProgress,
} from "../lib/api";
import type {
  AcmeCertMeta,
  AcmeCertText,
  AcmeOverview,
  AcmeProgress,
  DnsProviderKind,
} from "../lib/types";

const PROVIDER_LABEL: Record<DnsProviderKind, string> = {
  aliyun: "阿里云 DNS",
  tencent: "腾讯云 DNSPod",
};

/** 进度阶段的中文名，用于日志前缀。 */
const STAGE_LABEL: Record<string, string> = {
  account: "账户",
  order: "下单",
  dns: "DNS",
  verify: "传播",
  challenge: "校验",
  finalize: "签发",
  save: "保存",
  cleanup: "清理",
  done: "完成",
};

function fmtDate(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleDateString("zh-CN");
}

function daysTone(days: number): string {
  if (days < 0) return "bad";
  if (days < 15) return "warn";
  return "ok";
}

export default function AcmeCert() {
  const [overview, setOverview] = useState<AcmeOverview | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  // ---- 申请表单 ----
  const [domainsText, setDomainsText] = useState("");
  const [provider, setProvider] = useState<DnsProviderKind>("aliyun");
  const [ak, setAk] = useState("");
  const [sk, setSk] = useState("");
  const [staging, setStaging] = useState(false);
  const [waitSecs, setWaitSecs] = useState(20);

  const [running, setRunning] = useState(false);
  const [logs, setLogs] = useState<AcmeProgress[]>([]);

  // ---- 详情与导出 ----
  const [detail, setDetail] = useState<AcmeCertText | null>(null);
  const [detailId, setDetailId] = useState("");
  const [pfxFor, setPfxFor] = useState("");
  const [pfxPass, setPfxPass] = useState("");
  const [pfxPath, setPfxPath] = useState("");

  const unlistenRef = useRef<(() => void) | null>(null);

  const refresh = useCallback(async () => {
    try {
      setOverview(await acmeOverview());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // 进度事件：签发期间持续推送，卸载时必须解绑
  useEffect(() => {
    let cancelled = false;
    void onAcmeProgress((p) => {
      setLogs((cur) => [...cur, p].slice(-40));
    }).then((fn) => {
      if (cancelled) fn();
      else unlistenRef.current = fn;
    });
    return () => {
      cancelled = true;
      unlistenRef.current?.();
      unlistenRef.current = null;
    };
  }, []);

  async function run<T>(fn: () => Promise<T>, okMsg?: string): Promise<T | null> {
    setError("");
    setNotice("");
    try {
      const r = await fn();
      if (okMsg) setNotice(okMsg);
      return r;
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return null;
    }
  }

  function parseDomains(input: string): string[] {
    return input
      .split(/[\s,，;；]+/)
      .map((s) => s.trim())
      .filter(Boolean);
  }

  async function issue() {
    const domains = parseDomains(domainsText);
    if (domains.length === 0) {
      setError("请填写至少一个域名。");
      return;
    }
    if (!ak.trim() || !sk.trim()) {
      setError("请填写 AccessKey ID 与 Secret。");
      return;
    }

    setRunning(true);
    setLogs([]);
    setError("");
    setNotice("");
    setDetail(null);
    setDetailId("");

    try {
      const meta = await acmeIssue({
        domains,
        provider,
        credentials: { accessKeyId: ak.trim(), accessKeySecret: sk.trim() },
        staging,
        dnsWaitSecs: waitSecs,
      });
      setNotice(
        `证书已签发：${meta.primaryDomain}，有效期至 ${fmtDate(meta.notAfter)}。` +
          (meta.staging ? "（测试环境证书不被浏览器信任，仅用于验证流程）" : ""),
      );
      // 申请成功后不再保留密钥输入，减少旁观者看到的机会
      setSk("");
      await refresh();
      await openDetail(meta.id);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning(false);
    }
  }

  async function openDetail(id: string) {
    const text = await run(() => acmeCertText(id));
    if (text) {
      setDetail(text);
      setDetailId(id);
      setPfxFor("");
      setPfxPath("");
    }
  }

  async function copy(text: string, label: string) {
    await navigator.clipboard.writeText(text).catch(() => undefined);
    setNotice(`${label}已复制到剪贴板。`);
  }

  async function exportPfx(id: string) {
    if (pfxPass.length < 4) {
      setError("PFX 口令至少 4 位：Windows 导入时对空口令兼容性很差。");
      return;
    }
    const path = await run(() => acmeExportPfx(id, pfxPass), "PFX 已导出。");
    if (path) setPfxPath(path);
  }

  async function openDir(id: string) {
    const dir = await run(() => acmeDirOf(id));
    if (dir) await revealItemInDir(dir).catch(() => undefined);
  }

  async function remove(id: string) {
    if (!window.confirm("删除后私钥与证书文件将一并移除，且无法恢复。确认删除？")) return;
    const ok = await run(() => acmeDeleteCert(id), "证书已删除。");
    if (ok !== null) {
      if (detailId === id) {
        setDetail(null);
        setDetailId("");
      }
      await refresh();
    }
  }

  const certs: AcmeCertMeta[] = overview?.certs ?? [];
  const latest = logs.length > 0 ? logs[logs.length - 1] : null;

  return (
    <div className="stack">
      <div className="alert warn">
        证书与<strong>明文私钥</strong>保存在{" "}
        <span className="mono">{overview?.rootDir ?? "（证书库目录）"}</span>
        ，请限制该目录访问权限。Let&apos;s Encrypt 有频率限制（同一域名每周 50 张、完全重复的证书每周 5
        张），调试流程请先勾选测试环境。
      </div>

      {error && <div className="alert error">{error}</div>}
      {notice && <div className="alert ok">{notice}</div>}

      <section className="card">
        <div className="card-head">
          <span className="card-title">申请 ACME 证书</span>
          <span className="card-hint">DNS-01 验证，无需公网 80/443 端口</span>
        </div>

        <div className="form-row">
          <div className="field" style={{ flex: "2 1 360px" }}>
            <label htmlFor="acme-domains">域名（主域名在前，逗号或换行分隔，支持泛域名）</label>
            <input
              id="acme-domains"
              className="input mono"
              value={domainsText}
              onChange={(e) => setDomainsText(e.target.value)}
              placeholder="example.com, *.example.com"
              disabled={running}
            />
          </div>
          <div className="field" style={{ width: 180 }}>
            <label htmlFor="acme-provider">DNS 服务商</label>
            <select
              id="acme-provider"
              className="select"
              value={provider}
              onChange={(e) => setProvider(e.target.value as DnsProviderKind)}
              disabled={running}
            >
              {(Object.keys(PROVIDER_LABEL) as DnsProviderKind[]).map((k) => (
                <option key={k} value={k}>
                  {PROVIDER_LABEL[k]}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="form-row" style={{ marginTop: 12 }}>
          <div className="field" style={{ flex: "1 1 260px" }}>
            <label htmlFor="acme-ak">AccessKey ID</label>
            <input
              id="acme-ak"
              className="input mono"
              value={ak}
              onChange={(e) => setAk(e.target.value)}
              placeholder={provider === "aliyun" ? "LTAI..." : "AKID..."}
              autoComplete="off"
              disabled={running}
            />
          </div>
          <div className="field" style={{ flex: "1 1 260px" }}>
            <label htmlFor="acme-sk">AccessKey Secret</label>
            <input
              id="acme-sk"
              className="input mono"
              type="password"
              value={sk}
              onChange={(e) => setSk(e.target.value)}
              placeholder="仅用于本次写入 DNS 记录，不落盘"
              autoComplete="off"
              disabled={running}
            />
          </div>
        </div>

        <div className="form-row" style={{ marginTop: 12, alignItems: "flex-end" }}>
          <div className="field" style={{ width: 170 }}>
            <label htmlFor="acme-wait">DNS 等待（秒）</label>
            <input
              id="acme-wait"
              className="input mono"
              value={waitSecs}
              onChange={(e) => setWaitSecs(Number(e.target.value) || 20)}
              disabled={running}
            />
          </div>
          <label className="check" style={{ marginBottom: 8 }}>
            <input
              type="checkbox"
              checked={staging}
              onChange={(e) => setStaging(e.target.checked)}
              disabled={running}
            />
            使用测试环境（不占用正式额度，证书不受信任）
          </label>
          <div style={{ flex: 1 }} />
          <button className="btn primary" type="button" onClick={() => void issue()} disabled={running}>
            {running ? "签发中…" : "申请证书"}
          </button>
        </div>

        <p className="card-hint" style={{ marginTop: 10 }}>
          AccessKey 仅用于本次写入 <span className="mono">_acme-challenge</span> TXT 记录，
          不会写入磁盘；账户密钥保存在证书库目录，供后续续期复用。
        </p>

        {(running || logs.length > 0) && (
          <div style={{ marginTop: 12 }}>
            <div className="progress-line">
              {running && <span className="spin" />}
              <span>{latest ? latest.message : "准备中…"}</span>
            </div>
            <div className="pre" style={{ maxHeight: 160, overflow: "auto", marginTop: 8 }}>
              {logs.map((l, i) => (
                <div key={`${i}-${l.stage}`} className="mono muted-cell" style={{ fontSize: 11 }}>
                  [{STAGE_LABEL[l.stage] ?? l.stage}] {l.message}
                </div>
              ))}
            </div>
          </div>
        )}
      </section>

      <section className="card">
        <div className="card-head">
          <span className="card-title">已签发证书</span>
          <span className="card-hint">共 {certs.length} 张 · 到期前 30 天建议续期</span>
        </div>

        {certs.length === 0 ? (
          <div className="empty">还没有证书。填好域名与 AccessKey 后点「申请证书」。</div>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>主域名</th>
                <th>覆盖域名</th>
                <th>到期</th>
                <th>服务商</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {certs.map((c) => (
                <tr
                  key={c.id}
                  onClick={() => void openDetail(c.id)}
                  style={{ cursor: "pointer" }}
                >
                  <td className="mono">
                    {c.primaryDomain}
                    {c.staging && (
                      <span className="tag warn" style={{ marginLeft: 6 }}>
                        测试
                      </span>
                    )}
                  </td>
                  <td className="mono muted-cell" style={{ fontSize: 11 }}>
                    {c.domains.join("、")}
                  </td>
                  <td>
                    <span className={`tag ${daysTone(c.daysRemaining)}`}>
                      {fmtDate(c.notAfter)}（{c.daysRemaining} 天）
                    </span>
                  </td>
                  <td>{c.provider}</td>
                  <td onClick={(e) => e.stopPropagation()}>
                    <div style={{ display: "flex", gap: 6 }}>
                      <button
                        className="btn"
                        type="button"
                        onClick={() => {
                          setPfxFor(pfxFor === c.id ? "" : c.id);
                          setPfxPath("");
                        }}
                      >
                        PFX
                      </button>
                      <button className="btn" type="button" onClick={() => void openDir(c.id)}>
                        目录
                      </button>
                      <button className="btn" type="button" onClick={() => void remove(c.id)}>
                        删除
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {pfxFor && (
          <div className="form-row" style={{ marginTop: 12, alignItems: "flex-end" }}>
            <div className="field" style={{ flex: "1 1 240px" }}>
              <label htmlFor="acme-pfx-pass">PFX 口令（至少 4 位）</label>
              <input
                id="acme-pfx-pass"
                className="input"
                type="password"
                value={pfxPass}
                onChange={(e) => setPfxPass(e.target.value)}
                autoComplete="new-password"
              />
            </div>
            <button className="btn" type="button" onClick={() => void exportPfx(pfxFor)}>
              导出 PKCS#12
            </button>
            <p className="card-hint" style={{ marginBottom: 8 }}>
              用于 Windows / IIS 导入；OpenSSL 3 读取需启用 legacy provider。
            </p>
          </div>
        )}
        {pfxPath && (
          <p className="card-hint mono" style={{ marginTop: 6 }}>
            已导出：{pfxPath}
          </p>
        )}
      </section>

      {detail && (
        <section className="card">
          <div className="card-head">
            <span className="card-title">证书内容</span>
            <div style={{ display: "flex", gap: 6 }}>
              <button className="btn" type="button" onClick={() => void copy(detail.chainPem, "完整链")}>
                复制完整链
              </button>
              <button className="btn" type="button" onClick={() => void copy(detail.certPem, "证书")}>
                复制证书
              </button>
              <button className="btn" type="button" onClick={() => void copy(detail.keyPem, "私钥")}>
                复制私钥
              </button>
              <button className="btn" type="button" onClick={() => void openDir(detailId)}>
                打开目录
              </button>
            </div>
          </div>

          <p className="card-hint" style={{ marginBottom: 8 }}>
            完整链 = 站点证书 + 中间证书，Nginx 的 <span className="mono">ssl_certificate</span>{" "}
            直接用它；私钥为 PKCS#8 格式。
          </p>
          <div className="pre" style={{ maxHeight: 260, overflow: "auto" }}>
            <pre className="mono" style={{ margin: 0, fontSize: 11 }}>
              {detail.chainPem}
            </pre>
          </div>
          <p className="card-hint mono" style={{ marginTop: 8 }}>
            {detail.dir}
          </p>
        </section>
      )}
    </div>
  );
}
