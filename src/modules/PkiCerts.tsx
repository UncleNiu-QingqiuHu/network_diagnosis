import { Fragment, useCallback, useEffect, useState } from "react";
import { revealItemInDir } from "@tauri-apps/plugin-opener";
import {
  pkiCertText,
  pkiCreateCa,
  pkiDeleteCa,
  pkiDeleteCert,
  pkiDirOf,
  pkiExportPfx,
  pkiIssue,
  pkiOverview,
} from "../lib/api";
import type {
  CertText,
  KeyAlgorithm,
  CertUsage,
  PkiOverview,
} from "../lib/types";

const ALG_LABEL: Record<KeyAlgorithm, string> = {
  ecdsaP256: "ECDSA P-256",
  ed25519: "Ed25519",
};

const USAGE_LABEL: Record<CertUsage, string> = {
  server: "服务器",
  client: "客户端",
  both: "服务器 + 客户端",
};

function fmtDate(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleDateString("zh-CN");
}

function daysTone(days: number): string {
  if (days < 0) return "bad";
  if (days < 30) return "warn";
  return "ok";
}

export default function PkiCerts() {
  const [overview, setOverview] = useState<PkiOverview | null>(null);
  const [activeCa, setActiveCa] = useState<string>("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  // ---- 新建 CA ----
  const [showCaForm, setShowCaForm] = useState(false);
  const [caCn, setCaCn] = useState("");
  const [caOrg, setCaOrg] = useState("");
  const [caOu, setCaOu] = useState("");
  const [caCountry, setCaCountry] = useState("CN");
  const [caDays, setCaDays] = useState(3650);
  const [caAlg, setCaAlg] = useState<KeyAlgorithm>("ecdsaP256");

  // ---- 签发证书 ----
  const [cn, setCn] = useState("");
  const [sansText, setSansText] = useState("");
  const [days, setDays] = useState(397);
  const [alg, setAlg] = useState<KeyAlgorithm>("ecdsaP256");
  const [usage, setUsage] = useState<CertUsage>("server");

  // ---- 详情与导出 ----
  const [detail, setDetail] = useState<CertText | null>(null);
  const [pfxFor, setPfxFor] = useState("");
  const [pfxPass, setPfxPass] = useState("");
  const [pfxPath, setPfxPath] = useState("");

  const refresh = useCallback(async () => {
    try {
      const data = await pkiOverview();
      setOverview(data);
      setActiveCa((cur) => (data.cas.some((c) => c.id === cur) ? cur : (data.cas[0]?.id ?? "")));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);


  async function run<T>(fn: () => Promise<T>, okMsg?: string): Promise<T | null> {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const r = await fn();
      if (okMsg) setNotice(okMsg);
      return r;
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return null;
    } finally {
      setBusy(false);
    }
  }

  async function createCa() {
    if (!caCn.trim()) {
      setError("请填写 CA 名称（CN）。");
      return;
    }
    const created = await run(
      () =>
        pkiCreateCa({
          commonName: caCn.trim(),
          organization: caOrg.trim() || null,
          organizationalUnit: caOu.trim() || null,
          country: caCountry.trim() || null,
          validityDays: caDays,
          keyAlgorithm: caAlg,
        }),
      "CA 创建成功，私钥已按明文 PEM 保存在证书库目录。",
    );
    if (created) {
      setShowCaForm(false);
      setCaCn("");
      setActiveCa(created.id);
      await refresh();
    }
  }

  async function issueCert() {
    if (!activeCa) {
      setError("请先创建或选择一个 CA。");
      return;
    }
    if (!cn.trim()) {
      setError("请填写证书名称（CN）。");
      return;
    }
    const sans = sansText
      .split(/[\s,，;；]+/)
      .map((s) => s.trim())
      .filter(Boolean);

    const created = await run(
      () =>
        pkiIssue({
          caId: activeCa,
          commonName: cn.trim(),
          sans,
          validityDays: days,
          keyAlgorithm: alg,
          usage,
        }),
      "证书签发完成。",
    );
    if (created) {
      setCn("");
      setSansText("");
      await refresh();
    }
  }

  async function exportPfx(id: string) {
    if (pfxPass.length < 4) {
      setError("PFX 口令至少 4 位：Windows 导入时对空口令兼容性很差。");
      return;
    }
    const path = await run(() => pkiExportPfx(id, pfxPass), "PFX 已导出。");
    if (path) {
      setPfxPath(path);
      setPfxFor("");
      setPfxPass("");
    }
  }

  async function openDir(id: string, kind: "ca" | "cert") {
    try {
      const dir = await pkiDirOf(id, kind);
      await revealItemInDir(dir);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function removeCa(id: string) {
    if (!window.confirm("确定删除该 CA？其证书文件会一并保留在磁盘上。")) return;
    await run(() => pkiDeleteCa(id), "CA 已删除。");
    await refresh();
  }

  async function removeCert(id: string) {
    if (!window.confirm("确定删除该证书？私钥文件会被一并删除，无法恢复。")) return;
    await run(() => pkiDeleteCert(id), "证书已删除。");
    if (detail?.dir.includes(id)) setDetail(null);
    await refresh();
  }

  async function showDetail(id: string) {
    setDetail(null);
    const text = await run(() => pkiCertText(id));
    if (text) setPfxPath("");
    setDetail(text);
  }

  const cas = overview?.cas ?? [];
  const certs = (overview?.certs ?? []).filter((c) => !activeCa || c.caId === activeCa);
  const activeCaMeta = cas.find((c) => c.id === activeCa);

  return (
    <div className="stack">
      {overview && (
        <div className="alert warn">
          私钥以<strong>明文 PEM</strong> 保存在 <span className="mono">{overview.rootDir}</span>
          ，请限制该目录的访问权限；证书库随安装目录迁移，重装前请先备份。
        </div>
      )}

      {error && <div className="alert error">{error}</div>}
      {notice && <div className="alert ok">{notice}</div>}

      <section className="card">
        <div className="card-head">
          <span className="card-title">根证书（CA）</span>
          <div style={{ display: "flex", gap: 8 }}>
            <span className="card-hint">共 {cas.length} 个</span>
            <button className="btn" type="button" onClick={() => setShowCaForm((v) => !v)}>
              {showCaForm ? "收起" : "新建 CA"}
            </button>
          </div>
        </div>

        {showCaForm && (
          <>
            <div className="form-row">
              <div className="field" style={{ flex: "1 1 240px" }}>
                <label htmlFor="ca-cn">CA 名称 (CN)</label>
                <input
                  id="ca-cn"
                  className="input"
                  value={caCn}
                  onChange={(e) => setCaCn(e.target.value)}
                  placeholder="青丘湖内部根 CA"
                />
              </div>
              <div className="field" style={{ flex: "1 1 200px" }}>
                <label htmlFor="ca-org">组织 (O)</label>
                <input
                  id="ca-org"
                  className="input"
                  value={caOrg}
                  onChange={(e) => setCaOrg(e.target.value)}
                  placeholder="惠州华阳通机电有限公司"
                />
              </div>
              <div className="field" style={{ flex: "1 1 160px" }}>
                <label htmlFor="ca-ou">部门 (OU)</label>
                <input
                  id="ca-ou"
                  className="input"
                  value={caOu}
                  onChange={(e) => setCaOu(e.target.value)}
                  placeholder="网络信息安全组"
                />
              </div>
            </div>

            <div className="form-row" style={{ marginTop: 12 }}>
              <div className="field" style={{ width: 110 }}>
                <label htmlFor="ca-country">国家</label>
                <input
                  id="ca-country"
                  className="input mono"
                  value={caCountry}
                  onChange={(e) => setCaCountry(e.target.value)}
                  placeholder="CN"
                  maxLength={2}
                />
              </div>
              <div className="field" style={{ width: 140 }}>
                <label htmlFor="ca-days">有效期（天）</label>
                <input
                  id="ca-days"
                  className="input mono"
                  value={caDays}
                  onChange={(e) => setCaDays(Number(e.target.value) || 3650)}
                />
              </div>
              <div className="field" style={{ width: 170 }}>
                <label htmlFor="ca-alg">密钥算法</label>
                <select
                  id="ca-alg"
                  className="select"
                  value={caAlg}
                  onChange={(e) => setCaAlg(e.target.value as KeyAlgorithm)}
                >
                  {(Object.keys(ALG_LABEL) as KeyAlgorithm[]).map((k) => (
                    <option key={k} value={k}>
                      {ALG_LABEL[k]}
                    </option>
                  ))}
                </select>
              </div>
              <button className="btn primary" type="button" disabled={busy} onClick={() => void createCa()}>
                创建 CA
              </button>
            </div>
          </>
        )}

        {cas.length === 0 ? (
          <div className="empty" style={{ marginTop: 12 }}>
            还没有 CA。先创建一个根证书，再用它为内网服务签发证书。
          </div>
        ) : (
          <table className="table" style={{ marginTop: 12 }}>
            <thead>
              <tr>
                <th style={{ width: 36 }} />
                <th>名称</th>
                <th>主体 (Subject)</th>
                <th style={{ width: 110 }}>到期</th>
                <th style={{ width: 80 }}>已签发</th>
                <th style={{ width: 150 }}>操作</th>
              </tr>
            </thead>
            <tbody>
              {cas.map((ca) => (
                <tr
                  key={ca.id}
                  onClick={() => {
                    setActiveCa(ca.id);
                    setDetail(null);
                  }}
                  style={{ cursor: "pointer" }}
                >
                  <td>
                    <input type="radio" checked={activeCa === ca.id} readOnly />
                  </td>
                  <td>{ca.commonName}</td>
                  <td className="mono muted-cell" style={{ fontSize: 11 }}>
                    {ca.subject}
                  </td>
                  <td>
                    <span className={`tag ${daysTone(ca.daysRemaining)}`}>
                      {fmtDate(ca.notAfter)}
                    </span>
                  </td>
                  <td className="mono">{ca.issuedCount}</td>
                  <td onClick={(e) => e.stopPropagation()}>
                    <div style={{ display: "flex", gap: 6 }}>
                      <button className="btn" type="button" onClick={() => void openDir(ca.id, "ca")}>
                        目录
                      </button>
                      <button className="btn" type="button" onClick={() => void removeCa(ca.id)}>
                        删除
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="card">
        <div className="card-head">
          <span className="card-title">签发证书</span>
          <span className="card-hint">
            {activeCaMeta ? `签发者：${activeCaMeta.commonName}` : "请先选择 CA"}
          </span>
        </div>

        <div className="form-row">
          <div className="field" style={{ flex: "1 1 200px" }}>
            <label htmlFor="cn">名称 (CN)</label>
            <input
              id="cn"
              className="input mono"
              value={cn}
              onChange={(e) => setCn(e.target.value)}
              placeholder="nas.corp.local"
            />
          </div>
          <div className="field" style={{ flex: "2 1 320px" }}>
            <label htmlFor="sans">SAN（域名或 IP，逗号/换行分隔，留空则用 CN）</label>
            <input
              id="sans"
              className="input mono"
              value={sansText}
              onChange={(e) => setSansText(e.target.value)}
              placeholder="nas.corp.local, 192.168.60.10, *.corp.local"
            />
          </div>
        </div>

        <div className="form-row" style={{ marginTop: 12 }}>
          <div className="field" style={{ width: 140 }}>
            <label htmlFor="days">有效期（天）</label>
            <input
              id="days"
              className="input mono"
              value={days}
              onChange={(e) => setDays(Number(e.target.value) || 397)}
            />
          </div>
          <div className="field" style={{ width: 170 }}>
            <label htmlFor="alg">密钥算法</label>
            <select
              id="alg"
              className="select"
              value={alg}
              onChange={(e) => setAlg(e.target.value as KeyAlgorithm)}
            >
              {(Object.keys(ALG_LABEL) as KeyAlgorithm[]).map((k) => (
                <option key={k} value={k}>
                  {ALG_LABEL[k]}
                </option>
              ))}
            </select>
          </div>
          <div className="field" style={{ width: 190 }}>
            <label htmlFor="usage">用途</label>
            <select
              id="usage"
              className="select"
              value={usage}
              onChange={(e) => setUsage(e.target.value as CertUsage)}
            >
              {(Object.keys(USAGE_LABEL) as CertUsage[]).map((k) => (
                <option key={k} value={k}>
                  {USAGE_LABEL[k]}
                </option>
              ))}
            </select>
          </div>
          <button
            className="btn primary"
            type="button"
            disabled={busy || !activeCa}
            onClick={() => void issueCert()}
          >
            签发
          </button>
        </div>

        <div className="card-hint" style={{ marginTop: 10 }}>
          证书有效期会被 CA 的剩余有效期截断；更长期限请重建 CA。
        </div>
      </section>

      <section className="card">
        <div className="card-head">
          <span className="card-title">已签发证书</span>
          <span className="card-hint">共 {certs.length} 张</span>
        </div>

        {certs.length === 0 ? (
          <div className="empty" style={{ marginTop: 8 }}>
            当前 CA 下还没有证书。
          </div>
        ) : (
          <table className="table" style={{ marginTop: 8 }}>
            <thead>
              <tr>
                <th>名称</th>
                <th>SAN</th>
                <th style={{ width: 90 }}>用途</th>
                <th style={{ width: 110 }}>到期</th>
                <th style={{ width: 230 }}>操作</th>
              </tr>
            </thead>
            <tbody>
              {certs.map((c) => (
                <Fragment key={c.id}>
                  <tr>
                    <td className="mono">{c.commonName}</td>
                    <td className="mono muted-cell" style={{ fontSize: 11 }}>
                      {c.sans.join(", ")}
                    </td>
                    <td className="muted-cell">{c.usage}</td>
                    <td>
                      <span className={`tag ${daysTone(c.daysRemaining)}`}>
                        {c.daysRemaining} 天
                      </span>
                    </td>
                    <td>
                      <div style={{ display: "flex", gap: 6 }}>
                        <button className="btn" type="button" onClick={() => void showDetail(c.id)}>
                          证书
                        </button>
                        <button
                          className="btn"
                          type="button"
                          onClick={() => {
                            setPfxFor(pfxFor === c.id ? "" : c.id);
                            setPfxPath("");
                          }}
                        >
                          导出 PFX
                        </button>
                        <button className="btn" type="button" onClick={() => void openDir(c.id, "cert")}>
                          目录
                        </button>
                        <button className="btn" type="button" onClick={() => void removeCert(c.id)}>
                          删除
                        </button>
                      </div>
                    </td>
                  </tr>

                  {pfxFor === c.id && (
                    <tr>
                      <td colSpan={5}>
                        <div className="form-row" style={{ marginTop: 4 }}>
                          <div className="field" style={{ flex: "1 1 260px" }}>
                            <label htmlFor={`pfx-pass-${c.id}`}>PFX 口令（Windows 导入时需要）</label>
                            <input
                              id={`pfx-pass-${c.id}`}
                              className="input mono"
                              type="password"
                              value={pfxPass}
                              onChange={(e) => setPfxPass(e.target.value)}
                              onKeyDown={(e) => e.key === "Enter" && void exportPfx(c.id)}
                              placeholder="至少 4 位"
                            />
                          </div>
                          <button
                            className="btn primary"
                            type="button"
                            disabled={busy}
                            onClick={() => void exportPfx(c.id)}
                          >
                            生成 .pfx
                          </button>
                        </div>
                        <div className="card-hint" style={{ marginTop: 8 }}>
                          使用 PKCS#12 传统 RC2-40 加密：Windows / IIS 可直接导入；
                          OpenSSL 3 需要启用 legacy provider 才能读取。
                        </div>
                        {pfxPath && (
                          <div className="alert ok" style={{ marginTop: 10 }}>
                            已导出：<span className="mono">{pfxPath}</span>
                          </div>
                        )}
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {detail && (
        <section className="card">
          <div className="card-head">
            <span className="card-title">证书内容</span>
            <div style={{ display: "flex", gap: 8 }}>
              <button
                className="btn"
                type="button"
                onClick={() => void navigator.clipboard.writeText(detail.chainPem)}
              >
                复制证书链
              </button>
              <button className="btn" type="button" onClick={() => setDetail(null)}>
                关闭
              </button>
            </div>
          </div>
          <div className="card-hint" style={{ marginBottom: 6 }}>
            fullchain（服务器证书 + CA），可直接用于 Nginx `ssl_certificate`
          </div>
          <div className="pre mono" style={{ maxHeight: 260, overflow: "auto" }}>
            {detail.chainPem}
          </div>
          <div className="card-hint" style={{ marginTop: 8 }}>
            私钥文件：<span className="mono">{detail.dir}\\key.pem</span>（明文，签名前请确认目录权限）
          </div>
        </section>
      )}
    </div>
  );
}
