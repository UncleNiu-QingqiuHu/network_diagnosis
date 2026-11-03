import { useEffect, useState } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import { aboutInfo, isTauri } from "../lib/api";
import type { AboutInfo } from "../lib/types";

export default function About() {
  const [info, setInfo] = useState<AboutInfo | null>(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    aboutInfo()
      .then(setInfo)
      .catch((e) => setErr(e instanceof Error ? e.message : String(e)));
  }, []);

  async function open(url: string) {
    if (!isTauri) {
      await navigator.clipboard.writeText(url).catch(() => undefined);
      return;
    }
    try {
      await openUrl(url);
    } catch {
      await navigator.clipboard.writeText(url).catch(() => undefined);
    }
  }

  if (err) return <div className="alert error">{err}</div>;
  if (!info) return <div className="empty">正在读取…</div>;

  return (
    <div className="stack">
      <section className="card about-hero">
        <div className="brand-mark" style={{ width: 44, height: 44, background: "linear-gradient(135deg,#0F6E56,#141d29)", border: "1px solid #2dd4a733" }} />
        <div>
          <div className="about-name">{info.name}</div>
          <div className="about-sub">
            {info.nameEn} · v{info.version}
          </div>
        </div>
        <div className="about-meta">
          <span className="badge">{info.platformDisplay}</span>
          <span className="badge">{info.license}</span>
        </div>
      </section>

      <section className="card">
        <div className="card-head">
          <span className="card-title">作者与联系方式</span>
        </div>
        <div className="kv">
          <Row k="作者" v={info.author} />
          <Row k="邮箱" v={info.email} link={`mailto:${info.email}`} onOpen={open} />
          <Row k="QQ" v={info.qq} />
          <Row k="QQ 群" v={info.qqGroup} />
          <Row k="官方网站" v={info.website} link={info.website} onOpen={open} />
          <Row k="社区" v={info.community} link={info.community} onOpen={open} />
          <Row k="代码仓库" v={info.repository} link={info.repository} onOpen={open} />
        </div>
      </section>

      <section className="card">
        <div className="card-head">
          <span className="card-title">运行环境</span>
        </div>
        <div className="kv">
          <Row k="主机名" v={info.hostname} />
          <Row k="系统" v={info.osSummary} />
          <Row k="权限" v={info.elevated ? "管理员 / root" : "普通用户"} />
        </div>
      </section>

      <section className="card">
        <div className="card-head">
          <span className="card-title">版权</span>
        </div>
        <p className="about-copy">{info.copyright}</p>
        <p className="about-copy dim">
          本项目基于 {info.license} 发布，可自由使用、修改与再分发，须保留版权与许可声明。完整条款见「许可」页。
        </p>
      </section>
    </div>
  );
}

function Row({
  k,
  v,
  link,
  onOpen,
}: {
  k: string;
  v: string;
  link?: string;
  onOpen?: (url: string) => void;
}) {
  return (
    <div className="kv-row">
      <span className="kv-k">{k}</span>
      {link ? (
        <button className="kv-link" onClick={() => void onOpen?.(link)} type="button" title="点击打开">
          {v}
        </button>
      ) : (
        <span className="kv-v">{v}</span>
      )}
    </div>
  );
}
