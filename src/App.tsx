import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import AiPanel from "./components/AiPanel";
import Sidebar from "./components/Sidebar";
import { appInfo, isTauri } from "./lib/api";
import type { AppInfo } from "./lib/types";
import Placeholder from "./modules/Placeholder";
import SubnetCalc from "./modules/SubnetCalc";
import NetworkDiag from "./modules/NetworkDiag";
import IpScan from "./modules/IpScan";
import MacScan from "./modules/MacScan";
import About from "./modules/About";
import License from "./modules/License";

interface ModuleView {
  title: string;
  desc: string;
  render: () => ReactNode;
}

const VIEWS: Record<string, ModuleView> = {
  network: {
    title: "网络诊断",
    desc: "连通性、时延、丢包与端口可达性",
    render: () => <NetworkDiag />,
  },
  subnet: {
    title: "子网计算",
    desc: "IPv4 网段推导、可用主机区间与等长划分",
    render: () => <SubnetCalc />,
  },
  ipScan: {
    title: "IP 扫描",
    desc: "网段并发探活、TCP 兜底判定与结果导出",
    render: () => <IpScan />,
  },
  macScan: {
    title: "MAC 扫描",
    desc: "本机 ARP 邻居表、厂商识别与 IP-MAC 对照",
    render: () => <MacScan />,
  },
  sslCert: {
    title: "SSL 证书",
    desc: "Let's Encrypt 与私有 CA 签发",
    render: () => (
      <Placeholder
        title="SSL 证书"
        milestone="M4"
        items={["DNS-01 签发（阿里云 / 腾讯云 DNS）", "私有 CA 与站点证书", "PFX 导出"]}
      />
    ),
  },
  about: {
    title: "关于",
    desc: "版本、作者与运行环境",
    render: () => <About />,
  },
  license: {
    title: "许可",
    desc: "开源许可全文",
    render: () => <License />,
  },
};

export default function App() {
  const [info, setInfo] = useState<AppInfo | null>(null);
  const [fatal, setFatal] = useState("");
  const [active, setActive] = useState("subnet");
  const [aiOpen, setAiOpen] = useState(true);

  useEffect(() => {
    appInfo()
      .then((i) => {
        setInfo(i);
        if (!i.modules.some((m) => m.key === "subnet")) {
          setActive(i.modules[0]?.key ?? "subnet");
        }
      })
      .catch((e) => setFatal(e instanceof Error ? e.message : String(e)));
  }, []);

  if (fatal) {
    return (
      <div className="loading" style={{ flexDirection: "column", gap: 8 }}>
        <div style={{ color: "var(--danger)" }}>初始化失败：{fatal}</div>
      </div>
    );
  }

  if (!info) {
    return (
      <div className="loading">
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span className="spin" />
          <span>正在读取运行环境…</span>
        </div>
      </div>
    );
  }

  const modules = info.modules;
  const view = VIEWS[active] ?? VIEWS.subnet;
  const activeLabel = modules.find((m) => m.key === active)?.label ?? view.title;

  return (
    <div className={`app${aiOpen ? "" : " ai-collapsed"}`}>
      <Sidebar info={info} modules={modules} active={active} onSelect={setActive} />

      <main className="main">
        <header className="topbar">
          <div>
            <h1>{activeLabel}</h1>
            <p>{view.desc}</p>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            {!isTauri && <span className="badge warn">浏览器预览</span>}
            <span className="badge">{info.osSummary}</span>
          </div>
        </header>
        <div className="content">{view.render()}</div>
      </main>

      <AiPanel collapsed={!aiOpen} onToggle={() => setAiOpen((v) => !v)} contextLabel={activeLabel} />
    </div>
  );
}
