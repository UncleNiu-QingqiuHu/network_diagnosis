import type { CSSProperties } from "react";
import type { AppInfo, ModuleInfo } from "../lib/types";
import NavIcon from "./icons";

interface Props {
  info: AppInfo | null;
  modules: ModuleInfo[];
  active: string;
  onSelect: (key: string) => void;
}

export default function Sidebar({ info, modules, active, onSelect }: Props) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark" style={markStyle} />
        <div className="brand-text">
          <div className="brand-title">青丘湖网络工作台</div>
          <div className="brand-sub">workbench</div>
        </div>
      </div>

      <nav className="nav">
        {modules.map((m) => (
          <button
            key={m.key}
            className={`nav-item${m.key === active ? " active" : ""}`}
            onClick={() => onSelect(m.key)}
            type="button"
            title={m.label}
          >
            <NavIcon name={m.icon} />
            <span className="nav-label">{m.label}</span>
          </button>
        ))}
      </nav>

      <div className="sidebar-foot">
        <div className="foot-line">
          <span>版本</span>
          <span>{info ? `v${info.version}` : "—"}</span>
        </div>
        <div className="foot-line">
          <span>平台</span>
          <span>{info ? info.platformDisplay : "—"}</span>
        </div>
        <div className="foot-line">
          <span>权限</span>
          <span>{info ? (info.elevated ? "管理员" : "普通用户") : "—"}</span>
        </div>
      </div>
    </aside>
  );
}

const markStyle: CSSProperties = {
  background: "linear-gradient(135deg, #0F6E56, #141d29)",
  border: "1px solid #2dd4a733",
  position: "relative",
};
