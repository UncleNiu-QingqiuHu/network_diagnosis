import type { CSSProperties } from "react";
import type { AppInfo, ModuleInfo } from "../lib/types";

const GROUP_LABEL: Record<string, string> = {
  core: "核心",
  net: "网络",
  tool: "工具",
  info: "信息",
};

const GROUP_ORDER = ["core", "net", "tool", "info"];

interface Props {
  info: AppInfo | null;
  modules: ModuleInfo[];
  active: string;
  onSelect: (key: string) => void;
}

export default function Sidebar({ info, modules, active, onSelect }: Props) {
  const groups = GROUP_ORDER.map((g) => ({
    key: g,
    label: GROUP_LABEL[g] ?? g,
    items: modules.filter((m) => m.group === g),
  })).filter((g) => g.items.length > 0);

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
        {groups.map((g) => (
          <div className="nav-group" key={g.key}>
            <div className="nav-group-label">{g.label}</div>
            {g.items.map((m) => (
              <button
                key={m.key}
                className={`nav-item${m.key === active ? " active" : ""}`}
                onClick={() => onSelect(m.key)}
                type="button"
              >
                <span className="nav-dot" />
                <span>{m.label}</span>
              </button>
            ))}
          </div>
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
