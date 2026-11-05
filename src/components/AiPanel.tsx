import { useCallback, useEffect, useState } from "react";
import AiChat from "./AiChat";
import AiSettings from "./AiSettings";
import AiSkills from "./AiSkills";
import { agentConfig } from "../lib/agent";
import type { AgentConfigView } from "../lib/agent";

type Tab = "chat" | "skills" | "settings";

interface Props {
  collapsed: boolean;
  onToggle: () => void;
  /** 当前所在模块，供 AI 感知上下文 */
  contextLabel: string;
}

const TABS: Array<{ key: Tab; label: string }> = [
  { key: "chat", label: "对话" },
  { key: "skills", label: "技能" },
  { key: "settings", label: "设置" },
];

export default function AiPanel({ collapsed, onToggle, contextLabel }: Props) {
  const [tab, setTab] = useState<Tab>("chat");
  const [config, setConfig] = useState<AgentConfigView | null>(null);
  const [error, setError] = useState("");

  const reload = useCallback(async () => {
    try {
      const c = await agentConfig();
      setConfig(c);
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);


  if (collapsed) {
    return (
      <aside className="ai collapsed">
        <div className="ai-head">
          <button className="icon-btn" onClick={onToggle} title="展开 AI Agent" type="button">
            <Chevron dir="left" />
          </button>
        </div>
        <div
          style={{
            writingMode: "vertical-rl",
            color: "var(--text-faint)",
            fontSize: 11,
            marginTop: 12,
          }}
        >
          AI Agent
        </div>
      </aside>
    );
  }

  const active = config?.models.find((m) => m.id === config.activeModel);
  const badgeText = active ? (active.hasKey ? active.name : `${active.name}（缺 Key）`) : "未配置";

  return (
    <aside className="ai">
      <div className="ai-head">
        <div className="ai-title">
          <span className="pulse" />
          <span>AI Agent</span>
        </div>
        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
          <span className={`badge ${active?.hasKey ? "" : "warn"}`} title={active?.model}>
            {badgeText}
          </span>
          <button className="icon-btn" onClick={onToggle} title="收起" type="button">
            <Chevron dir="right" />
          </button>
        </div>
      </div>

      <div className="ai-tabs">
        {TABS.map((t) => (
          <button
            key={t.key}
            type="button"
            className={tab === t.key ? "active" : ""}
            onClick={() => setTab(t.key)}
          >
            {t.label}
            {t.key === "skills" && config && config.skills.length > 0 && (
              <span className="ai-tab-count">{config.skills.length}</span>
            )}
          </button>
        ))}
      </div>

      {error && (
        <div className="alert error" style={{ margin: "0 12px 8px", fontSize: 11 }}>
          {error}
        </div>
      )}

      {/* 三个视图都保持挂载：切到设置页时对话流不会中断 */}
      <AiChat
        hidden={tab !== "chat"}
        contextLabel={contextLabel}
        onOpenSettings={() => setTab("settings")}
      />
      <AiSkills hidden={tab !== "skills"} config={config} onReload={reload} onError={setError} />
      <AiSettings hidden={tab !== "settings"} config={config} onReload={reload} onError={setError} />
    </aside>
  );
}

function Chevron({ dir }: { dir: "left" | "right" }) {
  const d = dir === "left" ? "M11 3L5.5 8L11 13" : "M5 3L10.5 8L5 13";
  return (
    <svg width="13" height="13" viewBox="0 0 16 16" aria-hidden="true">
      <path
        d={d}
        fill="none"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
