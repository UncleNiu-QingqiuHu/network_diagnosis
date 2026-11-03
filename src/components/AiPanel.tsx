import { useRef, useState } from "react";
import { aiChat } from "../lib/api";

type Role = "user" | "agent" | "sys";

interface Msg {
  id: number;
  role: Role;
  text: string;
}

interface Props {
  collapsed: boolean;
  onToggle: () => void;
  /** 当前所在模块，供 AI 感知上下文（M4 会随请求一并送入模型）。 */
  contextLabel: string;
}

const SUGGESTIONS = [
  "诊断 192.168.1.1 的连通性",
  "计算 10.20.30.40/22 的子网",
  "这个网段能划出多少 /26 子网",
];

export default function AiPanel({ collapsed, onToggle, contextLabel }: Props) {
  const [messages, setMessages] = useState<Msg[]>([]);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const seq = useRef(0);

  const push = (role: Role, text: string) => {
    seq.current += 1;
    const id = seq.current;
    setMessages((prev) => [...prev, { id, role, text }]);
  };

  const send = async (text: string) => {
    const body = text.trim();
    if (!body || busy) return;
    setDraft("");
    push("user", body);
    setBusy(true);
    try {
      const reply = await aiChat(body);
      push("agent", reply);
    } catch (e) {
      push("sys", e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  if (collapsed) {
    return (
      <aside className="ai collapsed">
        <div className="ai-head">
          <button className="icon-btn" onClick={onToggle} title="展开 AI Agent" type="button">
            <Chevron dir="left" />
          </button>
        </div>
        <div style={{ writingMode: "vertical-rl", color: "var(--text-faint)", fontSize: 11, marginTop: 12 }}>
          AI Agent
        </div>
      </aside>
    );
  }

  return (
    <aside className="ai">
      <div className="ai-head">
        <div className="ai-title">
          <span className="pulse" />
          <span>AI Agent</span>
        </div>
        <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
          <span className="badge warn">未接入</span>
          <button className="icon-btn" onClick={onToggle} title="收起" type="button">
            <Chevron dir="right" />
          </button>
        </div>
      </div>

      <div className="ai-body">
        {messages.length === 0 ? (
          <div className="ai-empty">
            <p>当前上下文：{contextLabel}</p>
            <p>直接描述你要做的事，助手会调用本机能力完成。</p>
            <div className="suggest">
              {SUGGESTIONS.map((s) => (
                <button key={s} onClick={() => void send(s)} type="button">
                  {s}
                </button>
              ))}
            </div>
          </div>
        ) : (
          messages.map((m) => (
            <div key={m.id} className={`bubble ${m.role}`}>
              {m.text}
            </div>
          ))
        )}
      </div>

      <div className="ai-foot">
        <div className="ai-input">
          <textarea
            value={draft}
            placeholder="向 AI 描述你的需求…"
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                void send(draft);
              }
            }}
          />
          <button className="btn primary" disabled={busy || !draft.trim()} onClick={() => void send(draft)} type="button">
            {busy ? "…" : "发送"}
          </button>
        </div>
        <div className="ai-tip">Enter 发送 · Shift+Enter 换行</div>
      </div>
    </aside>
  );
}

function Chevron({ dir }: { dir: "left" | "right" }) {
  const d = dir === "left" ? "M11 3L5.5 8L11 13" : "M5 3L10.5 8L5 13";
  return (
    <svg width="13" height="13" viewBox="0 0 16 16" aria-hidden="true">
      <path d={d} fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
