import { useEffect, useRef, useState } from "react";
import {
  agentCancel,
  agentChat,
  agentConfirm,
  onAgentConfirm,
  onAgentDelta,
  onAgentTool,
} from "../lib/agent";
import type { ChatTurn, ConfirmRequest, ToolEvent } from "../lib/agent";

interface Msg {
  id: number;
  role: "user" | "agent" | "sys";
  text: string;
  tools: ToolEvent[];
  streaming?: boolean;
}

interface Props {
  /** 当前模块名，随请求送入模型 */
  contextLabel: string;
  /** 没有可用模型时引导去设置 */
  onOpenSettings: () => void;
  hidden: boolean;
}

const SUGGESTIONS = [
  "本机网段里有哪些设备在线？",
  "10.20.30.40/22 能放多少台主机？",
  "example.com 的证书还有多少天过期？",
];

const TOOL_LABEL: Record<string, string> = {
  subnet_calc: "子网计算",
  ping_host: "Ping 探测",
  trace_route: "路由追踪",
  check_ssl: "证书检查",
  run_command: "系统命令",
};

export default function AiChat({ contextLabel, onOpenSettings, hidden }: Props) {
  const [messages, setMessages] = useState<Msg[]>([]);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState<ConfirmRequest | null>(null);
  const [error, setError] = useState("");

  const seq = useRef(0);
  const streamingId = useRef<number | null>(null);
  const bodyRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!hidden) bodyRef.current?.scrollTo({ top: bodyRef.current.scrollHeight });
  }, [messages, hidden, confirm]);

  // 页面重载后，上一次请求可能还挂在后端（例如正等命令确认）。
  // 挂载时先发一次取消，避免新消息被「上一条还在处理中」挡住。
  useEffect(() => {
    void agentCancel().catch(() => undefined);
  }, []);

  // 事件订阅：增量、工具、命令确认
  useEffect(() => {
    let alive = true;
    const unsubs: Array<() => void> = [];

    void onAgentDelta((text) => {
      const id = streamingId.current;
      if (id == null) return;
      setMessages((prev) =>
        prev.map((m) => (m.id === id ? { ...m, text: m.text + text } : m)),
      );
    }).then((fn) => (alive ? unsubs.push(fn) : fn()));

    void onAgentTool((e) => {
      const id = streamingId.current;
      if (id == null) return;
      setMessages((prev) =>
        prev.map((m) => (m.id === id ? { ...m, tools: [...m.tools, e] } : m)),
      );
    }).then((fn) => (alive ? unsubs.push(fn) : fn()));

    let confirmTimer: number | undefined;
    void onAgentConfirm((req) => {
      setConfirm(req);
      // 后端 120 秒超时，这里同步收起，避免留下点不动的卡片
      window.clearTimeout(confirmTimer);
      confirmTimer = window.setTimeout(() => setConfirm(null), 120_000);
    }).then((fn) => (alive ? unsubs.push(fn) : fn()));

    return () => {
      alive = false;
      unsubs.forEach((fn) => fn());
      window.clearTimeout(confirmTimer);
    };
  }, []);


  function push(role: Msg["role"], text: string): number {
    seq.current += 1;
    const id = seq.current;
    setMessages((prev) => [...prev, { id, role, text, tools: [] }]);
    return id;
  }

  async function send(text: string) {
    const body = text.trim();
    if (!body || busy) return;

    const history: ChatTurn[] = messages
      .filter((m) => m.role !== "sys")
      .map((m) => ({
        role: m.role === "user" ? ("user" as const) : ("assistant" as const),
        content: m.text,
      }));

    setDraft("");
    setError("");
    push("user", body);
    const agentId = push("agent", "");
    streamingId.current = agentId;
    setBusy(true);

    try {
      const reply = await agentChat([...history, { role: "user", content: body }], contextLabel);
      setMessages((prev) =>
        prev.map((m) =>
          m.id === agentId
            ? { ...m, text: reply.content || m.text || "（模型没有返回内容）", streaming: false }
            : m,
        ),
      );
      if (reply.cancelled) push("sys", "已停止生成。");
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(msg);
      setMessages((prev) =>
        prev.map((m) => (m.id === agentId && !m.text ? { ...m, text: "（本轮没有产出）" } : m)),
      );
    } finally {
      streamingId.current = null;
      setBusy(false);
      setConfirm(null);
    }
  }

  async function decide(approved: boolean) {
    if (!confirm) return;
    const id = confirm.id;
    setConfirm(null);
    await agentConfirm(id, approved).catch(() => undefined);
  }

  async function stop() {
    await agentCancel().catch(() => undefined);
  }

  return (
    <div
      style={{ display: hidden ? "none" : "flex", flexDirection: "column", minHeight: 0, flex: 1 }}
    >
      <div className="ai-body" ref={bodyRef}>
        {messages.length === 0 ? (
          <div className="ai-empty">
            <p>
              网络运维助手 · 当前上下文：<strong>{contextLabel}</strong>
            </p>
            <p>
              我只处理网络与 IT 运维问题，可调用本机的诊断能力获取真实数据；
              渗透、攻击类请求不在服务范围。
            </p>
            <div className="suggest">
              {SUGGESTIONS.map((s) => (
                <button key={s} onClick={() => void send(s)} type="button">
                  {s}
                </button>
              ))}
            </div>
            <button className="btn" type="button" onClick={onOpenSettings}>
              配置模型
            </button>
          </div>
        ) : (
          messages.map((m) => (
            <div key={m.id} className={`bubble ${m.role}`}>
              {m.tools.length > 0 && (
                <div style={{ display: "grid", gap: 4, marginBottom: 6 }}>
                  {m.tools.map((t) => (
                    <div
                      key={t.id}
                      className="tool-chip"
                      title={t.preview}
                      data-status={t.status}
                    >
                      <span className="tool-chip-name">
                        {TOOL_LABEL[t.name] ?? t.name}
                      </span>
                      <span className="tool-chip-status">
                        {t.status === "ok" ? "已执行" : "失败"}
                      </span>
                    </div>
                  ))}
                </div>
              )}
              {m.text || (m.streaming && <span className="spin" />)}
            </div>
          ))
        )}
      </div>

      {confirm && (
        <div className="confirm-card">
          <div className="confirm-head">请求执行系统命令</div>
          <div className="confirm-cmd mono">
            {confirm.program} {confirm.args.join(" ")}
          </div>
          <div className="confirm-note">
            只读诊断命令才会被允许执行；确认前请核对参数。
          </div>
          <div style={{ display: "flex", gap: 6, marginTop: 8 }}>
            <button className="btn primary" type="button" onClick={() => void decide(true)}>
              允许执行
            </button>
            <button className="btn" type="button" onClick={() => void decide(false)}>
              拒绝
            </button>
          </div>
        </div>
      )}

      {error && <div className="alert error" style={{ margin: "0 12px 8px" }}>{error}</div>}

      <div className="ai-foot">
        <div className="ai-input">
          <textarea
            value={draft}
            placeholder="描述你的网络问题…"
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                void send(draft);
              }
            }}
          />
          {busy ? (
            <button className="btn" type="button" onClick={() => void stop()}>
              停止
            </button>
          ) : (
            <button
              className="btn primary"
              disabled={!draft.trim()}
              onClick={() => void send(draft)}
              type="button"
            >
              发送
            </button>
          )}
        </div>
        <div className="ai-tip">Enter 发送 · Shift+Enter 换行</div>
      </div>
    </div>
  );
}
