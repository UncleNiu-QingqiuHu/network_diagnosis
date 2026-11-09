import { useEffect, useRef, useState } from "react";
import {
  agentCancel,
  agentChat,
  agentConfirm,
  agentSessionAppend,
  agentSessionDelete,
  agentSessionGet,
  agentSessionNew,
  agentSessionRename,
  agentSessions,
  onAgentConfirm,
  onAgentDelta,
  onAgentTool,
} from "../lib/agent";
import type {
  ChatTurn,
  ConfirmRequest,
  Session,
  SessionSummary,
  ToolEvent,
} from "../lib/agent";

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

/** 会话落盘的消息 → 界面气泡。 */
function toMsgs(s: Session): Msg[] {
  return s.messages.map((m, i) => ({
    id: i + 1,
    role: m.role === "user" ? "user" : "agent",
    text: m.text,
    tools: (m.tools ?? []).map((t, j) => ({
      id: `${i}-${j}`,
      name: t.name,
      status: t.status,
      preview: t.preview ?? "",
    })),
  }));
}

/** 列表里的时间：今天只显示时分，其它显示月-日。 */
function fmtWhen(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const now = new Date();
  const sameDay =
    d.getFullYear() === now.getFullYear() &&
    d.getMonth() === now.getMonth() &&
    d.getDate() === now.getDate();
  const pad = (n: number) => String(n).padStart(2, "0");
  return sameDay
    ? `${pad(d.getHours())}:${pad(d.getMinutes())}`
    : `${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

export default function AiChat({ contextLabel, onOpenSettings, hidden }: Props) {
  const [messages, setMessages] = useState<Msg[]>([]);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState<ConfirmRequest | null>(null);
  const [error, setError] = useState("");

  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [title, setTitle] = useState("新对话");
  const [picker, setPicker] = useState(false);
  const [renaming, setRenaming] = useState(false);
  const [titleDraft, setTitleDraft] = useState("");

  const seq = useRef(0);
  const streamingId = useRef<number | null>(null);
  /** 本轮流式累积的文本：delta 回调里同步累加，落盘时不必回头读 state */
  const streamText = useRef("");
  /** 本轮调用过的工具，随助手消息一起落盘 */
  const roundTools = useRef<ToolEvent[]>([]);
  const bodyRef = useRef<HTMLDivElement | null>(null);
  const titleRef = useRef<HTMLInputElement | null>(null);
  /** 同步发送守卫：`busy` 是异步 state，快速连点或重复触发时会漏过 */
  const sendingRef = useRef(false);

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
      streamText.current += text;
      const id = streamingId.current;
      if (id == null) return;
      setMessages((prev) =>
        prev.map((m) => (m.id === id ? { ...m, text: m.text + text } : m)),
      );
    }).then((fn) => (alive ? unsubs.push(fn) : fn()));

    void onAgentTool((e) => {
      roundTools.current = [...roundTools.current, e];
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

  // 首次进入：拉列表并打开最近的会话
  useEffect(() => {
    let alive = true;
    void (async () => {
      try {
        const list = await agentSessions();
        if (!alive) return;
        setSessions(list);
        if (list[0]) await openSession(list[0].id);
      } catch (e) {
        if (alive) setError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);


  async function openSession(id: string) {
    if (busy) return;
    try {
      const s = await agentSessionGet(id);
      const list = toMsgs(s);
      seq.current = list.length;
      streamingId.current = null;
      setMessages(list);
      setSessionId(s.id);
      setTitle(s.title);
      setError("");
      setPicker(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function newSession() {
    if (busy) return;
    try {
      const s = await agentSessionNew();
      seq.current = 0;
      setMessages([]);
      setSessionId(s.id);
      setTitle(s.title);
      setPicker(false);
      setError("");
      setSessions(await agentSessions());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function removeSession(id: string) {
    if (busy) return;
    try {
      const rest = await agentSessionDelete(id);
      setSessions(rest);
      if (id === sessionId) {
        const next = rest[0];
        if (next) await openSession(next.id);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  function startRename() {
    setTitleDraft(title);
    setRenaming(true);
    window.setTimeout(() => titleRef.current?.select(), 0);
  }

  async function commitRename() {
    setRenaming(false);
    const next = titleDraft.trim();
    if (!sessionId || !next || next === title) return;
    try {
      const sum = await agentSessionRename(sessionId, next);
      setTitle(sum.title);
      setSessions(await agentSessions());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  function push(role: Msg["role"], text: string): number {
    seq.current += 1;
    const id = seq.current;
    setMessages((prev) => [...prev, { id, role, text, tools: [] }]);
    return id;
  }

  async function send(text: string) {
    const body = text.trim();
    if (!body || busy || sendingRef.current) return;
    sendingRef.current = true;

    // 首次发送时可能还没拿到会话（列表加载失败等），兜一个
    let sid = sessionId;
    if (!sid) {
      try {
        const s = await agentSessionNew();
        sid = s.id;
        setSessionId(s.id);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
        sendingRef.current = false;
        return;
      }
    }

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
    streamText.current = "";
    roundTools.current = [];
    setBusy(true);

    let finalText = "";
    try {
      const reply = await agentChat([...history, { role: "user", content: body }], contextLabel);
      finalText = reply.content || streamText.current || "（模型没有返回内容）";
      setMessages((prev) =>
        prev.map((m) => (m.id === agentId ? { ...m, text: finalText, streaming: false } : m)),
      );
      if (reply.cancelled) push("sys", "已停止生成。");
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(msg);
      // 中断前已经流出的内容仍然有价值，别丢
      finalText = streamText.current;
      setMessages((prev) =>
        prev.map((m) =>
          m.id === agentId ? { ...m, text: finalText || "（本轮没有产出）", streaming: false } : m,
        ),
      );
    } finally {
      streamingId.current = null;
      setBusy(false);
      setConfirm(null);
      sendingRef.current = false;

      // 落盘：用户消息与助手回复各记一条，工具标签跟着助手消息走
      const tools = roundTools.current;
      try {
        await agentSessionAppend(sid, "user", body);
        if (finalText) {
          const sum = await agentSessionAppend(sid, "assistant", finalText, tools);
          setTitle(sum.title);
        }
        setSessions(await agentSessions());
      } catch (e) {
        setError(`对话已生成，但保存失败：${e instanceof Error ? e.message : String(e)}`);
      }
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
      style={{
        display: hidden ? "none" : "flex",
        flexDirection: "column",
        minHeight: 0,
        flex: 1,
        position: "relative",
      }}
    >
      <div className="sess-bar">
        {renaming ? (
          <input
            ref={titleRef}
            className="sess-input"
            value={titleDraft}
            maxLength={60}
            onChange={(e) => setTitleDraft(e.target.value)}
            onBlur={() => void commitRename()}
            onKeyDown={(e) => {
              if (e.key === "Enter") void commitRename();
              if (e.key === "Escape") setRenaming(false);
            }}
          />
        ) : (
          <button
            className="sess-current"
            type="button"
            onClick={() => setPicker((v) => !v)}
            title="切换会话"
          >
            <span className="sess-title">{title}</span>
            <span className="sess-caret">{picker ? "▲" : "▼"}</span>
          </button>
        )}
        <button className="icon-btn" type="button" title="重命名当前会话" onClick={startRename}>
          <PenIcon />
        </button>
        <button
          className="icon-btn"
          type="button"
          title="新建对话"
          onClick={() => void newSession()}
          disabled={busy}
        >
          <PlusIcon />
        </button>
      </div>

      {picker && (
        <div className="sess-menu">
          <div className="sess-menu-head">最近会话（{sessions.length}）</div>
          <div className="sess-menu-list">
            {sessions.map((s) => (
              <div
                key={s.id}
                className={`sess-item ${s.id === sessionId ? "active" : ""}`}
                onClick={() => void openSession(s.id)}
              >
                <div className="sess-item-main">
                  <div className="sess-item-title">{s.title}</div>
                  <div className="sess-item-sub">
                    {fmtWhen(s.updatedAt)} · {s.messageCount} 条
                    {s.lastUserText ? ` · ${s.lastUserText}` : ""}
                  </div>
                </div>
                <button
                  className="icon-btn danger"
                  type="button"
                  title="删除会话"
                  onClick={(e) => {
                    e.stopPropagation();
                    void removeSession(s.id);
                  }}
                >
                  ×
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

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

function PenIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 16 16" aria-hidden="true">
      <path
        d="M11.2 2.6l2.2 2.2M3 13l.5-2.6 7-7 2.1 2.1-7 7L3 13z"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.3"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function PlusIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 16 16" aria-hidden="true">
      <path
        d="M8 3v10M3 8h10"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
    </svg>
  );
}
