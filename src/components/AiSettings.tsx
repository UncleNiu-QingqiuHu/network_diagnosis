import { useState } from "react";
import {
  agentDeleteModel,
  agentSaveModel,
  agentSetActiveModel,
  agentSetOptions,
} from "../lib/agent";
import type { AgentConfigView, ModelView } from "../lib/agent";

interface Props {
  config: AgentConfigView | null;
  onReload: () => void;
  onError: (msg: string) => void;
  hidden: boolean;
}

interface Draft {
  id: string;
  name: string;
  baseUrl: string;
  model: string;
  maxTokens: number;
  temperature: number;
  key: string;
}

const EMPTY: Draft = {
  id: "",
  name: "",
  baseUrl: "",
  model: "",
  maxTokens: 4096,
  temperature: 0.3,
  key: "",
};

/** 常见服务商的 BaseURL 快捷填充，减少填错地址。 */
const PRESETS: Array<{ label: string; baseUrl: string; model: string }> = [
  { label: "DeepSeek", baseUrl: "https://api.deepseek.com/v1", model: "deepseek-chat" },
  { label: "通义千问", baseUrl: "https://dashscope.aliyuncs.com/compatible-mode/v1", model: "qwen-plus" },
  { label: "Kimi", baseUrl: "https://api.moonshot.cn/v1", model: "moonshot-v1-8k" },
  { label: "智谱", baseUrl: "https://open.bigmodel.cn/api/paas/v4", model: "glm-4-flash" },
  { label: "OpenAI", baseUrl: "https://api.openai.com/v1", model: "gpt-4o-mini" },
  { label: "本地 Ollama", baseUrl: "http://127.0.0.1:11434/v1", model: "qwen2.5" },
];

export default function AiSettings({ config, onReload, onError, hidden }: Props) {
  const [draft, setDraft] = useState<Draft | null>(null);
  const [busy, setBusy] = useState(false);

  async function run(fn: () => Promise<unknown>) {
    setBusy(true);
    try {
      await fn();
      onReload();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  function edit(m: ModelView) {
    setDraft({
      id: m.id,
      name: m.name,
      baseUrl: m.baseUrl,
      model: m.model,
      maxTokens: m.maxTokens,
      temperature: m.temperature,
      key: "",
    });
  }

  async function save() {
    if (!draft) return;
    if (!draft.name.trim() || !draft.baseUrl.trim() || !draft.model.trim()) {
      onError("名称、接口地址、模型 ID 都要填。");
      return;
    }
    await run(() =>
      agentSaveModel(
        {
          id: draft.id,
          name: draft.name.trim(),
          baseUrl: draft.baseUrl.trim(),
          model: draft.model.trim(),
          maxTokens: draft.maxTokens,
          temperature: draft.temperature,
        },
        draft.key.trim() || undefined,
      ),
    );
    setDraft(null);
  }

  const models = config?.models ?? [];

  return (
    <div className="ai-body" style={{ display: hidden ? "none" : "flex" }}>
      <div className="section-title">模型</div>
      {models.length === 0 && (
        <p className="ai-tip">还没有模型。下面新增一个，BaseURL 与模型 ID 见服务商文档。</p>
      )}

      {models.map((m) => (
        <div key={m.id} className="model-row">
          <div style={{ minWidth: 0 }}>
            <div className="model-name">
              {m.name}
              {config?.activeModel === m.id && <span className="tag ok">当前</span>}
              {!m.hasKey && <span className="tag warn">无 Key</span>}
            </div>
            <div className="ai-tip mono ellipsis" title={`${m.baseUrl} · ${m.model}`}>
              {m.model} · {m.baseUrl}
            </div>
          </div>
          <div style={{ display: "flex", gap: 4 }}>
            {config?.activeModel !== m.id && (
              <button
                className="btn"
                type="button"
                disabled={busy}
                onClick={() => void run(() => agentSetActiveModel(m.id))}
              >
                启用
              </button>
            )}
            <button className="btn" type="button" disabled={busy} onClick={() => edit(m)}>
              编辑
            </button>
            <button
              className="btn"
              type="button"
              disabled={busy}
              onClick={() => {
                if (!window.confirm(`删除模型「${m.name}」？已保存的 API Key 也会一并清除。`)) return;
                void run(() => agentDeleteModel(m.id));
              }}
            >
              删除
            </button>
          </div>
        </div>
      ))}

      {draft === null ? (
        <button className="btn" type="button" onClick={() => setDraft({ ...EMPTY })}>
          添加模型
        </button>
      ) : (
        <div className="card" style={{ padding: 10, display: "grid", gap: 8 }}>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
            {PRESETS.map((p) => (
              <button
                key={p.label}
                className="btn"
                type="button"
                style={{ height: 26, padding: "0 8px", fontSize: 11 }}
                onClick={() =>
                  setDraft((d) =>
                    d ? { ...d, name: d.name || p.label, baseUrl: p.baseUrl, model: p.model } : d,
                  )
                }
              >
                {p.label}
              </button>
            ))}
          </div>

          <label className="field">
            <span>名称</span>
            <input
              className="input"
              value={draft.name}
              onChange={(e) => setDraft({ ...draft, name: e.target.value })}
              placeholder="DeepSeek 生产"
            />
          </label>
          <label className="field">
            <span>接口地址（BaseURL）</span>
            <input
              className="input mono"
              value={draft.baseUrl}
              onChange={(e) => setDraft({ ...draft, baseUrl: e.target.value })}
              placeholder="https://api.deepseek.com/v1"
            />
          </label>
          <label className="field">
            <span>模型 ID</span>
            <input
              className="input mono"
              value={draft.model}
              onChange={(e) => setDraft({ ...draft, model: e.target.value })}
              placeholder="deepseek-chat"
            />
          </label>
          <div style={{ display: "flex", gap: 8 }}>
            <label className="field" style={{ flex: 1 }}>
              <span>max_tokens</span>
              <input
                className="input mono"
                value={draft.maxTokens}
                onChange={(e) =>
                  setDraft({ ...draft, maxTokens: Number(e.target.value) || 4096 })
                }
              />
            </label>
            <label className="field" style={{ flex: 1 }}>
              <span>temperature</span>
              <input
                className="input mono"
                value={draft.temperature}
                onChange={(e) =>
                  setDraft({ ...draft, temperature: Number(e.target.value) || 0 })
                }
              />
            </label>
          </div>
          <label className="field">
            <span>API Key{draft.id ? "（留空则不修改）" : ""}</span>
            <input
              className="input mono"
              type="password"
              value={draft.key}
              onChange={(e) => setDraft({ ...draft, key: e.target.value })}
              autoComplete="off"
              placeholder={config?.vaultBackend ?? "系统凭据管理器"}
            />
          </label>

          <div style={{ display: "flex", gap: 6 }}>
            <button className="btn primary" type="button" disabled={busy} onClick={() => void save()}>
              保存
            </button>
            <button className="btn" type="button" onClick={() => setDraft(null)}>
              取消
            </button>
          </div>
        </div>
      )}

      <div className="section-title" style={{ marginTop: 6 }}>
        能力边界
      </div>
      <p className="ai-tip">
        Agent 被限定为网络运维助手：越界请求（渗透、攻击、无关话题）会被告知不在范围。
        内置诊断工具始终可用，系统命令需单独开启。
      </p>

      <label className="check" style={{ alignItems: "flex-start" }}>
        <input
          type="checkbox"
          checked={config?.allowCommands ?? false}
          disabled={busy}
          onChange={(e) =>
            void run(() =>
              agentSetOptions(e.target.checked, config?.confirmCommands ?? true),
            )
          }
        />
        <span>
          允许执行本机命令
          <span className="ai-tip">
            仅白名单内的只读命令（ping / tracert / nslookup / arp / ipconfig / route print /
            netstat）。
          </span>
        </span>
      </label>

      <label className="check" style={{ alignItems: "flex-start" }}>
        <input
          type="checkbox"
          checked={config?.confirmCommands ?? true}
          disabled={busy || !(config?.allowCommands ?? false)}
          onChange={(e) =>
            void run(() => agentSetOptions(config?.allowCommands ?? false, e.target.checked))
          }
        />
        <span>
          每条命令执行前询问我
          <span className="ai-tip">关闭后模型会在白名单范围内直接执行，风险自负。</span>
        </span>
      </label>

      <p className="ai-tip">
        API Key 保存在{config?.vaultBackend ?? "系统凭据管理器"}，配置文件中不出现明文。
      </p>
    </div>
  );
}
