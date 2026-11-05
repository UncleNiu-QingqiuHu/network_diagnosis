import { useState } from "react";
import {
  agentDeleteSkill,
  agentImportSkill,
  agentScanSkills,
  agentSetSkillEnabled,
} from "../lib/agent";
import type { AgentConfigView, SkillCandidate } from "../lib/agent";

interface Props {
  config: AgentConfigView | null;
  onReload: () => void;
  onError: (msg: string) => void;
  hidden: boolean;
}

export default function AiSkills({ config, onReload, onError, hidden }: Props) {
  const [candidates, setCandidates] = useState<SkillCandidate[] | null>(null);
  const [scanning, setScanning] = useState(false);
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

  async function scan() {
    setScanning(true);
    onError("");
    try {
      setCandidates(await agentScanSkills());
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setScanning(false);
    }
  }

  const skills = config?.skills ?? [];

  return (
    <div className="ai-body" style={{ display: hidden ? "none" : "flex" }}>
      <div className="section-title">已导入技能（{skills.length}）</div>
      <p className="ai-tip">
        启用后，技能内容会作为方法论注入系统提示词；与安全边界冲突时以边界为准。
      </p>

      {skills.length === 0 && <p className="ai-tip">还没有导入技能。可以扫描本机其它 Agent 的技能库。</p>}

      {skills.map((s) => (
        <div key={s.slug} className="skill-row">
          <div style={{ minWidth: 0 }}>
            <div className="model-name">
              {s.name}
              {s.enabled ? <span className="tag ok">已启用</span> : <span className="tag">已停用</span>}
            </div>
            <div className="ai-tip ellipsis" title={s.description}>
              {s.description || "（无描述）"}
            </div>
            <div className="ai-tip mono ellipsis" title={s.source}>
              {s.source}
            </div>
          </div>
          <div style={{ display: "flex", gap: 4 }}>
            <button
              className="btn"
              type="button"
              disabled={busy}
              onClick={() => void run(() => agentSetSkillEnabled(s.slug, !s.enabled))}
            >
              {s.enabled ? "停用" : "启用"}
            </button>
            <button
              className="btn"
              type="button"
              disabled={busy}
              onClick={() => {
                if (!window.confirm(`删除技能「${s.name}」？只删除本应用内的副本。`)) return;
                void run(() => agentDeleteSkill(s.slug));
              }}
            >
              删除
            </button>
          </div>
        </div>
      ))}

      <div className="section-title" style={{ marginTop: 6 }}>
        从本机导入
      </div>
      <p className="ai-tip">
        只读取其它 Agent 的技能目录，导入是复制一份到本应用，不会改动对方文件。
      </p>
      <button className="btn" type="button" disabled={scanning} onClick={() => void scan()}>
        {scanning ? "扫描中…" : "扫描本机 Agent 技能"}
      </button>

      {config && config.scanRoots.length > 0 && (
        <details>
          <summary className="ai-tip">扫描位置（{config.scanRoots.length}）</summary>
          {config.scanRoots.map((r) => (
            <div key={r} className="ai-tip mono ellipsis" title={r}>
              {r}
            </div>
          ))}
        </details>
      )}

      {candidates !== null &&
        (candidates.length === 0 ? (
          <p className="ai-tip">没有找到技能。确认目标 Agent 已安装并存在技能目录。</p>
        ) : (
          candidates.map((c) => (
            <div key={c.path} className="skill-row">
              <div style={{ minWidth: 0 }}>
                <div className="model-name">
                  {c.name}
                  <span className="tag">{c.origin}</span>
                </div>
                <div className="ai-tip ellipsis" title={c.description}>
                  {c.description || "（无描述）"}
                </div>
                <div className="ai-tip mono ellipsis" title={c.path}>
                  {c.path}
                </div>
              </div>
              <button
                className="btn"
                type="button"
                disabled={busy || c.imported}
                onClick={() => void run(() => agentImportSkill(c.path))}
              >
                {c.imported ? "已导入" : "导入"}
              </button>
            </div>
          ))
        ))}
    </div>
  );
}
