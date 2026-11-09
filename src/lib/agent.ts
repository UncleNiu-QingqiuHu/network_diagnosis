import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

export interface ModelConfig {
  id: string;
  name: string;
  baseUrl: string;
  model: string;
  maxTokens: number;
  temperature: number;
}

export interface ModelView extends ModelConfig {
  /** 系统凭据库里是否已存 Key（不回传 Key 本身） */
  hasKey: boolean;
}

export interface Skill {
  slug: string;
  name: string;
  description: string;
  source: string;
  importedAt: string;
  enabled: boolean;
}

export interface SkillCandidate {
  name: string;
  description: string;
  path: string;
  origin: string;
  bytes: number;
  imported: boolean;
}

export interface AgentConfigView {
  models: ModelView[];
  activeModel: string | null;
  allowCommands: boolean;
  confirmCommands: boolean;
  /** 凭据存放后端：系统凭据管理器 / 本地文件 */
  vaultBackend: string;
  skills: Skill[];
  scanRoots: string[];
}

export interface ChatTurn {
  role: "user" | "assistant";
  content: string;
}

export interface ChatReply {
  content: string;
  rounds: number;
  cancelled: boolean;
}

/** 会话消息里记录的工具摘要（落盘用，不含完整输出） */
export interface StoredTool {
  name: string;
  status: string;
  preview?: string;
}

export interface StoredMessage {
  role: "user" | "assistant";
  text: string;
  tools?: StoredTool[];
  at: string;
}

export interface Session {
  id: string;
  title: string;
  createdAt: string;
  updatedAt: string;
  messages: StoredMessage[];
}

export interface SessionSummary {
  id: string;
  title: string;
  updatedAt: string;
  messageCount: number;
  lastUserText: string;
}

export interface ToolEvent {
  id: string;
  name: string;
  /** ok / error */
  status: string;
  preview: string;
}

export interface ConfirmRequest {
  id: string;
  program: string;
  args: string[];
}

const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

function ensure() {
  if (!isTauri) throw new Error("AI Agent 需要 Rust 后端，请在 Tauri 窗口中运行。");
}

export async function agentConfig(): Promise<AgentConfigView> {
  ensure();
  return invoke<AgentConfigView>("agent_config");
}

export async function agentSaveModel(
  model: ModelConfig,
  key?: string,
): Promise<AgentConfigView> {
  ensure();
  return invoke<AgentConfigView>("agent_save_model", { model, key: key ?? null });
}

export async function agentDeleteModel(id: string): Promise<AgentConfigView> {
  ensure();
  return invoke<AgentConfigView>("agent_delete_model", { id });
}

export async function agentSetKey(id: string, key: string): Promise<void> {
  ensure();
  return invoke<void>("agent_set_key", { id, key });
}

export async function agentSetActiveModel(id: string): Promise<AgentConfigView> {
  ensure();
  return invoke<AgentConfigView>("agent_set_active_model", { id });
}

export async function agentSetOptions(
  allowCommands: boolean,
  confirmCommands: boolean,
): Promise<AgentConfigView> {
  ensure();
  return invoke<AgentConfigView>("agent_set_options", { allowCommands, confirmCommands });
}

export async function agentScanSkills(): Promise<SkillCandidate[]> {
  ensure();
  return invoke<SkillCandidate[]>("agent_scan_skills");
}

export async function agentImportSkill(path: string): Promise<Skill> {
  ensure();
  return invoke<Skill>("agent_import_skill", { path });
}

export async function agentSetSkillEnabled(slug: string, enabled: boolean): Promise<Skill> {
  ensure();
  return invoke<Skill>("agent_set_skill_enabled", { slug, enabled });
}

export async function agentDeleteSkill(slug: string): Promise<void> {
  ensure();
  return invoke<void>("agent_delete_skill", { slug });
}

export async function agentChat(messages: ChatTurn[], module?: string): Promise<ChatReply> {
  ensure();
  return invoke<ChatReply>("agent_chat", { messages, module: module ?? null });
}

export async function agentCancel(): Promise<void> {
  ensure();
  return invoke<void>("agent_cancel");
}

export async function agentConfirm(requestId: string, approved: boolean): Promise<void> {
  ensure();
  return invoke<void>("agent_confirm", { requestId, approved });
}

/** 流式文本增量。 */
export async function onAgentDelta(handler: (text: string) => void): Promise<() => void> {
  if (!isTauri) return () => undefined;
  return listen<string>("agent-delta", (e) => handler(e.payload));
}

export async function onAgentTool(handler: (e: ToolEvent) => void): Promise<() => void> {
  if (!isTauri) return () => undefined;
  return listen<ToolEvent>("agent-tool", (e) => handler(e.payload));
}

/** 命令执行确认请求。 */
export async function onAgentConfirm(
  handler: (req: ConfirmRequest) => void,
): Promise<() => void> {
  if (!isTauri) return () => undefined;
  return listen<ConfirmRequest>("agent-confirm", (e) => handler(e.payload));
}

// ---------------------------------------------------------------- 会话

export async function agentSessions(): Promise<SessionSummary[]> {
  ensure();
  return invoke<SessionSummary[]>("agent_sessions");
}

export async function agentSessionGet(id: string): Promise<Session> {
  ensure();
  return invoke<Session>("agent_session_get", { id });
}

export async function agentSessionNew(): Promise<Session> {
  ensure();
  return invoke<Session>("agent_session_new");
}

/** 往会话里追加一条消息，返回更新后的列表项。 */
export async function agentSessionAppend(
  id: string,
  role: "user" | "assistant",
  text: string,
  tools?: ToolEvent[],
): Promise<SessionSummary> {
  ensure();
  return invoke<SessionSummary>("agent_session_append", {
    id,
    role,
    text,
    tools: (tools ?? []).map((t) => ({
      name: t.name,
      status: t.status,
      preview: t.preview.slice(0, 300),
    })),
  });
}

export async function agentSessionRename(id: string, title: string): Promise<SessionSummary> {
  ensure();
  return invoke<SessionSummary>("agent_session_rename", { id, title });
}

/** 删除会话，返回剩余列表（后端保证至少留一个）。 */
export async function agentSessionDelete(id: string): Promise<SessionSummary[]> {
  ensure();
  return invoke<SessionSummary[]>("agent_session_delete", { id });
}
