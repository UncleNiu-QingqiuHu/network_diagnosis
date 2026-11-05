import { localNetwork } from "./api";

/**
 * 扫描范围的初始值。
 *
 * 顺序：本地记忆 → 按本机网卡推断 → 空串（交给界面提示手动填写）。
 * 记忆值存在 localStorage，避免每次打开都重新推断；推断结果也会写入记忆，
 * 这样即使用户清空了输入框，下次仍能回到本机网段。
 */
export async function resolveScanScope(storageKey: string): Promise<string> {
  const saved = localStorage.getItem(storageKey)?.trim();
  if (saved) return saved;

  try {
    const info = await localNetwork();
    const scope = info.scope?.trim();
    if (scope) {
      localStorage.setItem(storageKey, scope);
      return scope;
    }
  } catch {
    // 浏览器预览模式下后端不可用，保持空值
  }
  return "";
}

/** 记住用户实际使用的范围。 */
export function rememberScanScope(storageKey: string, value: string): void {
  const v = value.trim();
  if (v) localStorage.setItem(storageKey, v);
}
