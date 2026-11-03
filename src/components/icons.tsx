import type { ReactNode } from "react";

/**
 * 侧栏图标注册表。
 *
 * 后端 `ModuleInfo.icon` 返回语义名，这里按名渲染。
 * 取不到时回退默认图标 —— 新增模块即便忘了登记图标，
 * 导航也不会出现空白位，只是样式朴素一档。
 */
const PATHS: Record<string, ReactNode> = {
  // 网络诊断：信号波动
  wave: <path d="M3 12h3.5L10 4.5 14 19.5 17.5 12H21" />,

  // 子网计算：一个父节点分叉到两个子节点
  split: (
    <>
      <rect x="9" y="2.5" width="6" height="5" rx="1.5" />
      <rect x="2.5" y="16.5" width="6" height="5" rx="1.5" />
      <rect x="15.5" y="16.5" width="6" height="5" rx="1.5" />
      <path d="M12 7.5v4.5M5.5 16.5V12h13v4.5" />
    </>
  ),

  // IP 扫描：雷达扫描
  radar: (
    <>
      <circle cx="12" cy="12" r="9" />
      <circle cx="12" cy="12" r="4.5" />
      <path d="M12 12l6.4-6.4" />
      <circle cx="12" cy="12" r="1" fill="currentColor" stroke="none" />
    </>
  ),

  // MAC 扫描：芯片
  chip: (
    <>
      <rect x="6.5" y="6.5" width="11" height="11" rx="2" />
      <path d="M10 3v3.5M14 3v3.5M10 17.5V21M14 17.5V21M3 10h3.5M3 14h3.5M17.5 10H21M17.5 14H21" />
    </>
  ),

  // SSL 证书：盾牌 + 勾
  shield: (
    <>
      <path d="M12 2.5l7.5 3v6c0 4.6-3.1 8.2-7.5 10-4.4-1.8-7.5-5.4-7.5-10v-6z" />
      <path d="M8.8 11.8l2.3 2.3 4.1-4.4" />
    </>
  ),

  // 关于：信息
  info: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11v5.5" />
      <circle cx="12" cy="7.9" r="1" fill="currentColor" stroke="none" />
    </>
  ),

  // 许可：文档
  doc: (
    <>
      <path d="M14 2.5H7a2 2 0 0 0-2 2v15a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7.5z" />
      <path d="M14 2.5v5h5" />
      <path d="M8.5 13h7M8.5 17h4.5" />
    </>
  ),
};

/** 未登记图标名的回退：小圆点。 */
const FALLBACK = <circle cx="12" cy="12" r="3.5" />;

interface Props {
  name: string;
  size?: number;
}

export default function NavIcon({ name, size = 17 }: Props) {
  return (
    <svg
      className="nav-icon"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.6}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {PATHS[name] ?? FALLBACK}
    </svg>
  );
}
