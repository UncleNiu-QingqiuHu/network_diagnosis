# 青丘狐网络工作台 · Rust + Tauri 重构版

本目录是 `feat/rust-tauri-rewrite` 分支上的重写实现，与仓库根目录的 Python 版并存，
用于逐模块替换与结果对拍。Python 版在过渡期内保持可用。

## 当前状态

| 项 | 状态 |
|---|---|
| 三栏骨架（导航 / 模块 / AI Agent 右栏） | 已完成 |
| 平台抽象层 + 能力矩阵 | 已完成 |
| 子网计算（首个端到端功能） | 已完成 |
| 网络诊断 | 排期 M2 |
| IP 扫描 / MAC 扫描 | 排期 M3 |
| SSL 证书 / AI 接入 | 排期 M4 |

## 目录结构

```text
workbench/
├── Cargo.toml              # workspace
├── crates/
│   ├── qqhu-core/          # 领域模型 / 子网计算 / 质量评分（零平台依赖，纯单测）
│   └── qqhu-sys/           # 平台抽象层：HostPlatform trait + 能力矩阵
├── src-tauri/              # Tauri 应用层：IPC 命令
└── src/                    # 前端 React + TS
    ├── components/         # Sidebar / AiPanel
    ├── modules/            # 各功能页面
    └── lib/                # 类型契约与 IPC 封装
```

## 开发

```bash
pnpm install
pnpm app:dev      # 启动桌面应用（自动拉起 vite dev server）
pnpm app:build    # 打包
pnpm build        # 仅校验前端
cargo test        # 跑 Rust 单测
```

只调界面时可 `pnpm dev` 用浏览器打开，此时后端未连接，界面显示「浏览器预览」角标。

## 关键设计决策

**1. 导航清单由 Rust 返回，前端不硬编码**

`app_info` 命令返回当前构建可用的模块列表。Windows 专有模块用 `cfg(target_os = "windows")`
编译，mac/Linux 构建里根本不存在这些入口——不需要运行期判断平台。

**2. 能力矩阵而非散落的 cfg**

`CapabilitySet` 一次性给出 15 个模块的 `full / partial / unavailable`，前端据此决定
显示、标注限制或灰化。新增平台差异时只改一处。

**3. 前后端契约以 serde camelCase 为准**

`crates/qqhu-core/src/model.rs` 与 `src/lib/types.ts` 必须同步修改。
后续引入 `ts-rs` 自动生成，消除手工漂移。

**4. AI Agent 为常驻右栏，不是导航页**

右侧栏保留在任意模块之上，并把当前模块名作为上下文传入（`contextLabel`），
M4 接入模型时随请求一并送入。IPC 通道已打通，`ai_chat` 目前返回明确的未实现错误。

## 待办

- [ ] M0 技术 spike：Windows 上原生 ICMP 免管理员验证 + 三平台 ARP 表获取
- [ ] CI 三平台矩阵（windows / macos / ubuntu 跑 `cargo check` + `cargo test`）
- [ ] `AppPaths`：跨平台可写目录解析（mac/Linux 不能写 app 包内部）
- [ ] `qqhu-cli`：报告对拍与批量诊断入口
