# 青丘湖网络工作台

Windows / macOS / Linux 桌面网络工作台，Rust + Tauri 2 + React 实现。

集成网络连通性诊断、子网计算、IP/MAC 扫描、SSL 证书管理等能力，
右侧常驻 AI Agent 侧栏可基于当前模块上下文发起操作。

> **仓库分支说明**
> - `main` —— 当前 Rust 实现（主产品线）
> - `legacy/python-v3` —— 上一代 Python + tkinter 实现（v3.4.2，已归档，仅保留查阅）
>
> 迁移前的完整快照见 tag `pre-migration-backup`。

## 当前状态

| 项 | 状态 |
|---|---|
| 三栏骨架（导航 / 模块 / AI Agent 右栏） | 已完成 |
| 平台抽象层 + 能力矩阵 | 已完成 |
| 子网计算 | 已完成 |
| 网络诊断（ICMP / TCP / DNS / 质量评判） | 已完成 |
| 诊断报告（Markdown 归档 + 历史对比） | 已完成 |
| 关于 / 许可 | 已完成 |
| 网络诊断进阶（Traceroute / MTU / 带宽） | 排期 M2.1 |
| IP 扫描 / MAC 扫描 | 排期 M3 |
| SSL 证书 / AI 接入 | 排期 M4 |

## 环境要求

- Rust 1.82+
- Node.js 20.19+ / 22.12+，pnpm 10+
- Windows 需 WebView2（Win11 自带；Win10 一般已随 Edge 安装）
- macOS 需 Xcode Command Line Tools
- Linux 需 `libwebkit2gtk-4.1-dev`、`libssl-dev`、`libayatana-appindicator3-dev`

## 开发

```bash
pnpm install
pnpm app:dev      # 启动桌面应用（自动拉起 vite dev server）
pnpm app:build    # 打包
pnpm build        # 仅校验前端
cargo test        # 跑 Rust 单测
```

只调界面时可 `pnpm dev` 用浏览器打开 `http://localhost:1420`，
此时后端未连接，界面显示「浏览器预览」角标。

## 目录结构

```text
.
├── Cargo.toml              # workspace 根
├── crates/
│   ├── qqhu-core/          # 领域模型 / 子网计算 / 质量评分 / 结论摘要（零平台依赖）
│   ├── qqhu-sys/           # 平台抽象层：HostPlatform trait + 能力矩阵
│   ├── qqhu-probe/         # 原生探针：ICMP / TCP / DNS / 诊断编排
│   └── qqhu-report/        # Markdown 报告渲染 / 历史索引与对比
├── src-tauri/              # Tauri 应用层：IPC 命令
├── src/                    # 前端 React + TS
│   ├── components/         # Sidebar / AiPanel
│   ├── modules/            # 各功能页面
│   └── lib/                # 类型契约与 IPC 封装
├── ThirdParty/             # 随包分发的第三方工具（iperf3 等）
└── skills/                 # AI Agent 可加载的技能定义
```

## 版本约定

采用 `4.0.0-alpha.x` 序列：表示「下一代重写」，与已归档的 Python 版 `v3.x` 明确区分。
每完成一个功能打一个 tag（如 `v4.0.0-alpha.2`），功能齐备可替换旧版时发布 `v4.0.0`。

版本号唯一来源是 `Cargo.toml` 的 `[workspace.package].version`；
`src-tauri/tauri.conf.json` 与 `package.json` 的 version 必须同步，打包元信息读取这两处。

## 关键设计决策

**1. 导航清单由 Rust 返回，前端不硬编码**

`app_info` 命令返回当前构建可用的模块列表。Windows 专有模块用 `cfg(target_os = "windows")`
编译，mac/Linux 构建里根本不存在这些入口——不需要运行期判断平台。

**2. 能力矩阵而非散落的 cfg**

`CapabilitySet` 一次性给出各模块的 `full / partial / unavailable`，前端据此决定
显示、标注限制或灰化。新增平台差异时只改一处。

**3. 前后端契约以 serde camelCase 为准**

`crates/qqhu-core/src/model.rs` 与 `src/lib/types.ts` 必须同步修改。
后续引入 `ts-rs` 自动生成，消除手工漂移。

**4. AI Agent 为常驻右栏，不是导航页**

右侧栏保留在任意模块之上，并把当前模块名作为上下文传入（`contextLabel`），
接入模型时随请求一并送入。IPC 通道已打通，`ai_chat` 目前返回明确的未实现错误。

**5. 探针不依赖外部可执行文件**

ICMP 走原生 socket、TCP 探测直接建连、DNS 用 `hickory-resolver`，
三平台统一实现，不再需要 `tcping.exe` 与系统 `ping` 的文本解析。

## 待办

- [ ] M0 技术 spike：Windows 上原生 ICMP 免管理员验证 + 三平台 ARP 表获取
- [ ] CI 三平台矩阵（windows / macos / ubuntu 跑 `cargo check` + `cargo test`）
- [ ] `AppPaths`：跨平台可写目录解析（mac/Linux 不能写 app 包内部）
- [ ] `qqhu-cli`：报告对拍与批量诊断入口

## 许可证

MIT，见 [LICENSE](LICENSE)。
