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
| IP 扫描（并发探活 / TCP 兜底 / CSV 导出） | 已完成 |
| MAC 扫描（ARP 邻居表 / OUI 厂商 / CSV 导出） | 已完成 |
| SSL 证书检查（信任链 / 有效期 / SAN / 指纹） | 已完成 |
| 路径追踪（Traceroute）与路径 MTU 探测 | 已完成 |
| 私有 CA 与证书签发（PEM / PFX 导出） | 已完成 |
| ACME 证书（Let's Encrypt DNS-01，阿里云 / 腾讯云） | 已完成 |
| 关于 / 许可 | 已完成 |
| 带宽测试 | 待定（需对端配合，暂不纳入） |
| 右侧 AI Agent 接入真实模型 | 排期 M4 后续 |

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
│   ├── qqhu-core/          # 领域模型 / 子网计算 / 质量评分 / 扫描范围解析（零平台依赖）
│   ├── qqhu-sys/           # 平台抽象层：HostPlatform trait + 能力矩阵 + ARP 采集
│   ├── qqhu-probe/         # 原生探针：ICMP / TCP / DNS / IP 扫描 / 诊断编排
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

每个模块同时返回 `icon` 语义名（`wave` / `split` / `radar` / `chip` / `shield` / `info` / `doc`），
前端 `src/components/icons.tsx` 按名查表渲染 SVG。新增模块只需后端加一行，图标位不会空白；
未登记的名称回退默认图标，并有单测拦截空图标名。

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

**6. IP 扫描共享一个 ICMP Client，并提供 TCP 兜底**

`surge-ping` 的回包按 `(host, ident, seq)` 路由，因此多个 Pinger 可以共用同一 socket。
逐个地址新建 Client 会为每个 IP 创建一次 raw socket，扫 /24 就是 254 次创建。

另外不少企业网络出口禁 ICMP，"ping 不通" 不等于 "主机不在"。
扫描可配 TCP 兜底端口：ICMP 无响应的地址会再试一次建连，命中即判存活并标注判定方式。
这是 `probe_method` 字段存在的原因——结论要能说清是"怎么判出来的"。

**7. MAC 扫描以 ARP 表为准，不做主动 ARP 扫描**

主动发 ARP 请求需要 raw socket 或 `CAP_NET_RAW`，也就是要管理员权限，
这与"装完就能用"的定位冲突。替代方案是同网段 ICMP 探活：
ICMP 走二层，内核必须先解析 MAC 才能发包，探活完成后邻居表自然是满的。

因此结果以邻居表为准，探活只用来给条目补在线状态。跨网段探活不会增加邻居表
（不经过 ARP），界面会明确提示这一点，避免把"在线条目 0"误读成扫描失败。

**8. 厂商库宁可留空也不猜**

内置 OUI 表很短（22 条），只收录确信无疑的前缀。错误的厂商归属会让排障走错方向，
比显示"未知"有害得多。未命中时展示 6 位前缀原值便于自行核实；
需要全量数据时把 IEEE 的 `oui.csv` 放进 `config/` 即可，下次扫描生效。

## 待办

- [ ] M0 技术 spike：Windows 上原生 ICMP 免管理员验证 + 三平台 ARP 表获取
- [ ] CI 三平台矩阵（windows / macos / ubuntu 跑 `cargo check` + `cargo test`）
- [ ] `AppPaths`：跨平台可写目录解析（mac/Linux 不能写 app 包内部）
- [ ] `qqhu-cli`：报告对拍与批量诊断入口

## 许可证

MIT，见 [LICENSE](LICENSE)。
