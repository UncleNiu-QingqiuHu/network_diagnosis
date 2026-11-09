# 变更日志

> **版本分线说明**
> 从 4.0.0 起，本项目改用 Rust + Tauri 重写。下方 `3.x` 记录属于 Python + tkinter 实现，
> 该实现已归档到 `legacy/python-v3` 分支，仅保留查阅。

## [4.0.0-alpha.14] — 2026-11-09

### 新增
- **对话历史落盘与多会话**：关掉窗口再打开，之前的对话还在。
  - 新模块 `qqhu_agent::session`：一个会话一个 JSON 文件，**不维护全局索引** ——
    索引文件一旦与目录不同步，用户就会看到「列表里有、点开是空的」，比慢一点糟得多。
  - 会话 id 由「时间戳-随机短串」组成，天然按时间排序，也挡住路径穿越（只允许字母数字与 `-`）。
  - **标题从首条用户消息推导**（首行 + 压缩空白 + 24 字截断），不调模型：
    标题多一次请求、多一份等待，模型挂掉时连会话都没名字。
  - 落盘只存对话可见内容（用户消息、助手回复、工具标签的 name/status/preview），
    不存完整工具输出 —— 那东西动辄几十 KB，而用户切回来看的其实是「当时调了什么、成没成」。
  - 写入用「先写 .tmp 再 rename」；单个文件损坏只跳过该文件，不影响整张列表。
  - 上限：单会话 400 条消息、单条 20000 字符、最多保留 100 个会话，超出自动裁最旧。
  - 界面：对话页顶部会话条（标题 / 重命名 / 新建），下拉列最近会话（时间 + 条数 + 摘要），
    当前项用左侧竖条高亮，条目内可直接删除。
- 命令：`agent_sessions` / `agent_session_get` / `agent_session_new` / `agent_session_save` /
  `agent_session_rename` / `agent_session_delete` / `agent_session_append`。

### 修复
- **快速连点「发送」会发两轮**：`busy` 是异步 state，两次点击都能通过检查。
  改用 `sendingRef` 同步守卫，并在所有提前返回的分支复位。
- **反复点「新建」堆出一排「新对话」**：已有空会话时直接复用，并顺带删掉历史遗留的多余空会话。
- 当前会话在列表里只靠底色区分，实际屏幕上几乎看不出差别，改为左侧竖条 + 更实的底色。

### 说明
- 会话文件存放在 `<安装目录>/agent/sessions/`，与 `pki/` 一样已加入 `.gitignore`。
- 历史里保留的是可见文本；一次对话中间的工具往返过程不会回放。

## [4.0.0-alpha.13] — 2026-11-05

### 新增
- **AI Agent（右侧常驻面板）**：可配置主流模型的 OpenAI 兼容接口，边聊边调本机诊断能力。
  - 新 crate `qqhu-agent`：`config`（模型配置）/ `secrets`（Key 保管）/ `skills`（技能）/
    `prompt`（角色与边界）/ `chat`（流式与工具调用）/ `tools`（工具定义与命令白名单）。
  - 新 crate `qqhu-secret`：凭据保管统一收口，ACME 与 Agent 共用一套 keyring 逻辑。
  - **模型接入**：任意 OpenAI 兼容服务（DeepSeek / 通义 / Kimi / 智谱 / OpenAI / 本地 Ollama），
    填 BaseURL + 模型 ID 即可；内置常用服务商快捷填充。API Key 存系统凭据管理器，
    配置文件里不出现明文。
  - **流式对话**：SSE 逐字输出，支持中途「停止」；一轮最多 6 次工具往返。
  - **工具调用**：内置 `subnet_calc` / `ping_host` / `trace_route` / `check_ssl`；
    开启命令执行后额外提供 `run_command`。
  - **技能**：扫描本机 Claude Code / WorkBuddy / Codex / Cursor / Qoder 的技能目录，
    列出候选并可导入（**只读扫描，导入是复制**，不改对方文件）；支持启停与删除。
    技能正文按预算注入系统提示词，超出截断。
  - **角色与边界**：系统提示词固定角色（网络运维助手）与拒绝规则（渗透 / 攻击 /
    越权 / 无关话题），并附事实纪律（实测 / 推断 / 建议分开）与命令纪律；
    与技能内容冲突时以边界为准。
- 命令 `agent_*`（配置、Key、技能、对话、取消、确认），事件 `agent-delta` /
  `agent-tool` / `agent-confirm`。

### 安全设计
- 命令执行**默认关闭**；开启后每条命令仍需用户点「允许执行」确认，120 秒未确认视为拒绝。
- 命令走**白名单 + 参数校验**：只允许 ping / tracert / nslookup / arp / ipconfig /
  route print / netstat，拒绝管道、重定向、分号等字符；`route add`、`netstat -s`、
  `ipconfig /release`、`ping -t` 这类会被单独拦下。
- 直接 spawn 进程、不经 shell；Windows 下不弹控制台窗口，命令超时 20 秒。

### 修复
- 命令确认期间无法中断：原先只等 120 秒超时，用户点「停止」或刷新页面后对话会一直占着
  后端。现在确认等待同时监听取消信号（300ms 轮询），前端挂载时也会清理上一次残留请求。
- 技能描述解析：真实技能常用 YAML 块标量（`description: |` 加缩进多行），
  原先只取冒号右边，结果描述变成字面量 `|`。现已支持 `|` / `>` / `|-` / `>-` 四种写法。
- 面板复选框里的补充说明与主文案挤成一句，补充了块级样式。

### 说明
- 仅支持 OpenAI 兼容协议（含流式与工具调用）；Anthropic / Gemini 原生协议未接入。
- 技能扫描只覆盖有明确目录约定的 Agent（Claude Code / WorkBuddy / Codex / Cursor / Qoder），
  不做全盘搜索，避免把无关 Markdown 当技能。
- 对话历史只存在界面内存，刷新即清空；没有做会话落盘。

## [4.0.0-alpha.12] — 2026-11-05

### 新增
- **证书自动续期（M4 收尾）**：到期前 30 天自动重签，不用再记着手动点。
  - 后台调度：应用启动即检查一轮，之后每 6 小时一轮；同一时刻只允许一个续期任务，
    多张证书串行处理（并发会在同一域名下互相干扰，也会打满 CA 频率额度）。
  - 判定规则独立成纯函数 `qqhu_acme::renewal::is_due`（自动续期开关 + 进入 30 天窗口
    + 已过 12 小时退避），可直接单测，不必等真实时间流逝。
  - 失败后写回 `lastError` / `lastAttemptAt` 并进入 12 小时退避，界面显示「上次失败：…」。
  - **续期沿用原证书 id**，覆盖写入同一目录 —— Nginx 里写的 `pki/acme/certs/<id>/chain.pem`
    路径不需要改。
- **DNS 凭据保管**：自动续期必须能无人值守写 DNS，因此凭据改存
  **系统凭据管理器**（Windows Credential Manager / macOS Keychain，经 `keyring`），
  不再落在明文文件里；仅无凭据管理器的平台退回 0600 文件，并在界面标明当前后端。
  关闭自动续期时会一并删除已保存的凭据。
- 命令 `acme_set_auto_renew` / `acme_renewal_status` / `acme_check_renewals` /
  `acme_renew_now`，进度事件 `acme-renew`。
- 界面：新增「自动续期」状态卡（上次/下次检查、待续期数量、凭据后端、续期日志、
  立即检查）；申请表单增加「启用自动续期」开关；证书表格增加自动续期开关、
  已续期次数与失败原因，并支持「立即续期」。

### 修复
- 证书表格在长失败信息下被挤成竖排单字：覆盖域名与错误信息改为单行截断 + 悬停显示全文，
  表格列合并为「域名 / 到期 / 自动续期 / 操作」四列。

### 说明
- 自动续期依赖程序运行：窗口关闭后不会续期，下次启动会立即补一次检查。
  没有注册系统计划任务（会带来提权与卸载残留问题），这是明确的取舍。
- macOS 上 `keyring` 走 Keychain，未在真机验证（仅保证编译）。

## [4.0.0-alpha.11] — 2026-11-05

### 新增
- **ACME 证书签发（M4 第二块，DNS-01）**：不占公网 80/443，内网机器也能签公网证书，
  且支持泛域名。
  - 新 crate `qqhu-acme`：`model` 校验 / `dns` 服务商适配 / `propagate` 传播确认 /
    `store` 落盘 / `issue` 流程编排。
  - **阿里云 DNS**：RPC 风格 API，HMAC-SHA1 签名。签名实现用官方文档样例做回归
    （`OLeaidS1JvxuMvnyHOwuJ+uX5qY=`），把排序、编码、密钥拼接、Base64 四个环节一起锁住。
  - **腾讯云 DNSPod**：API 3.0，TC3-HMAC-SHA256 逐级派生密钥签名。签名值对照
    Python 独立实现的结果做断言，避免「自己算自己验」。
  - 区域自动识别：拉取账号下全部域名，取**最长匹配后缀**。同时托管 `example.com`
    与 `a.example.com` 时，记录不会误写到父域。
  - 先写完全部 TXT 再统一等待，多域名不会把等待时间乘以域名数；
    用 DoH（阿里 / Cloudflare 双源）确认记录生效后再交给 CA 校验。
  - 无论成功失败都会清理写入的 TXT 记录，不在域名下留垃圾。
  - 账户凭据按 ACME 目录地址分文件存放，正式与测试环境互不干扰；
    签发结果含 `cert.pem` / `chain.pem`（Nginx 直用）/ `key.pem`（PKCS#8）/ `cert.pfx`。
  - 界面新增「ACME 证书」模块：服务商切换、AccessKey 输入（仅本次使用，不落盘）、
    测试环境开关、DNS 等待可调、**逐阶段进度实时推送**、证书列表、内容复制与 PFX 导出。
- 命令：`acme_overview` / `acme_issue` / `acme_delete_cert` / `acme_cert_text` /
  `acme_export_pfx` / `acme_dir_of`，进度事件 `acme-progress`。
- 手动联调入口：`live_provider_smoke`（`QQHU_ACME_PROVIDER` / `QQHU_ACME_AK` /
  `QQHU_ACME_SK`），可直接验证某套 AccessKey 能否列出域名。

### 修复
- 磁盘写满导致编译中断：清理 `target/debug/incremental`（11 GB）后恢复，
  后续构建建议加 `CARGO_INCREMENTAL=0`。

### 说明
- AccessKey 只用于写入 TXT 记录，不保存；**账户密钥**（含账户私钥）保存在
  `pki/acme/accounts/`，属于必须保护的凭据。
- 证书**续期**需手动重新申请：Let's Encrypt 证书 90 天有效，界面按剩余天数着色提醒。
- 未做 HTTP-01 与 TLS-ALPN-01；EAB（ZeroSSL 等）也未支持。

## [4.0.0-alpha.10] — 2026-11-05

### 新增
- **私有 CA 与证书签发（M4 第一块）**：内网 HTTPS / 设备证书不再需要装 OpenSSL 敲命令行。
  - 新 crate `qqhu-pki`，三层职责：`model`（输入校验，纯逻辑）、`issue`（rcgen 生成，
    不碰文件）、`store`（目录布局与元信息）。
  - 根 CA：自签名、`KeyCertSign` + `CrlSign`，默认 3650 天，可填 O / OU / C / ST / L。
  - 站点证书：SAN 同时支持 DNS 名、通配符（只允许最左一级）与 IP，用途可选
    服务器 / 客户端 / 两者（对应 Extended Key Usage）。
  - **子证书有效期自动受 CA 剩余有效期截断**，避免出现「每张证书都没过期、链却验不过」。
  - `chain.pem` 按「服务器证书 → CA」顺序拼接，可直接用于 Nginx `ssl_certificate`。
  - PKCS#12（`.pfx`）导出：口令保护，打包时一并写入 CA 证书，Windows 双击即可导入。
    使用 PKCS#12 传统的 RC2-40 加密（Windows / IIS 全版本兼容；OpenSSL 3 默认禁用该算法，
    需要 `-provider legacy` 才能读取，界面已注明）。
  - 界面新增「证书签发」模块：CA 列表与创建、签发证书、证书内容查看与复制、
    PFX 导出、目录定位、删除保护（CA 下仍有证书时拒绝删除）。
- 命令：`pki_overview` / `pki_create_ca` / `pki_delete_ca` / `pki_issue` /
  `pki_delete_cert` / `pki_export_pfx` / `pki_cert_text` / `pki_dir_of`。

### 说明
- 按选择，私钥以**明文 PEM** 保存在 `<安装目录>/pki/`，界面顶部固定提示该路径与风险。
- 目前仅支持 ECDSA P-256 与 Ed25519：rcgen 的 ring 后端无法生成 RSA 密钥，
  启用 RSA 需引入 aws-lc-rs（额外依赖 cmake / nasm），待确有需要再加。
- ACME（Let's Encrypt DNS-01）不在本批次，留作 M4 下一块。

## [4.0.0-alpha.9] — 2026-11-05

### 新增
- **路径追踪（M2.1 第一块）**：定位「在哪一跳开始不通」。
  - `qqhu-probe::icmp`：自建原始 ICMP socket（`SOCK_RAW + IPPROTO_ICMP`），
    手写 Echo 报文与校验和、跳过 IP 首部解析 Echo Reply / Time Exceeded /
    Fragmentation Needed，并从差错报文的内层包取出目的地址与序号做匹配。
    Windows 普通用户即可创建 raw ICMP socket；Linux/macOS 需 root 或 `CAP_NET_RAW`。
  - `qqhu-probe::traceroute`：逐跳递增 TTL，每跳重建 socket（TTL 是 socket 级选项）；
    连续 5 跳无响应提前收尾，避免对屏蔽 ICMP 的目标死等。
  - 界面：逐跳实时推送（事件 `trace-progress`）、跳数 / RTT / 备注表格、
    到达提示、重复地址告警（ECMP 或路由环路）。
- **路径 MTU 探测（M2.1 第二块）**：排查「网页能开、大文件卡住」的分片黑洞。
  - 发带 DF 标志的 ICMP Echo 并二分查找最大可通尺寸，十几轮收敛到 1 字节。
  - 先打基线 1500：本机网卡拒绝更大包时（`EMSGSIZE`）直接判定 1500，
    不再对 1500–9000 做十几次无意义二分（实测探测次数 14 → 2）。
  - 区分「本地接口 MTU 封顶」与「路径上路由器回 ICMP 3/4」，并读取路由器回报的下一跳 MTU。
  - 界面：以本机网关为默认目标，结论横幅 + 每次探测明细（MTU / 载荷 / 结果 / RTT / 下一跳 MTU）。
- 新命令 `trace_route`、`probe_mtu`；侧栏新增「路径追踪」模块（图标 `route`）。

### 修复
- **ICMP 应答误判**：只比对 ident/seq 时，raw socket 收到的其他 ICMP Echo Reply
  会被当作「已到达目标」（实测跟踪公网时第 2 跳错报网关即目标）。
  现在 Echo Reply 必须来自目标地址，差错报文的内层包目的地址也必须匹配。
- MTU 目标不响应 ICMP 时错误文案曾误用「目标地址无效」，改为直接说明探测失败的
  原因与替代建议（新增 `ProbeError::ProbeFailed`）。

## [4.0.0-alpha.8] — 2026-11-05

### 新增
- **SSL 证书检查模块**（M4 第一块）：排查站点证书问题不再依赖浏览器或 `openssl s_client`。
  - `qqhu-core::sslcert`：证书模型、有效期分级（有效 / 30 天内过期 / 已过期 / 尚未生效）、
    RFC 6125 主机名匹配（含通配符只跨一级、SAN 优先于 CN、IP SAN）、
    自签名识别、告警汇总（弱密钥、SHA-1 签名、链上中间证书过期、TLS 1.0/1.1）。
  - `qqhu-probe::sslcert`：`rustls` + `x509-parser` 原生握手与解析，无外部命令。
    先按信任链握手一次判断「是否被本机信任」，失败后换「接受任意证书」的只读连接再取一次证书，
    因此**自签、过期、域名不符的证书同样能看到完整信息**。
  - 信任判定同时加载**系统根证书**与 **Mozilla 根证书**并取并集：主流浏览器用自带根存储，
    只认系统根会把浏览器能正常访问的站点误判为不受信任。
  - 界面：检查表单（支持 `域名`、`域名:端口`、`https://…` 等写法）、结论横幅、
    证书详情（主体 / 签发者 / 有效期 / 剩余天数 / 签名与公钥算法 / SAN / SHA-256 指纹）、
    可展开的证书链表格。

### 变更
- 「SSL 证书」从占位页转为可用模块，导航描述改为「证书链检查、有效期与信任校验」。
- 证书签发（ACME DNS-01 / 私有 CA / PFX）留在 M4 后续批次。

## [4.0.0-alpha.7] — 2026-11-05

### 新增
- **本机网段自动识别**：IP 扫描与 MAC 扫描不再写死 `192.168.1.0/24`。
  - `qqhu-sys::netif`：原生接口枚举 —— Windows `GetAdaptersAddresses`、
    Linux/macOS `getifaddrs`；默认网关 —— Windows `GetIpForwardTable2`、
    Linux `/proc/net/route`、macOS `sysctl(NET_RT_DUMP)`。全程不解析本地化命令行输出。
  - `suggest_scope` 纯函数：优先取默认路由出口所在接口，跳过环回与 `169.254/16`
    链路本地地址；前缀过窄（>30，点对点）或过宽（<8）时收敛到 /24，避免扫出无意义目标。
  - 新命令 `local_network`：返回接口列表、默认网关与建议网段。
  - 界面：两个扫描模块首次进入自动填入本机网段，上次用过的范围仍优先生效。

### 变更
- `HostPlatform` 新增 `interfaces()` 与 `suggested_scope()`，默认实现走 `netif`，
  三个平台实现不再各自返回 `None` 的死代码。

## [4.0.0-alpha.6] — 2026-11-03

### 新增
- **MAC 扫描模块**（M3 第二块）：本机 ARP 邻居表 + OUI 厂商识别。
  - `qqhu-core::macscan`：ARP 条目模型、MAC 归一化（冒号/短横线/点分/纯十六进制四种写法）、
    OUI 厂商库、本地管理地址（手机随机化 MAC）识别、非主机条目过滤。
  - `qqhu-sys::arp`：三平台采集 —— Windows `GetIpNetTable2`、Linux `/proc/net/arp`、
    macOS `sysctl(NET_RT_FLAGS)`；出口统一过滤广播与全零 MAC。
  - `qqhu-probe::macscan`：可选「先探活再读表」。同网段 ICMP 必经 ARP 解析，
    因此探活能顺带填充邻居表，且全程不需要管理员权限。
    **以 ARP 表为准，探测结果只用于标注在线状态**——没有 MAC 的地址对这一屏没有意义。
  - 界面：探测开关、统计、按 IP/MAC/厂商/接口搜索、仅显示在线、CSV 导出、进度与取消。
- `config/oui.csv` 扩展机制：放入 IEEE 官方 OUI 列表即可补齐全量厂商数据，
  下次扫描生效，无需重启。

### 变更
- 扫描取消入口统一为 `cancelScan`：IP 扫描与 MAC 扫描共用后端同一个取消开关，
  按模块命名会误导。
- 统计卡片在窄容器下改用更紧凑列宽，避免 4 格退化成 2+1 后留出大片空白。

### 修复
- 广播地址 `ff:ff:ff:ff:ff:ff` 因第一字节命中本地管理位而被误标为「随机地址」。
- 子网定向广播（如 /27 的 `.63`）曾混进 ARP 列表，现于采集出口统一过滤。

### 测试
- 新增 16 项：MAC 归一化与 OUI 库 9 项、`/proc/net/arp` 解析 3 项、
  MAC 扫描编排 3 项（只读模式不给在线状态、厂商不猜、探测计数）、
  MAC CSV 格式 1 项。总计 87 项。

### 已知限制
- macOS 的 `sysctl` 路由表解析**未在真机验证**（开发环境为 Windows），仅保证可编译。
  首次在 mac 上使用时需要确认采集结果正确。
- 内置 OUI 库只收录确信的前缀（22 条），未命中显示 6 位前缀原值。
  宁可留空也不给错误归属；需要全量数据请放 `config/oui.csv`。

## [4.0.0-alpha.5] — 2026-11-03

### 新增
- **IP 扫描模块**（M3 第一块）：网段 / 区间 / 单 IP 三种输入，并发 ICMP 探活。
  - `qqhu-core::ipscan`：扫描范围解析（CIDR、闭区间、`192.168.1.10-50` 短写），
    正确排除网络与广播地址，`/31` `/32` 按现代语义处理，单次上限 4096 个地址。
  - `qqhu-probe::ipscan`：共享单个 ICMP Client + 滑动并发窗口，
    支持中途取消（`AtomicBool`）、进度节流回调、结果按地址升序。
  - **TCP 兜底**：ICMP 无响应的地址可再试指定端口，命中即判存活并记录端口；
    解决企业网络禁 ICMP 时「ping 不通 ≠ 主机不在线」的误判。
  - CSV 导出（UTF-8 BOM、`reports/ipscan/`），界面支持搜索过滤、仅显示存活、
    进度条与存活计数。
- 命令行示例 `ipscan_demo`，便于在无 GUI 环境验证与对拍。

### 变更
- 前端版本号改由 `vite define` 从 `package.json` 注入，消除浏览器预览模式下
  硬编码的 `4.0.0-dev` 这一冗余版本来源。

### 修复
- 浏览器预览模式的占位模块清单补齐「关于 / 许可」。

### 测试
- 新增 13 项扫描范围解析测试、6 项扫描引擎测试（含取消、进度顺序、TCP-only 模式）、
  1 项 CSV 导出格式测试。

## [4.0.0-alpha.4] — 2026-11-03

### 变更
- **侧栏改为扁平列表**：取消「核心 / 网络 / 工具 / 信息」分组标题，所有模块同级平铺，
  7 个入口一屏可见，减少纵向空间与视觉层级。
- **每个菜单项配图标**：新增 `src/components/icons.tsx` 图标注册表，采用统一线条风格
  （1.6px 描边、`currentColor` 跟随主题）。后端 `ModuleInfo` 的 `group` 字段替换为
  `icon` 语义名（`wave` / `split` / `radar` / `chip` / `shield` / `info` / `doc`），
  前端按名查表渲染，未登记名称回退默认圆点。
- 选中项增加左侧竖条指示，低对比环境下不必仅靠背景色辨识。
- 浏览器预览模式的占位模块清单补齐「关于 / 许可」，与真实后端保持一致。

### 测试
- 新增 `every_module_has_icon`：防止新增模块时漏写图标名导致侧栏空白位。

## [4.0.0-alpha.3] — 2026-11-03

### 新增
- **诊断报告归档**：每次诊断在 `reports/diagnosis/<task_id>/report.md` 生成完整
  Markdown 技术报告，含任务信息、结论建议、输入参数、解析、ICMP 逐包结果、端口表、
  质量评判、降级事件。
- **历史索引与对比**：`reports/diagnosis/_history.json` 记录同目标历次结果（上限 500 条，
  原子写入，损坏时降级为空不阻断诊断），自动生成「上次 vs 本次」档位、丢包、时延、抖动变化。
- **qqhu-report crate**：`persist()` 统一报告落盘与历史登记，Tauri 命令与 CLI 共用同一路径。
- 界面新增对比卡片与「打开所在目录」，可一键定位报告文件。

### 变更
- `run_diagnosis` 返回结构由 `DiagnosticReport` 改为 `DiagnosisOutcome`
  （含 report / reportPath / compare）。

### 验证
- 单元测试 50 项通过；端到端连跑两次，第二次正确输出对比结论

---

## [4.0.0-alpha.2] — 2026-11-03

### 新增
- **网络诊断**（首个核心探测模块）：
  - 原生 ICMP 探测，输出丢包率、最小/最大/平均 RTT 与逐包序列，**不依赖系统 `ping`**
  - 原生 TCP 端口探测（并发 + 多样本），**不依赖 `tcping.exe`**，可区分拒绝/超时/不可达
  - DNS 解析与耗时统计
  - 链路质量综合评判（极佳/正常/较差/堵塞）与结论摘要、处置建议
  - 界面实时进度推送（`diag-progress` 事件）与 RTT 序列图
- `qqhu-probe` crate：探针层（icmp / tcp / dns / 诊断编排）

### 修复
- 结论判定逻辑：ICMP 可达但端口全不通时，判为「主机可达，端口未响应」（降级），
  不再误判为「链路中断」

### 验证
- M0 spike 结论：Windows 非管理员进程可创建原生 ICMP socket 并完成远端探测
  （实测网关与内网 DNS 服务器 3/3 通）
- 单元测试 38 项通过

---

## [4.0.0-alpha.1] — 2026-11-03

### 新增
- **重写为 Rust + Tauri 2 架构**：`qqhu-core`（领域模型 / 子网计算 / 质量评分，零平台依赖）、
  `qqhu-sys`（平台抽象层 + 能力矩阵）、`qqhu-app`（Tauri IPC 层）。
- **三栏界面**：左侧导航 / 中间模块 / 右侧常驻 AI Agent 侧栏，导航清单由 Rust 按平台能力返回。
- **子网计算**：前缀与点分掩码双模式、12 项推导结果、等长子网划分。
- **关于 / 许可**：应用信息、作者联系方式、运行环境；MIT 全文编译期内嵌。
- **跨平台能力矩阵**：Windows / macOS / Linux 各一份实现，模块可用性由后端统一给出。

### 变更
- 仓库主线切换：`main` 现为 Rust 实现；Python 实现归档至 `legacy/python-v3`。
- 项目更名为「青丘湖网络工作台」。

### 已知限制
- 网络诊断、IP/MAC 扫描、SSL 证书、AI 接入尚未实现。
- 域与策略、数字签名、安全诊断仅计划在 Windows 构建中提供。

---

## [3.4.0] — 2026-05-26

### 新增
- **抓包分析**独立模块：实时抓包（自选网卡、BPF 过滤器、定时/大小限制）、pcap/pcapng 离线分析、Display Filter、报文预览、Markdown 报告（`reports/packet_capture/`）。
- 网络诊断结果区 **「在抓包分析中打开」**，可从诊断历史载入 pcap 深入分析。
- 帮助页新增 **抓包分析** 说明；设计文档 [`docs/packet-capture-design.md`](docs/packet-capture-design.md) 状态更新为 v1 已实现。

---

## [2.1.6] — 2026-05-15

### 新增
- **SSL 证书**模块（导航「SSL证书」）：**Let's Encrypt**（ACME DNS-01，阿里云 DNS / 腾讯云 DNSPod API）；**私有证书**（`cryptography` 根 CA + 站点证书，固定 10 年有效期，可选 PFX）；内置帮助与方案文档 [`docs/ssl_certificate_scheme.md`](docs/ssl_certificate_scheme.md)。
- 依赖：`acme`、`requests`（Let's Encrypt）；延续 `cryptography`（私有证书）。

### 文档
- **打包**：README 中 PyInstaller / Nuitka 长篇说明迁至 [`docs/packaging.md`](docs/packaging.md)，英文 [`docs/packaging.en.md`](docs/packaging.en.md)；README 仅保留摘要与链接。

---

## [2026-05-13] [文档] 设计方案 v1.5

- 新增 `docs/network-diagnostic-tool-design_v1.5.md`：主窗口多模块（子网计算、交换机、数据库诊断）、扩展依赖与 `reports/db_diagnosis/`、`switch_console/` 路径约定；`v1.4` 文档保留并标注归档。
- README、`pyproject.toml`、`network_diagnosis.version.DESIGN_DOC_REF` 引用已同步至 v1.5。

## [2026-05-13] [优化] GUI 左右分栏与运行态

- 主界面改为左右分割（`Panedwindow` 水平）：左侧为探测表单、工具按钮、任务状态与报告入口；右侧为「结论」与「进度与详情」，右侧纵向约 1:4 分配以加高日志区。
- 运行中：`任务状态` 区域高亮、加粗文案，并显示不确定进度条；结束或失败时恢复。

## [2026-05-13] [修复] GUI：Panedwindow 与 Python 3.14 / Tcl 9

- 移除 `paneconfigure` 调用（`ttk::panedwindow` 不再支持该子命令），避免启动即崩溃。

## [2026-05-13] [优化] GUI 布局

- 主界面采用垂直分割（`Panedwindow`）分隔「表单 + 结论」与「日志」；探测目标/选项分组、状态条与操作按钮区对齐优化；默认窗口与分割条比例调整。

## [2026-05-13] [文档] 项目 README

- 新增根目录 `README.md`（安装、运行、报告目录、第三方资源、仓库结构）；`pyproject.toml` 的 `readme` 改为指向该文件。

## [2026-05-13] [变更] 报告默认输出目录

- 诊断任务与 Markdown 默认写入**项目根目录**下 `reports/`（打包后为可执行文件同目录下 `reports/`），不再使用「文档」目录。

## [2026-05-13] [新增] 网络诊断桌面工具 MVP

- 依据 `docs/network-diagnostic-tool-design_v1.4.md` 实现 Python + tkinter + ttkbootstrap GUI。
- 同源诊断模型：DNS、可选 ICMP ping、多端口 tcping、可选 tshark 抓包；双输出 GUI 摘要 + Markdown 技术报告。
- 内置 `ThirdParty/tcping/` 相对路径解析；Wireshark 安装包引导与同捆目录探测。
