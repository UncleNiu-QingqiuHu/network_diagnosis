# Skills 目录

将自定义 **Skill** 放在此目录，AI 助手启动对话时会自动扫描并注入系统约束。

## 推荐结构

```
skills/
  my-network-report/
    SKILL.md          # 必需：含 YAML 头与说明正文
  quick-subnet.md     # 也可：根目录下单文件 skill
```

## SKILL.md 示例

```markdown
---
name: network-report-style
description: 用户要求「按运维报告格式」解读网络诊断结果时使用
---

# 网络诊断报告格式

1. 先写一行结论（正常 / 需关注 / 严重）。
2. 分节：DNS、Ping、端口、质量评分。
3. 每条建议须可执行，避免空泛表述。
```

## 说明

- `name`、`description` 供模型判断何时触发该 skill。
- 正文为模型必须遵守的详细规则。
- 修改文件后**下一条消息**即会重新扫描（无需重启程序）。
