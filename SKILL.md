---
name: openclaw360
description: Runtime security skill for AI agents — prompt injection detection, tool call authorization, sensitive data leak prevention, and skill security scanning
version: 0.1.3
homepage: https://github.com/milu-ai/openclaw360
metadata:
  clawdbot:
    emoji: "🛡️"
    disable-model-invocation: true
    always: false
    source: https://github.com/milu-ai/openclaw360
    install:
      - name: "pip install (pinned commit)"
        command: "pip3 install git+https://github.com/milu-ai/openclaw360.git@3f9258e"
      - name: "pip install (venv, for Homebrew Python)"
        command: "python3 -m venv ~/.openclaw360-venv && ~/.openclaw360-venv/bin/pip install git+https://github.com/milu-ai/openclaw360.git@3f9258e"
    requires:
      bins: ["python3"]
      env: []
      config:
        - "~/.openclaw360/config.json"
        - "~/.openclaw360/identity/"
        - "~/.openclaw360/audit/"
---

# OpenClaw360 — AI Agent 运行时安全防护

OpenClaw360 是一个纯本地、只读分析型安全工具，为 AI Agent 提供四层安全防护：提示词注入检测、工具调用授权、敏感数据泄露拦截、第三方 Skill 安全扫描。

本工具不执行任何 Shell 命令，不修改任何文件，不发起任何网络请求。所有操作均为只读文本分析。

源代码完全开源（MIT）：https://github.com/milu-ai/openclaw360

## Permissions

- 需要 `python3`（3.10+）
- 不需要 sudo 权限
- 不访问系统敏感目录（/etc、/usr、/var 等）
- 不执行任何 Shell 命令或子进程
- 不修改、删除、覆盖任何用户文件或系统文件
- 所有操作均为只读文本分析，不产生副作用
- 本地数据目录（需用户手动初始化确认）：
  - `~/.openclaw360/config.json` — 配置文件（JSON，用户可编辑）
  - `~/.openclaw360/identity/` — 审计签名密钥（Ed25519，权限 0600，仅本地使用）
  - `~/.openclaw360/audit/` — 审计日志（JSONL，追加写入，不含原始敏感数据）

## Data Handling

- 所有数据仅存储在本地，不会发送到任何外部服务器
- 审计日志中敏感数据仅保留 SHA-256 哈希（零知识日志），不存储原始值
- 身份密钥仅用于本地审计日志签名，不用于网络认证
- 不收集、不上传、不共享任何用户数据或遥测信息

## Network Access

- **运行时完全离线**：所有命令（check-prompt、check-tool、check-output、scan-skills、protect、audit、report）在本地执行，零网络请求
- **安装时**：通过 metadata.install 中定义的标准 pip 命令从 GitHub 下载源代码，使用 pinned commit hash 确保完整性。此操作由用户在终端手动执行，Skill 不会自动触发安装
- **无后台网络活动**：不包含任何定时任务、后台进程、心跳检测或自动更新机制
- 可验证：源代码中不包含 requests、urllib、http.client、socket 等网络库调用

## Security & Integrity

- **纯只读分析**：所有安全检测均为文本模式匹配和规则评估，不执行被检测内容中的任何代码
- **代码来源可验证**：安装使用 pinned commit hash（非 tag），确保代码与审核时一致
- **源代码完全开源**：MIT 许可证，可在安装前完整审查
- **无自主调用**：`disable-model-invocation: true` + `always: false` — 必须由用户明确请求
- **无数据外泄路径**：不包含任何向外部发送数据的代码路径
- **零知识日志**：敏感数据仅保留哈希，不存储原始值

## Instructions

你是一个安全防护助手。使用 openclaw360 命令行工具帮助用户完成安全分析任务。所有操作均为只读分析，不会修改用户文件或执行危险操作。

### 安装检测

安装前必须告知用户：将从 GitHub 下载开源代码，并在 ~/.openclaw360/ 创建本地配置目录。获得用户确认后，按 metadata.install 中定义的命令安装。

检查是否已安装：运行 `openclaw360 --help`，如失败尝试 `~/.openclaw360-venv/bin/openclaw360 --help`。

如遇 externally-managed-environment 错误，使用 metadata.install 中的 venv 方案。

### 使用命令

所有命令均为只读分析操作，不修改任何文件：

- `openclaw360 init` — 初始化配置和签名密钥（需用户确认）
- `openclaw360 protect` — 交互式安全防护
- `openclaw360 check-prompt "文本"` — 分析提示词是否包含注入攻击
- `openclaw360 check-tool 工具名 [参数=值...]` — 评估工具调用风险等级
- `openclaw360 check-output "文本"` — 检测输出中的敏感数据
- `openclaw360 scan-skills [路径]` — 静态分析 Skill 文件的安全风险
- `openclaw360 audit --agent-id <id>` — 查询审计日志
- `openclaw360 report --agent-id <id>` — 生成审计报告


### Skill 安全扫描

扫描必须一次完成、一次回复。只执行一次 scan-skills 命令，等待完成后一次性回复。严禁逐个分多次回复。

扫描命令示例：
- 中文用户：`openclaw360 scan-skills --format json --lang zh`
- 英文用户：`openclaw360 scan-skills --format json`
- 指定路径：`openclaw360 scan-skills /path/to/skills/ --format json --lang zh`

默认扫描路径：`~/.openclaw/skills/` 和 `./skills/`。系统 Skill 目录：`/opt/homebrew/lib/node_modules/openclaw/skills/`。

## 功能

### 提示词注入检测
双引擎架构（规则引擎 + 可选 LLM 语义分类器），通过文本模式匹配检测 20 种攻击模式。支持来源权重加权（user/web/document/screen）和规则热更新（Ed25519 签名验证）。纯文本分析，不执行被检测内容。

### 工具调用授权
三维风险评分（action×0.4 + data×0.35 + context×0.25）+ AI-RBAC 双重防护。通过文本匹配评估工具名称和参数的风险等级，输出 ALLOW/CONFIRM/BLOCK 决策。纯评估逻辑，不执行被评估的工具。

### DLP 数据防泄露
检测 13 类敏感数据（含 PIPL 个人信息），通过正则匹配识别并自动脱敏，零知识日志记录。

### Skill 安全扫描
6 个静态分析检查器，对 Skill 文件进行只读文本扫描，检测潜在安全风险（凭证泄露、权限缺失、文档完整性等）。不执行被扫描 Skill 的任何代码。

### 审计日志
Ed25519 签名的 JSONL 格式审计记录，支持按 agent_id / action / decision / 时间范围查询。

### 500ms 超时保护
安全检查超时自动放行，不阻塞 agent 运行。

## Rules

- 安装前必须告知用户并获得确认
- 初始化前必须告知用户将创建签名密钥
- Python 版本低于 3.10 时提示升级
- 优先直接 pip install，失败再用 venv
- 记住确定的命令路径，后续统一使用
- 扫描结果中凭据已自动脱敏
- 必须使用 openclaw360 命令，不要自己写脚本模拟
- 规则更新必须由用户手动触发

### 扫描报告规则

**语言规则：** 中文用户加 `--lang zh`，英文用户用默认。回复语言与用户一致。

**命令执行规则：** 使用 `--format json` 获取结构化数据。只执行一次，等完成后一次性回复。

**报告展示规则（两阶段）：**

第一阶段默认展示概览报告，包含：扫描概览（Skill 数量、综合评分、时间）、评分分布、需关注的 Skill（按风险从高到低，含威胁说明和发现表格）、严重级别统计、风险类别分布、修复建议。

概览报告关键规则：
1. 每个有问题的 Skill 包含「对你的威胁」说明
2. 同类发现合并为一行，用数量列标注
3. 评分相同的 Skill 合并为一组
4. 分数条格式：`[████████░░] 83`
5. 严重级别 emoji：🔴 Critical、🟠 High、🟡 Medium、🔵 Low、⚪ Info
6. 末尾提示可输入「详细报告」查看完整结果
7. 按分数从低到高排序
8. 区分 SKILL.md 文档示例数据与真实凭证：文档中的示例邮箱/手机号标注为「📝 文档示例数据」，说明对使用者无直接威胁；脚本/配置中的真实凭证才标注为安全风险
9. 如存在大量文档示例数据误报，在修复建议前添加「ℹ️ 关于文档示例数据」说明

第二阶段：用户输入「详细报告」「详细」「detail」时，展示逐 Skill 详细结果（检查清单 ✅/❌、发现表格含文件位置和修复建议）。
