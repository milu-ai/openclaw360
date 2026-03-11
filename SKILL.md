---
name: openclaw360
description: Runtime security skill for AI agents — prompt injection detection, tool call authorization, sensitive data leak prevention, and skill security scanning
version: 0.1.5
disable-model-invocation: true
homepage: https://github.com/milu-ai/openclaw360
metadata:
  clawdbot:
    emoji: "🛡️"
    always: false
    source: https://github.com/milu-ai/openclaw360
    install:
      - name: "pip install (pinned commit)"
        command: "pip3 install git+https://github.com/milu-ai/openclaw360.git@5fd69db"
      - name: "pip install (venv, for Homebrew Python)"
        command: "python3 -m venv ~/.openclaw360-venv && ~/.openclaw360-venv/bin/pip install git+https://github.com/milu-ai/openclaw360.git@5fd69db"
    requires:
      bins: ["python3"]
      env: []
      config:
        - "~/.openclaw360/config.json"
        - "~/.openclaw360/identity/"
        - "~/.openclaw360/audit/"
---

# OpenClaw360 — AI Agent 运行时安全防护

OpenClaw360 为 AI Agent 提供四层安全防护：提示词注入检测、工具调用授权、敏感数据泄露拦截、第三方 Skill 安全扫描。

源代码完全开源（MIT）：https://github.com/milu-ai/openclaw360

## Permissions

- 需要 `python3`（3.10+）
- 不需要 sudo 权限

读取操作：
- 读取用户指定的文本输入（check-prompt、check-tool、check-output 命令的参数）
- 读取 Skill 目录中的 SKILL.md 和脚本文件（scan-skills 命令，用户指定路径）
- 读取 `~/.openclaw360/audit/` 中的审计日志（audit、report 命令）

写入操作（仅限 `~/.openclaw360/` 目录）：
- `openclaw360 init`：创建 `~/.openclaw360/config.json`（配置）和 `~/.openclaw360/identity/`（Ed25519 签名密钥，权限 0600）。需用户确认
- 安全检测命令：向 `~/.openclaw360/audit/` 追加 JSONL 格式审计日志。日志中敏感数据仅保留 SHA-256 哈希

不访问的资源：
- 不访问 /etc、/usr、/var 等系统目录
- 不读写用户的 ~/.ssh、~/.aws、~/.config 等敏感配置
- 不访问其他应用的数据目录

## Data Handling

- 所有数据存储在 `~/.openclaw360/` 目录内，不存储到其他位置
- 审计日志使用零知识模式：敏感数据仅保留 SHA-256 哈希，不存储原始值
- 身份密钥仅用于本地审计日志签名，不用于网络认证
- 不收集遥测信息，不上传任何数据

## Network Access

- 安装时：通过 metadata.install 中的 pip 命令从 GitHub 下载源代码（用户在终端手动执行，Skill 不自动触发）
- 安装后的所有命令（check-prompt、check-tool、check-output、scan-skills、protect、audit、report、init）均在本地执行，不发起网络请求
- 不包含定时任务、后台进程或自动更新机制
- 源代码中不使用 requests、urllib、http.client 等网络库

## Security & Integrity

- 安装使用 pinned commit hash（非 tag），确保代码与审核时一致
- 源代码完全开源，可在安装前审查
- `disable-model-invocation: true`（顶级 frontmatter 字段）+ `always: false`：Agent 不会自动运行此 Skill，仅在用户明确请求安全分析时由 Agent 调用对应命令
- 安全检测逻辑为文本模式匹配和规则评估，不执行被检测内容中的代码

## Instructions

你是一个安全防护助手。当用户请求安全分析时，使用 openclaw360 命令行工具完成任务。

### 安装检测

安装前告知用户：将从 GitHub 下载开源代码，并在 ~/.openclaw360/ 创建本地配置目录。获得确认后，按 metadata.install 中定义的命令安装。

检查是否已安装：运行 `openclaw360 --help`，如失败尝试 `~/.openclaw360-venv/bin/openclaw360 --help`。如遇 externally-managed-environment 错误，使用 metadata.install 中的 venv 方案。

### 使用命令

- `openclaw360 init` — 初始化配置和签名密钥（需用户确认）
- `openclaw360 protect` — 交互式安全防护
- `openclaw360 check-prompt "文本"` — 分析提示词是否包含注入攻击
- `openclaw360 check-tool 工具名 [参数=值...]` — 评估工具调用风险等级
- `openclaw360 check-output "文本"` — 检测输出中的敏感数据
- `openclaw360 scan-skills [路径]` — 静态分析 Skill 文件的安全风险
- `openclaw360 audit --agent-id <id>` — 查询审计日志
- `openclaw360 report --agent-id <id>` — 生成审计报告

### Skill 安全扫描

扫描必须一次完成、一次回复。只执行一次 scan-skills 命令，等待完成后一次性回复。

扫描命令：
- 中文用户：`openclaw360 scan-skills --format json --lang zh`
- 英文用户：`openclaw360 scan-skills --format json`
- 指定路径：`openclaw360 scan-skills /path/to/skills/ --format json --lang zh`

默认扫描路径：`~/.openclaw/skills/` 和 `./skills/`。系统 Skill 目录：`/opt/homebrew/lib/node_modules/openclaw/skills/`。

## 功能

### 提示词注入检测
规则引擎通过文本模式匹配检测 20 种攻击模式，可选 LLM 语义分类器。支持来源权重加权和规则热更新（Ed25519 签名验证）。

### 工具调用授权
三维风险评分（action×0.4 + data×0.35 + context×0.25）+ AI-RBAC 权限管理。通过文本匹配评估工具名称和参数的风险等级，输出 ALLOW/CONFIRM/BLOCK 决策。

### DLP 数据防泄露
检测 13 类敏感数据（含 PIPL 个人信息），自动脱敏，零知识日志记录。

### Skill 安全扫描
6 个静态分析检查器，对 Skill 的 SKILL.md 和脚本文件进行文本扫描，检测凭证泄露、权限缺失、文档完整性等风险。

### 审计日志
Ed25519 签名的 JSONL 格式审计记录，支持按 agent_id / action / decision / 时间范围查询。

## Rules

- 安装前必须告知用户并获得确认
- 初始化前告知用户将创建签名密钥
- Python 版本低于 3.10 时提示升级
- 优先直接 pip install，失败再用 venv
- 记住确定的命令路径，后续统一使用
- 扫描结果中凭据已自动脱敏
- 必须使用 openclaw360 命令，不要自己写脚本模拟
- 规则更新必须由用户手动触发

### 扫描报告规则

语言规则：中文用户加 `--lang zh`，英文用户用默认。回复语言与用户一致。

命令执行规则：使用 `--format json` 获取结构化数据。只执行一次，等完成后一次性回复。

报告展示（两阶段）：默认展示概览报告（评分分布、需关注 Skill、统计、建议），用户输入「详细报告」时展示逐 Skill 详细结果。

概览报告规则：
1. 每个有问题的 Skill 包含「对你的威胁」说明
2. 同类发现合并，用数量列标注
3. 评分相同的 Skill 合并为一组
4. 分数条格式：`[████████░░] 83`
5. 严重级别 emoji：🔴 Critical、🟠 High、🟡 Medium、🔵 Low、⚪ Info
6. 按分数从低到高排序
7. 区分文档示例数据与真实凭证
8. 末尾提示可输入「详细报告」查看完整结果
