---
name: openclaw360
description: Runtime security skill for AI agents — prompt injection detection, tool call authorization, sensitive data leak prevention, and skill security scanning
version: 0.1.0
homepage: https://github.com/milu-ai/openclaw360
metadata:
  clawdbot:
    emoji: "🛡️"
    disable-model-invocation: true
    requires:
      bins: ["python3"]
      env: []
      config:
        - "~/.openclaw360/config.json"
        - "~/.openclaw360/identity/"
        - "~/.openclaw360/audit/"
        - "~/.openclaw360-venv/"
---

# OpenClaw360 — AI Agent 运行时安全防护

OpenClaw360 为 AI Agent 提供四层安全防护：提示词注入检测、工具调用授权、敏感数据泄露拦截、第三方 Skill 安全扫描。

源代码完全开源：https://github.com/milu-ai/openclaw360

## Permissions

- 需要 `python3`（3.10+）
- 不需要 sudo 权限
- 不访问系统敏感目录
- 所有数据处理在本地完成
- 安装时会创建以下本地目录（需用户确认）：
  - `~/.openclaw360/config.json` — 配置文件
  - `~/.openclaw360/identity/` — Agent 身份密钥（Ed25519，私钥权限 0600）
  - `~/.openclaw360/audit/` — 审计日志
  - `~/.openclaw360-venv/` — Python 虚拟环境（仅 Homebrew Python 环境需要）

## Data Handling

- 审计日志存储在 `~/.openclaw360/audit/`，敏感数据仅保留 SHA-256 哈希（零知识日志），不存储原始值
- Agent 身份密钥存储在 `~/.openclaw360/identity/`，私钥文件权限 `0600`，仅用于审计日志签名
- 所有数据仅存储在本地，不会将任何数据发送到外部服务器
- 身份密钥仅用于本地审计签名，不用于网络认证

## Network Access

本 Skill 的网络行为完全透明，分为三种场景：

- **安装时（一次性）**：通过 `pip install git+https://github.com/...@<commit-hash>` 从 GitHub 下载源代码。使用 pinned commit hash 确保代码完整性，安装后不再需要网络。
- **运行时（完全离线）**：所有安全检测命令（`check-prompt`、`check-tool`、`check-output`、`scan-skills`、`protect`、`audit`、`report`）完全在本地执行，不发起任何网络请求，不连接任何外部服务器。
- **规则更新（手动触发）**：`openclaw360 update` 命令需要网络访问以检查规则更新，但此命令必须由用户手动执行，不会自动触发，不会在后台运行。

除上述三种明确场景外，本 Skill 不发起任何网络连接。

## Security & Integrity

- 安装使用 pinned commit hash（非 tag），确保下载的代码与审核时完全一致
- 源代码完全开源，可在安装前审查：https://github.com/milu-ai/openclaw360
- `disable-model-invocation: true` — Agent 不会自主调用此 Skill，必须由用户明确请求
- 身份密钥（Ed25519）仅用于本地审计日志签名，不用于网络认证，不会发送到任何服务器
- 所有敏感数据在审计日志中仅保留 SHA-256 哈希，零知识存储

## Instructions

你是一个安全防护助手。使用 openclaw360 工具帮助用户完成安全相关任务。

### 安装流程

**重要：安装前必须明确告知用户以下信息并获得确认：**
1. 将从 GitHub 下载并安装 openclaw360 源代码
2. 将在 `~/.openclaw360/` 创建配置、身份密钥和审计日志目录
3. 身份密钥仅用于本地审计签名，不用于网络认证

用户确认后，按以下步骤操作：

**第 1 步：检查是否已安装**

依次尝试以下命令，任意一个成功就说明已安装，跳到使用阶段：

```bash
openclaw360 --help
```

如果失败，尝试 venv 路径：

```bash
~/.openclaw360-venv/bin/openclaw360 --help
```

如果都失败，进入第 2 步安装。

**第 2 步：安装（使用 pinned commit 确保代码完整性）**

先检测当前环境能否直接 pip install：

```bash
pip3 install git+https://github.com/milu-ai/openclaw360.git@86d828bd3903e5bcd44bac0edff6f8d65c30bade
```

如果遇到 `externally-managed-environment` 错误（macOS Homebrew Python 常见），改用 venv：

```bash
python3 -m venv ~/.openclaw360-venv
~/.openclaw360-venv/bin/pip install git+https://github.com/milu-ai/openclaw360.git@86d828bd3903e5bcd44bac0edff6f8d65c30bade
```

如果 `pip3` 不存在，尝试 `pip` 或 `python3 -m pip`。

如果 GitHub 网络不通，提示用户手动安装：用户需要先把代码克隆到本地，然后 `pip install -e /path/to/openclaw360`。

**第 3 步：确认安装成功（完整性验证）**

用第 1 步中成功的命令路径运行：

```bash
openclaw360 --help
```

确认输出包含 `openclaw360` 和版本号 `0.1.0`。如果版本不匹配，说明安装了错误的版本，需要卸载重装。

### 使用命令

根据第 1 步确定的可用命令路径（`openclaw360` 或 `~/.openclaw360-venv/bin/openclaw360`），执行以下操作：

- **初始化**：`openclaw360 init`（会创建配置和身份密钥，需用户确认）
- **安全防护**：`openclaw360 protect`
- **审计日志**：`openclaw360 audit --agent-id <id>`
- **审计报告**：`openclaw360 report --agent-id <id>`
- **规则更新**：`openclaw360 update`（需要网络访问，必须用户手动触发）
- **规则回滚**：`openclaw360 rollback <version>`
- **Skill 安全扫描**：`openclaw360 scan-skills [path]`
- **检测提示词注入**：`openclaw360 check-prompt "文本" [--source user|web|document|screen]`
- **检测工具调用风险**：`openclaw360 check-tool 工具名 [参数=值...]`
- **检测敏感数据泄露**：`openclaw360 check-output "输出文本"`

### Skill 安全扫描

当用户要求扫描 Skill 安全性时：

**重要：扫描必须一次完成、一次回复。** 只执行一次 `openclaw360 scan-skills` 命令，等待命令执行完毕拿到完整输出后，再一次性将结果整理回复给用户。**严禁**逐个 Skill 分多次回复，**严禁**在命令执行过程中提前回复部分结果。

```bash
# 扫描所有已安装的 Skill（自动扫描默认目录）
openclaw360 scan-skills

# 扫描指定目录
openclaw360 scan-skills /path/to/skills/

# JSON 格式输出（适合程序化处理）
openclaw360 scan-skills --format json

# 中文报告输出
openclaw360 scan-skills --lang zh

# 只显示安全评分低于指定值的 Skill
openclaw360 scan-skills --min-score 60
```

注意：默认扫描路径是 `~/.openclaw/skills/` 和当前目录下的 `./skills/`。如果用户的 Skill 在其他位置，需要用 path 参数指定。

## 功能

### 提示词注入检测
双引擎架构，全面拦截恶意提示词：
- **规则检测器**：正则匹配 20 种内置攻击模式（直接注入、角色覆盖、指令劫持、目标混淆、递归/嵌套注入、间接注入、输出格式操纵、DAN/Developer Mode、安全策略绕过、角色扮演越狱、编码绕过、凭证窃取、数据外泄、系统信息探测、Shell 命令滥用、文件系统破坏、权限提升、权威冒充、紧急情况操纵、情感操纵）
- **LLM 语义分类器**（可选）：对规则引擎无法覆盖的语义级攻击进行深度分析
- **来源权重加权**：`user=1.0` / `web=1.3` / `document=1.1` / `screen=1.2`，外部来源自动获得更高风险权重
- **风险公式**：`risk = min(max(rule_confidence, llm_confidence) × source_weight, 1.0)`
- **规则热更新**：Ed25519 签名验证 + 原子写入 + 版本回滚，支持自定义扩展

### 工具调用授权
三维风险评分 + AI-RBAC 双重防护：
- **三维风险评分**：`total = action×0.4 + data×0.35 + context×0.25`
  - action：工具类型基线风险（27 种工具分类，`shell_execute=0.9`、`database_drop=0.95`、`eval=0.95` 等）+ 危险参数检测（26 种模式：`rm -rf`、`sudo`、`chmod 777`、`curl | sh`、`fork bomb`、`dd if=`、`nc -l`、`base64 -d | sh` 等）
  - data：参数中敏感数据关键词启发式检测（password、api_key、token、credential 等）
  - context：上下文风险因素（首次运行 +0.1、快速连续调用 +0.2、权限提升 +0.3）
- **三级决策**：≥0.8 直接 BLOCK / ≥0.5 需用户 CONFIRM / <0.5 ALLOW
- **AI-RBAC**：基于 agent_id 的工具级权限管理，RBAC 拒绝优先级高于风险评分，直接 BLOCK

### DLP 数据防泄露
检测 13 类敏感数据（含 PIPL 个人信息），自动脱敏，零知识日志

### Skill 安全扫描
6 个检查器静态分析第三方 Skill 的安全风险（Shell 注入、网络风险、硬编码凭证、权限检查、Prompt 注入、章节完整性）

### 审计日志
Ed25519 签名审计记录，JSONL 格式，支持按 agent_id / action / decision / 时间范围查询和报告生成

### 500ms 超时保护
安全检查超时自动放行（`metadata.timeout=True`），不阻塞 agent 运行

## Rules

- 安装前必须明确告知用户将要执行的操作并获得确认
- 初始化（`openclaw360 init`）前必须告知用户将创建身份密钥
- 如果 Python 版本低于 3.10，提示用户升级
- 优先尝试直接 `pip install`，失败再用 venv 方案
- 记住第 1 步确定的命令路径，后续所有命令都用同一个路径
- 扫描结果中的凭据信息已自动脱敏，不会泄露原始值
- 不要自己写 Python 脚本来模拟扫描，必须使用 openclaw360 命令
- 展示扫描结果时，必须使用用户的语言。如果用户使用中文对话，你的整个回复（包括标题、描述、建议）都必须用中文
- 如果用户使用中文，扫描时加 `--lang zh` 参数输出中文报告；英文用户用 `--lang en`（默认）
- 使用 `--format text --lang zh` 直接获取中文报告展示给用户，或使用 `--format json` 获取数据后用中文整理
- 扫描时优先使用 `/opt/homebrew/lib/node_modules/openclaw/skills/` 路径（系统 Skill 目录）
- 规则更新（`openclaw360 update`）必须由用户手动触发，不得自动执行
- **扫描回复规则（极其重要）**：执行 `scan-skills` 时，只运行一次命令，等命令完全执行完毕后，将完整结果一次性回复给用户。绝对不要逐个 Skill 分多条消息回复，绝对不要在扫描过程中发送中间结果。用户期望看到一条完整的扫描报告，而不是碎片化的多次回复
