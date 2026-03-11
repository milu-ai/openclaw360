---
name: openclaw360
description: Runtime security skill for AI agents — prompt injection detection, tool call authorization, sensitive data leak prevention, and skill security scanning
version: 0.1.0
homepage: https://github.com/milu-ai/openclaw360
metadata:
  clawdbot:
    emoji: "🛡️"
    requires:
      bins: ["python3"]
      env: []
---

# OpenClaw360 — AI Agent 运行时安全防护

OpenClaw360 为 AI Agent 提供四层安全防护：提示词注入检测、工具调用授权、敏感数据泄露拦截、第三方 Skill 安全扫描。

## Permissions

本 Skill 需要 `python3`（3.10+）来安装运行。不需要 sudo 权限，不需要访问系统敏感目录。所有数据处理在本地完成。

## Data Handling

- 审计日志存储在 `~/.openclaw360/audit/`，敏感数据仅保留 SHA-256 哈希（零知识日志）
- Agent 身份密钥存储在 `~/.openclaw360/identity/`，私钥文件权限 `0600`
- 不会将任何数据发送到外部服务器

## Network Access

本 Skill 不主动发起网络请求。安装时需要访问 GitHub 下载代码。规则更新功能需要网络访问，但默认不自动触发。

## Instructions

你是一个安全防护助手。使用 openclaw360 工具帮助用户完成安全相关任务。

### 安装流程

当用户要求安装或使用 openclaw360 时，按以下步骤操作：

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

**第 2 步：安装**

先检测当前环境能否直接 pip install：

```bash
pip3 install git+https://github.com/milu-ai/openclaw360.git
```

如果遇到 `externally-managed-environment` 错误（macOS Homebrew Python 常见），改用 venv：

```bash
python3 -m venv ~/.openclaw360-venv
~/.openclaw360-venv/bin/pip install git+https://github.com/milu-ai/openclaw360.git
```

如果 `pip3` 不存在，尝试 `pip` 或 `python3 -m pip`。

如果 GitHub 网络不通，提示用户手动安装：用户需要先把代码克隆到本地，然后 `pip install -e /path/to/openclaw360`。

**第 3 步：确认安装成功**

用第 1 步中成功的命令路径运行：

```bash
openclaw360 --help
```

### 使用命令

根据第 1 步确定的可用命令路径（`openclaw360` 或 `~/.openclaw360-venv/bin/openclaw360`），执行以下操作：

- **初始化**：`openclaw360 init`
- **安全防护**：`openclaw360 protect`
- **审计日志**：`openclaw360 audit --agent-id <id>`
- **审计报告**：`openclaw360 report --agent-id <id>`
- **规则更新**：`openclaw360 update`
- **规则回滚**：`openclaw360 rollback <version>`
- **Skill 安全扫描**：`openclaw360 scan-skills [path]`

### Skill 安全扫描

当用户要求扫描 Skill 安全性时：

```bash
# 扫描所有已安装的 Skill（自动扫描默认目录）
openclaw360 scan-skills

# 扫描指定目录
openclaw360 scan-skills /path/to/skills/

# JSON 格式输出（适合程序化处理）
openclaw360 scan-skills --format json

# 只显示安全评分低于指定值的 Skill
openclaw360 scan-skills --min-score 60
```

注意：默认扫描路径是 `~/.openclaw/skills/` 和当前目录下的 `./skills/`。如果用户的 Skill 在其他位置，需要用 path 参数指定。

## 功能

- **提示词注入检测**：识别 jailbreak、prompt injection 等 10 种攻击模式
- **工具调用授权**：三维风险评分 + AI-RBAC 权限控制
- **DLP 数据防泄露**：检测 8 类敏感数据，自动脱敏，零知识日志
- **Skill 安全扫描**：6 个检查器静态分析第三方 Skill 的安全风险
- **审计日志**：Ed25519 签名审计记录，支持查询和报告
- **500ms 超时保护**：安全检查超时自动放行，不阻塞 agent 运行

## Rules

- 安装前必须确认用户同意
- 如果 Python 版本低于 3.10，提示用户升级
- 优先尝试直接 `pip install`，失败再用 venv 方案
- 记住第 1 步确定的命令路径，后续所有命令都用同一个路径
- 扫描结果中的凭据信息已自动脱敏，不会泄露原始值
- 不要自己写 Python 脚本来模拟扫描，必须使用 openclaw360 命令
- 展示扫描结果时，使用 `--format json` 获取数据，然后用用户的语言整理成易读的报告
- 扫描时优先使用 `/opt/homebrew/lib/node_modules/openclaw/skills/` 路径（系统 Skill 目录）
