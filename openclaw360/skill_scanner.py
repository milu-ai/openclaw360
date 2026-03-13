"""Skill Security Scanner for OpenClaw360.

Provides static security scanning for third-party Agent Skills,
detecting shell injection, data exfiltration, hardcoded credentials,
excessive permissions, prompt injection, and other security risks.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import yaml

from openclaw360.exceptions import ScanError, SkillParseError


# ---------------------------------------------------------------------------
# i18n translation tables
# ---------------------------------------------------------------------------

_TRANSLATIONS: dict[str, dict[str, str]] = {
    "en": {
        "report_title": "=== Skill Security Scan Report ===",
        "scan_time": "Scan Time",
        "skills_scanned": "Skills Scanned",
        "overall_score": "Overall Score",
        "summary": "Summary",
        "details": "Details",
        "score": "Score",
        "parse_error": "Parse Error",
        "file": "File",
        "line": "Line",
        "recommendation": "Recommendation",
        "score_distribution": "Score Distribution",
        "critical_label": "critical",
        "warning_label": "warning",
        "good_label": "good",
        "best": "Best",
        "worst": "Worst",
        "findings": "Findings",
        "needs_attention": "Skills needing immediate attention",
        "multiple_issues": "multiple issues",
        "missing_section": "Missing security section",
        "missing_perm_decl": "Missing permission declaration: metadata.clawdbot.requires not found",
        "add_section_rec": "Add a '{section}' section to SKILL.md to document security considerations.",
        "add_requires_rec": "Add a 'requires' section to metadata.clawdbot to declare needed permissions.",
        "by_category": "By Category",
        "checklist": "Checklist",
        "checklist_perms": "Permission Decl",
    },
    "zh": {
        "report_title": "=== Skill 安全扫描报告 ===",
        "scan_time": "扫描时间",
        "skills_scanned": "扫描 Skill 数量",
        "overall_score": "综合评分",
        "summary": "摘要",
        "details": "详情",
        "score": "评分",
        "parse_error": "解析错误",
        "file": "文件",
        "line": "行号",
        "recommendation": "建议",
        "score_distribution": "评分分布",
        "critical_label": "危险",
        "warning_label": "警告",
        "good_label": "良好",
        "best": "最佳",
        "worst": "最差",
        "findings": "发现",
        "needs_attention": "需要立即关注的 Skill",
        "multiple_issues": "多个问题",
        "missing_section": "缺少安全章节",
        "missing_perm_decl": "缺少权限声明：未找到 metadata.clawdbot.requires",
        "add_section_rec": "请在 SKILL.md 中添加 '{section}' 章节以说明安全相关信息。",
        "add_requires_rec": "请在 metadata.clawdbot 中添加 'requires' 字段以声明所需权限。",
        "by_category": "按类别",
        "checklist": "检查清单",
        "checklist_perms": "权限声明",
    },
}

# Finding description translations (en -> zh)
_FINDING_TRANSLATIONS_ZH: dict[str, str] = {
    # ScriptAnalyzer
    "Unescaped variable interpolation": "未转义的变量插值",
    "eval() call": "eval() 调用",
    "curl | sh pipe execution": "curl | sh 管道执行",
    "exec() with dynamic arguments": "exec() 动态参数调用",
    "File write outside Skill directory": "向 Skill 目录外写入文件",
    "File copy outside Skill directory": "向 Skill 目录外复制文件",
    # NetworkAnalyzer
    "POST/PUT request with local file content or environment variables": "POST/PUT 请求包含本地文件内容或环境变量",
    "Network request with dynamic URL": "使用动态 URL 的网络请求",
    "Non-HTTPS endpoint detected": "检测到非 HTTPS 端点",
    # PermissionChecker
    "Missing permission declaration: metadata.clawdbot.requires not found": "缺少权限声明：未找到 metadata.clawdbot.requires",
    # Recommendation translations
    "Use environment variables or a secrets manager instead of hardcoding credentials.": "请使用环境变量或密钥管理器，避免硬编码凭据。",
    "Use HTTPS instead of HTTP for secure communication.": "请使用 HTTPS 替代 HTTP 以确保通信安全。",
    "Use static, validated URLs for network requests.": "请使用静态、经过验证的 URL 进行网络请求。",
    "Avoid sending local file content or sensitive environment variables in HTTP requests.": "避免在 HTTP 请求中发送本地文件内容或敏感环境变量。",
    "Restrict file operations to the Skill directory.": "请将文件操作限制在 Skill 目录内。",
    "Reduce the number of required binaries to the minimum necessary.": "请将所需二进制文件减少到最低限度。",
}


def _t(lang: str, key: str, **kwargs: Any) -> str:
    """Look up a translation string, falling back to English."""
    table = _TRANSLATIONS.get(lang, _TRANSLATIONS["en"])
    template = table.get(key, _TRANSLATIONS["en"].get(key, key))
    return template.format(**kwargs) if kwargs else template


def _translate_finding(desc: str, lang: str) -> str:
    """Translate a finding description if a translation exists."""
    if lang == "en":
        return desc
    # Try exact match first
    if desc in _FINDING_TRANSLATIONS_ZH:
        return _FINDING_TRANSLATIONS_ZH[desc]
    # Handle "Missing security section: X" pattern
    if desc.startswith("Missing security section: "):
        section = desc[len("Missing security section: "):]
        return f"缺少安全章节: {section}"
    # Handle "Hardcoded X detected: Y" pattern
    if desc.startswith("Hardcoded ") and " detected: " in desc:
        parts = desc.split(" detected: ", 1)
        data_type = parts[0][len("Hardcoded "):]
        masked = parts[1]
        return f"检测到硬编码的 {data_type}: {masked}"
    # Handle "High-risk binary requested: X"
    if desc.startswith("High-risk binary requested: "):
        bin_name = desc[len("High-risk binary requested: "):]
        return f"请求高风险二进制文件: {bin_name}"
    # Handle "Sensitive environment variable requested: X"
    if desc.startswith("Sensitive environment variable requested: "):
        rest = desc[len("Sensitive environment variable requested: "):]
        return f"请求敏感环境变量: {rest}"
    # Handle "Excessive binary permissions: X"
    if desc.startswith("Excessive binary permissions: "):
        rest = desc[len("Excessive binary permissions: "):]
        return f"过多的二进制权限: {rest}"
    # Try prefix match for other parameterized descriptions
    for en, zh in _FINDING_TRANSLATIONS_ZH.items():
        if desc.startswith(en):
            return zh + desc[len(en):]
    return desc


def _translate_recommendation(rec: str, lang: str) -> str:
    """Translate a recommendation if a translation exists."""
    if lang == "en":
        return rec
    if rec in _FINDING_TRANSLATIONS_ZH:
        return _FINDING_TRANSLATIONS_ZH[rec]
    # Handle parameterized recommendations like "Add a 'X' section..."
    if rec.startswith("Add a '") and "section to SKILL.md" in rec:
        section = rec.split("'")[1]
        return _t(lang, "add_section_rec", section=section)
    if rec.startswith("Add a 'requires'"):
        return _t(lang, "add_requires_rec")
    return rec


class FindingSeverity(Enum):
    """Security finding severity level."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(Enum):
    """Security finding category."""

    SHELL_INJECTION = "shell_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    HARDCODED_CREDENTIAL = "hardcoded_credential"
    EXCESSIVE_PERMISSION = "excessive_permission"
    PROMPT_INJECTION = "prompt_injection"
    MISSING_SECTION = "missing_section"
    PARSE_ERROR = "parse_error"
    EXTERNAL_WRITE = "external_write"
    NETWORK_RISK = "network_risk"
    FILE_ERROR = "file_error"


@dataclass
class ScanFinding:
    """A single security finding."""

    severity: FindingSeverity
    category: FindingCategory
    description: str
    file_path: str  # Relative to the Skill directory
    line_number: Optional[int] = None
    recommendation: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ParsedSkill:
    """Parsed result of a SKILL.md file."""

    name: str
    metadata: dict[str, Any]  # YAML frontmatter
    requires_bins: list[str]  # metadata.clawdbot.requires.bins
    requires_env: list[str]  # metadata.clawdbot.requires.env
    requires_files: list[str]  # metadata.clawdbot.requires.files
    instructions: str  # Markdown instructions section
    raw_content: str  # Original file content
    sections: dict[str, str]  # Markdown sections {heading: content}


@dataclass
class SecurityChecklist:
    """Security checklist for a Skill."""

    has_permissions_section: bool = False
    has_data_handling_section: bool = False
    has_network_access_section: bool = False
    has_valid_frontmatter: bool = False
    has_permission_declaration: bool = False


@dataclass
class SkillScanResult:
    """Scan result for a single Skill."""

    skill_name: str
    skill_path: str
    score: int  # Security score [0, 100]
    findings: list[ScanFinding]
    checklist: SecurityChecklist
    parse_error: Optional[str] = None  # Error message if parsing failed


@dataclass
class SeverityStats:
    """Finding counts grouped by severity level."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


@dataclass
class ScanReport:
    """Complete scan report."""

    scan_time: str  # ISO 8601 timestamp
    skill_count: int  # Number of Skills scanned
    results: list[SkillScanResult]  # Per-Skill scan results
    overall_score: float  # Overall security score (arithmetic mean)
    severity_stats: SeverityStats  # Finding counts by severity
    scanned_paths: list[str] = field(default_factory=list)  # Paths that were scanned


class SkillMDParser:
    """SKILL.md file parser.

    Parses YAML frontmatter and Markdown instruction content from SKILL.md files.
    """

    _FRONTMATTER_RE = re.compile(
        r"^---\s*\n(.*?)\n---\s*\n(.*)",
        re.DOTALL,
    )

    def parse(self, skill_md_path: Path) -> ParsedSkill:
        """Parse a SKILL.md file.

        Args:
            skill_md_path: Path to the SKILL.md file.

        Returns:
            ParsedSkill with extracted metadata and sections.

        Raises:
            SkillParseError: If YAML frontmatter is missing or invalid.
        """
        content = skill_md_path.read_text(encoding="utf-8")

        # Step 1: Separate YAML frontmatter and Markdown content
        match = self._FRONTMATTER_RE.match(content)
        if not match:
            raise SkillParseError("Missing YAML frontmatter (no --- delimiters found)")

        yaml_str = match.group(1)
        markdown_str = match.group(2)

        # Step 2: Parse YAML
        try:
            metadata = yaml.safe_load(yaml_str) or {}
        except yaml.YAMLError as exc:
            raise SkillParseError(f"Invalid YAML: {exc}") from exc

        # Step 3: Extract requires fields
        clawdbot = metadata.get("metadata", {}).get("clawdbot", {}) if isinstance(metadata, dict) else {}
        requires = clawdbot.get("requires", {}) if isinstance(clawdbot, dict) else {}
        requires_bins = requires.get("bins", []) or []
        requires_env = requires.get("env", []) or []
        requires_files = requires.get("files", []) or []

        # Step 4: Parse Markdown sections
        sections = self._parse_markdown_sections(markdown_str)

        # Step 5: Extract instructions
        instructions = sections.get("Instructions", "")

        # Name comes from the parent directory
        name = skill_md_path.parent.name

        return ParsedSkill(
            name=name,
            metadata=metadata,
            requires_bins=requires_bins,
            requires_env=requires_env,
            requires_files=requires_files,
            instructions=instructions,
            raw_content=content,
            sections=sections,
        )

    def pretty_print(self, parsed: ParsedSkill) -> str:
        """Format a ParsedSkill back to SKILL.md file content.

        Args:
            parsed: Parsed Skill data.

        Returns:
            Formatted SKILL.md string.
        """
        # Reconstruct YAML frontmatter
        yaml_str = yaml.dump(parsed.metadata, default_flow_style=False, allow_unicode=True)
        result = f"---\n{yaml_str}---\n"

        # Reconstruct Markdown sections in order
        for heading, body in parsed.sections.items():
            result += f"\n## {heading}\n"
            if body:
                result += f"\n{body}\n"

        return result

    @staticmethod
    def _parse_markdown_sections(markdown: str) -> dict[str, str]:
        """Split Markdown content into sections by ``## `` headings.

        Args:
            markdown: The Markdown portion of the SKILL.md file.

        Returns:
            Ordered dict mapping heading text to section body.
        """
        sections: dict[str, str] = {}
        parts = re.split(r"^## ", markdown, flags=re.MULTILINE)

        for part in parts:
            if not part.strip():
                continue
            lines = part.split("\n", 1)
            heading = lines[0].strip()
            body = lines[1].strip() if len(lines) > 1 else ""
            sections[heading] = body

        return sections


class SkillDiscovery:
    """Skill directory discovery and traversal."""

    # ~/.openclaw/skills/ is the OpenClaw platform Skill directory (not openclaw360's own ~/.openclaw360/)
    DEFAULT_PATHS = [
        "~/.openclaw/skills/",
        "<workspace>/skills/",
    ]

    def discover_skills(self, paths: list[str] | None = None) -> list[Path]:
        """Discover all Skill directories.

        When *paths* is ``None``, the default scan locations are used:
        ``~/.openclaw/skills/`` (OpenClaw platform Skill directory) and ``<cwd>/skills/``.

        Discovery logic (for each base path):
        1. If the base path itself contains ``SKILL.md``, treat it as a single Skill.
        2. Otherwise, scan immediate children for directories containing ``SKILL.md``.
        3. If no immediate children match, recursively search up to 3 levels deep.

        Args:
            paths: Explicit scan paths. ``None`` uses defaults.

        Returns:
            Sorted list of directories that contain a ``SKILL.md`` file.

        Raises:
            ScanError: If a specified path does not exist or is not a directory.
        """
        if paths is None:
            # ~/.openclaw/skills/ is the OpenClaw platform Skill directory, not openclaw360's own dir
            resolved_paths = [
                os.path.expanduser("~/.openclaw/skills/"),
                os.path.join(os.getcwd(), "skills/"),
            ]
        else:
            resolved_paths = list(paths)

        skill_dirs: list[Path] = []
        seen: set[Path] = set()

        for base in resolved_paths:
            p = Path(base)
            if not p.exists() or not p.is_dir():
                raise ScanError(f"Path does not exist or is not a directory: {base}")

            # Case 1: The path itself is a Skill directory
            if self._has_skill_md(p):
                resolved = p.resolve()
                if resolved not in seen:
                    seen.add(resolved)
                    skill_dirs.append(p)
                continue

            # Case 2: Check immediate children
            immediate: list[Path] = []
            for child in sorted(p.iterdir()):
                if child.is_dir() and self._has_skill_md(child):
                    resolved = child.resolve()
                    if resolved not in seen:
                        seen.add(resolved)
                        immediate.append(child)

            if immediate:
                skill_dirs.extend(immediate)
                continue

            # Case 3: Recursive search (up to 3 levels deep)
            self._discover_recursive(p, skill_dirs, seen, max_depth=3, current_depth=0)

        return sorted(skill_dirs, key=lambda d: d.name)

    @staticmethod
    def _has_skill_md(directory: Path) -> bool:
        """Check if a directory contains a SKILL.md file (case-insensitive)."""
        try:
            for f in directory.iterdir():
                if f.is_file() and f.name.lower() == "skill.md":
                    return True
        except PermissionError:
            pass
        return False

    @staticmethod
    def _get_skill_md(directory: Path) -> Path | None:
        """Get the SKILL.md path (case-insensitive) or None."""
        try:
            for f in directory.iterdir():
                if f.is_file() and f.name.lower() == "skill.md":
                    return f
        except PermissionError:
            pass
        return None

    def _discover_recursive(
        self,
        directory: Path,
        skill_dirs: list[Path],
        seen: set[Path],
        max_depth: int,
        current_depth: int,
    ) -> None:
        """Recursively discover Skill directories up to max_depth."""
        if current_depth >= max_depth:
            return
        try:
            for child in sorted(directory.iterdir()):
                if not child.is_dir():
                    continue
                if self._has_skill_md(child):
                    resolved = child.resolve()
                    if resolved not in seen:
                        seen.add(resolved)
                        skill_dirs.append(child)
                else:
                    self._discover_recursive(child, skill_dirs, seen, max_depth, current_depth + 1)
        except PermissionError:
            pass


class ScriptAnalyzer:
    """Script file security analyzer.

    Detects shell injection, unsafe command execution, and external write
    operations in script files within a Skill directory.
    """

    SUPPORTED_EXTENSIONS = {".sh", ".bash", ".py", ".js", ".ts"}

    # Shell injection risk patterns: (regex, severity, description)
    SHELL_INJECTION_PATTERNS: list[tuple[str, str, str]] = [
        (r'\$\{?\w+\}?', "high", "Unescaped variable interpolation"),
        (r'\beval\s*\(', "critical", "eval() call"),
        (r'curl\s+.*\|\s*(?:sh|bash)', "critical", "curl | sh pipe execution"),
        (r'\bexec\s*\(.*\$', "high", "exec() with dynamic arguments"),
    ]

    # External write patterns: (regex, description)
    EXTERNAL_WRITE_PATTERNS: list[tuple[str, str]] = [
        (r'>\s*/(?!tmp/)', "File write outside Skill directory"),
        (r'cp\s+.*\s+/(?!tmp/)', "File copy outside Skill directory"),
    ]

    def analyze(self, file_path: Path, skill_dir: Path) -> list[ScanFinding]:
        """Analyze a single script file for security risks.

        Args:
            file_path: Path to the script file.
            skill_dir: Skill root directory (used to judge external writes).

        Returns:
            List of ScanFinding instances.
        """
        findings: list[ScanFinding] = []
        relative_path = str(file_path.relative_to(skill_dir))

        try:
            lines = file_path.read_text(encoding="utf-8").splitlines()
        except Exception as exc:
            findings.append(
                ScanFinding(
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.FILE_ERROR,
                    description=f"Unable to read file: {exc}",
                    file_path=relative_path,
                    recommendation="Check file permissions and encoding.",
                )
            )
            return findings

        for line_number, line in enumerate(lines, start=1):
            # Check shell injection patterns
            for pattern, severity, description in self.SHELL_INJECTION_PATTERNS:
                if re.search(pattern, line):
                    findings.append(
                        ScanFinding(
                            severity=FindingSeverity(severity),
                            category=FindingCategory.SHELL_INJECTION,
                            description=description,
                            file_path=relative_path,
                            line_number=line_number,
                            recommendation=f"Avoid {description.lower()}; use safe alternatives.",
                        )
                    )

            # Check external write patterns
            for pattern, description in self.EXTERNAL_WRITE_PATTERNS:
                if re.search(pattern, line):
                    findings.append(
                        ScanFinding(
                            severity=FindingSeverity.HIGH,
                            category=FindingCategory.EXTERNAL_WRITE,
                            description=description,
                            file_path=relative_path,
                            line_number=line_number,
                            recommendation="Restrict file operations to the Skill directory.",
                        )
                    )

        return findings

    def analyze_all(self, skill_dir: Path) -> list[ScanFinding]:
        """Analyze all supported script files in a Skill directory.

        Args:
            skill_dir: Skill root directory.

        Returns:
            Combined list of ScanFinding from all script files.
        """
        findings: list[ScanFinding] = []
        for file_path in sorted(skill_dir.rglob("*")):
            if file_path.is_file() and file_path.suffix in self.SUPPORTED_EXTENSIONS:
                findings.extend(self.analyze(file_path, skill_dir))
        return findings


class NetworkAnalyzer:
    """Network call security analyzer.

    Detects suspicious network requests including non-HTTPS endpoints,
    dynamic URLs, and potential data exfiltration via POST/PUT.
    """

    NETWORK_CALL_PATTERNS: list[str] = [
        r'\bcurl\b',
        r'\bwget\b',
        r'\brequests\.\w+',
        r'\burllib\.\w+',
        r'\bhttp\.client\b',
        r'\bfetch\s*\(',
        r'\baxios\.\w+',
    ]

    # Patterns for detecting non-HTTPS URLs
    _HTTP_URL_RE = re.compile(r'http://[^\s\'"]+')
    # Patterns for detecting dynamic URLs (variable interpolation)
    _DYNAMIC_URL_RE = re.compile(
        r'(?:\$\{?\w+\}?|f["\'].*\{|`.*\$\{)',
    )
    # Patterns for POST/PUT with local file content or env vars
    _POST_PUT_EXFIL_RE = re.compile(
        r'(?:-X\s*(?:POST|PUT)|\.post\s*\(|\.put\s*\(|method\s*[:=]\s*["\'](?:POST|PUT))'
    )
    _LOCAL_DATA_RE = re.compile(
        r'(?:@/|--data-binary\s+@|open\s*\(|read\s*\(|\$\w*(?:SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL))',
        re.IGNORECASE,
    )

    def analyze(self, file_path: Path) -> list[ScanFinding]:
        """Analyze a single file for network call risks.

        Args:
            file_path: Path to the script file.

        Returns:
            List of ScanFinding, each with detected URL or URL pattern in metadata.
        """
        findings: list[ScanFinding] = []
        relative_path = str(file_path.relative_to(file_path.parent.parent)) if len(file_path.parts) > 1 else file_path.name

        try:
            lines = file_path.read_text(encoding="utf-8").splitlines()
        except Exception:
            return findings

        for line_number, line in enumerate(lines, start=1):
            # Check if line contains any network call pattern
            has_network_call = any(
                re.search(p, line) for p in self.NETWORK_CALL_PATTERNS
            )
            if not has_network_call:
                continue

            # Check for POST/PUT with local file content or env vars → critical
            if self._POST_PUT_EXFIL_RE.search(line) and self._LOCAL_DATA_RE.search(line):
                url_match = self._HTTP_URL_RE.search(line) or re.search(r'https?://[^\s\'"]+', line)
                detected_url = url_match.group(0) if url_match else "<dynamic>"
                findings.append(
                    ScanFinding(
                        severity=FindingSeverity.CRITICAL,
                        category=FindingCategory.DATA_EXFILTRATION,
                        description="POST/PUT request with local file content or environment variables",
                        file_path=relative_path,
                        line_number=line_number,
                        recommendation="Avoid sending local file content or sensitive environment variables in HTTP requests.",
                        metadata={"url": detected_url},
                    )
                )
                continue

            # Check for dynamic URLs → high
            if self._DYNAMIC_URL_RE.search(line):
                url_match = re.search(r'https?://[^\s\'"]*', line)
                detected_url = url_match.group(0) if url_match else "<dynamic>"
                findings.append(
                    ScanFinding(
                        severity=FindingSeverity.HIGH,
                        category=FindingCategory.NETWORK_RISK,
                        description="Network request with dynamic URL",
                        file_path=relative_path,
                        line_number=line_number,
                        recommendation="Use static, validated URLs for network requests.",
                        metadata={"url": detected_url},
                    )
                )
                continue

            # Check for non-HTTPS endpoints → medium
            http_match = self._HTTP_URL_RE.search(line)
            if http_match:
                findings.append(
                    ScanFinding(
                        severity=FindingSeverity.MEDIUM,
                        category=FindingCategory.NETWORK_RISK,
                        description="Non-HTTPS endpoint detected",
                        file_path=relative_path,
                        line_number=line_number,
                        recommendation="Use HTTPS instead of HTTP for secure communication.",
                        metadata={"url": http_match.group(0)},
                    )
                )

        return findings



class SecretDetector:
    """Hardcoded credential detector.

    Reuses DLPEngine's SENSITIVE_PATTERNS to detect API keys, passwords,
    tokens, SSH private keys, AWS access keys, and database connection strings.

    Context-aware severity: credentials found in SKILL.md documentation are
    likely author-provided example/placeholder data and receive reduced
    severity (INFO for obvious examples, LOW for ambiguous cases) compared
    to credentials in scripts or config files (CRITICAL).
    """

    # Patterns that indicate a value is example/placeholder data
    _EXAMPLE_INDICATORS = re.compile(
        r"(?:example|placeholder|your[_\-]?|sample|test|dummy|fake|demo|"
        r"xxx|foo|bar|changeme|replace[_\-]?me|todo|fixme)",
        re.IGNORECASE,
    )

    # Common example email local parts and domains
    _EXAMPLE_EMAIL_PARTS = {
        "you", "your", "user", "example", "test", "demo", "sample",
        "recipient", "sender", "john", "jane", "alice", "bob",
        "someone", "anybody", "nobody", "admin", "info", "mail",
        "name", "email", "myemail", "me", "person",
    }
    _EXAMPLE_EMAIL_DOMAINS = {
        "example.com", "example.org", "example.net", "test.com",
        "gmail.com", "mail.com", "email.com", "domain.com",
        "yourdomain.com", "company.com", "placeholder.com",
    }

    # Common example phone prefixes (US 555, Chinese test numbers)
    _EXAMPLE_PHONE_PREFIXES = ("1555", "+1555", "555", "+86555")

    def __init__(self) -> None:
        from openclaw360.dlp_engine import DLPEngine

        self._dlp = DLPEngine(None)

    def _is_example_value(self, raw_value: str, data_type_value: str) -> bool:
        """Check if a detected value looks like example/placeholder data.

        Args:
            raw_value: The original (unmasked) value detected.
            data_type_value: The SensitiveDataType.value string.

        Returns:
            True if the value appears to be example/demo data.
        """
        val_lower = raw_value.lower().strip()

        # Check generic example indicators
        if self._EXAMPLE_INDICATORS.search(val_lower):
            return True

        # Email-specific checks
        if data_type_value == "email":
            parts = val_lower.split("@")
            if len(parts) == 2:
                local, domain = parts
                if local in self._EXAMPLE_EMAIL_PARTS:
                    return True
                if domain in self._EXAMPLE_EMAIL_DOMAINS:
                    return True

        # Phone-specific checks
        if data_type_value == "phone_number":
            digits = re.sub(r"[\s\-\+]", "", val_lower)
            for prefix in self._EXAMPLE_PHONE_PREFIXES:
                clean_prefix = re.sub(r"[\s\-\+]", "", prefix)
                if digits.startswith(clean_prefix):
                    return True

        # IP address: multicast (224-239.x.x.x) or documentation ranges
        if data_type_value == "ip_address":
            first_octet = val_lower.split(".")[0]
            try:
                if 224 <= int(first_octet) <= 239:
                    return True  # Multicast range, not a real credential
            except ValueError:
                pass

        return False

    def _is_skill_md(self, file_path: Path) -> bool:
        """Check if the file is a SKILL.md documentation file."""
        return file_path.name.lower() == "skill.md"

    def detect(self, file_path: Path) -> list[ScanFinding]:
        """Detect hardcoded credentials in a file.

        Context-aware severity assignment:
        - SKILL.md + example data → INFO (no score penalty)
        - SKILL.md + ambiguous data → LOW (minor penalty)
        - Scripts/config files → CRITICAL (full penalty)

        Args:
            file_path: Path to the file to scan.

        Returns:
            List of ScanFinding with context-appropriate severity.
        """
        findings: list[ScanFinding] = []
        relative_path = str(file_path.relative_to(file_path.parent.parent)) if len(file_path.parts) > 1 else file_path.name

        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception:
            return findings

        matches = self._dlp.scan_text(content)
        if not matches:
            return findings

        is_doc = self._is_skill_md(file_path)

        # Pre-compute line start offsets for line number calculation
        line_starts = [0]
        for i, ch in enumerate(content):
            if ch == '\n':
                line_starts.append(i + 1)

        for match in matches:
            # Calculate line number from match start position
            start_pos = match.location[0]
            line_number = 1
            for idx, offset in enumerate(line_starts):
                if offset > start_pos:
                    line_number = idx
                    break
            else:
                line_number = len(line_starts)

            masked = match.masked_value

            # Determine severity based on file context
            if is_doc:
                # Extract raw value from content for example detection
                raw_value = content[match.location[0]:match.location[1]]
                is_example = self._is_example_value(raw_value, match.data_type.value)

                if is_example:
                    severity = FindingSeverity.INFO
                    rec = (
                        "Documentation example data detected. Consider replacing "
                        "with generic placeholders like <your-email> or <phone> "
                        "to avoid scanner false positives."
                    )
                else:
                    severity = FindingSeverity.LOW
                    rec = (
                        "Credential found in SKILL.md documentation. If this is "
                        "example data, replace with generic placeholders like "
                        "<your-email>. If real, remove immediately."
                    )
            else:
                severity = FindingSeverity.CRITICAL
                rec = "Use environment variables or a secrets manager instead of hardcoding credentials."
                is_example = False

            findings.append(
                ScanFinding(
                    severity=severity,
                    category=FindingCategory.HARDCODED_CREDENTIAL,
                    description=f"Hardcoded {match.data_type.value} detected: {masked}",
                    file_path=relative_path,
                    line_number=line_number,
                    recommendation=rec,
                    metadata={"is_example_data": is_example, "in_documentation": is_doc},
                )
            )

        return findings



class PermissionChecker:
    """Permission declaration checker.

    Analyzes SKILL.md's declared permissions (requires.bins, requires.env)
    for excessive or high-risk declarations.
    """

    HIGH_RISK_BINS: set[str] = {"sudo", "chmod", "chown", "dd", "nc", "ncat"}
    SENSITIVE_ENV_KEYWORDS: set[str] = {"SECRET", "KEY", "TOKEN", "PASSWORD", "CREDENTIAL"}
    MAX_BINS_THRESHOLD: int = 10

    def check(self, parsed_skill: ParsedSkill) -> list[ScanFinding]:
        """Check a Skill's permission declarations.

        Args:
            parsed_skill: Parsed Skill data from SkillMDParser.

        Returns:
            List of ScanFinding for permission issues.
        """
        findings: list[ScanFinding] = []

        # Check high-risk binaries
        for bin_name in parsed_skill.requires_bins:
            if bin_name in self.HIGH_RISK_BINS:
                findings.append(
                    ScanFinding(
                        severity=FindingSeverity.HIGH,
                        category=FindingCategory.EXCESSIVE_PERMISSION,
                        description=f"High-risk binary requested: {bin_name}",
                        file_path="SKILL.md",
                        recommendation=f"Avoid requiring '{bin_name}' unless absolutely necessary. Consider a safer alternative.",
                    )
                )

        # Check sensitive environment variables
        for env_name in parsed_skill.requires_env:
            env_upper = env_name.upper()
            for keyword in self.SENSITIVE_ENV_KEYWORDS:
                if keyword in env_upper:
                    findings.append(
                        ScanFinding(
                            severity=FindingSeverity.MEDIUM,
                            category=FindingCategory.EXCESSIVE_PERMISSION,
                            description=f"Sensitive environment variable requested: {env_name} (contains '{keyword}')",
                            file_path="SKILL.md",
                            recommendation=f"Ensure '{env_name}' is necessary and document why it is required.",
                        )
                    )
                    break  # Only one finding per env var

        # Check missing permission declaration
        clawdbot = parsed_skill.metadata.get("metadata", {}).get("clawdbot", {})
        if not clawdbot.get("requires"):
            findings.append(
                ScanFinding(
                    severity=FindingSeverity.MEDIUM,
                    category=FindingCategory.EXCESSIVE_PERMISSION,
                    description="Missing permission declaration: metadata.clawdbot.requires not found",
                    file_path="SKILL.md",
                    recommendation="Add a 'requires' section to metadata.clawdbot to declare needed permissions.",
                )
            )

        # Check excessive bins count
        if len(parsed_skill.requires_bins) > self.MAX_BINS_THRESHOLD:
            findings.append(
                ScanFinding(
                    severity=FindingSeverity.MEDIUM,
                    category=FindingCategory.EXCESSIVE_PERMISSION,
                    description=f"Excessive binary permissions: {len(parsed_skill.requires_bins)} binaries requested (threshold: {self.MAX_BINS_THRESHOLD})",
                    file_path="SKILL.md",
                    recommendation="Reduce the number of required binaries to the minimum necessary.",
                )
            )

        return findings


class PromptRiskChecker:
    """Prompt injection risk checker.

    Detects prompt injection risks in SKILL.md instruction sections,
    reusing RuleDetector's attack patterns for comprehensive detection.
    """

    # Skill-specific prompt injection patterns: (regex, severity, description)
    SKILL_PROMPT_PATTERNS: list[tuple[str, str, str]] = [
        (r'ignore\s+previous\s+instructions', "critical", "Role override instruction"),
        (r'you\s+are\s+now', "critical", "Role override instruction"),
        (r'execute\s+as\s+admin', "critical", "Privilege escalation instruction"),
        (r'bypass\s+security', "critical", "Privilege escalation instruction"),
    ]

    # Hidden instruction detection patterns: (regex, severity, description)
    HIDDEN_INSTRUCTION_PATTERNS: list[tuple[str, str, str]] = [
        (r'[\u200b\u200c\u200d\ufeff]', "high", "Unicode zero-width character"),
        (r'(?:base64|atob)\s*\(', "high", "Base64 encoded instruction"),
    ]

    def __init__(self) -> None:
        from openclaw360.prompt_engine import RuleDetector

        self._rule_detector = RuleDetector()

    def check(self, instructions: str) -> list[ScanFinding]:
        """Detect prompt injection risks in SKILL.md instructions.

        Args:
            instructions: The Markdown instruction section of SKILL.md.

        Returns:
            List of ScanFinding for detected prompt injection risks.
        """
        findings: list[ScanFinding] = []

        # Check skill-specific prompt patterns (case-insensitive)
        for pattern, severity, desc in self.SKILL_PROMPT_PATTERNS:
            if re.search(pattern, instructions, re.IGNORECASE):
                findings.append(
                    ScanFinding(
                        severity=FindingSeverity(severity),
                        category=FindingCategory.PROMPT_INJECTION,
                        description=f"{desc}: matched pattern '{pattern}'",
                        file_path="SKILL.md",
                        recommendation=f"Remove or rephrase content matching '{pattern}'. This pattern indicates a potential prompt injection risk.",
                    )
                )

        # Check hidden instruction patterns (case-sensitive)
        for pattern, severity, desc in self.HIDDEN_INSTRUCTION_PATTERNS:
            if re.search(pattern, instructions):
                findings.append(
                    ScanFinding(
                        severity=FindingSeverity(severity),
                        category=FindingCategory.PROMPT_INJECTION,
                        description=f"{desc}: matched pattern '{pattern}'",
                        file_path="SKILL.md",
                        recommendation=f"Remove content matching '{pattern}'. Hidden instructions are a security risk.",
                    )
                )

        # Use RuleDetector for additional threat detection
        detections = self._rule_detector.scan(instructions)
        for detection in detections:
            findings.append(
                ScanFinding(
                    severity=FindingSeverity(
                        "critical" if detection.confidence >= 0.9 else "high"
                    ),
                    category=FindingCategory.PROMPT_INJECTION,
                    description=f"{detection.threat_type.value}: {detection.description or detection.matched_pattern}",
                    file_path="SKILL.md",
                    recommendation=f"Review and remove content matching '{detection.matched_pattern}'. Detected threat: {detection.threat_type.value}.",
                )
            )

        return findings


class ScoreCalculator:
    """Security score calculator.

    Computes per-Skill security scores and overall scores based on
    the severity of findings.  Context-aware: missing security sections
    receive heavier penalties when the Skill actually uses the
    corresponding capability (e.g. missing "Network Access" section
    when network calls are detected).
    """

    SEVERITY_WEIGHTS: dict[str, int] = {
        "critical": 25,
        "high": 15,
        "medium": 8,
        "low": 3,
        "info": 0,
    }

    # Categories that indicate the Skill uses network
    _NETWORK_CATEGORIES: set[str] = {"network_risk", "data_exfiltration"}

    def calculate(self, findings: list[ScanFinding]) -> int:
        """Calculate a single Skill's security score.

        Score = max(0, 100 - sum(deductions)).  Range is [0, 100].

        Context-aware adjustments:
        - Missing "Network Access" section is upgraded from LOW (3) to
          MEDIUM (8) when the Skill has network-related findings.
        - Missing "Data Handling" section is upgraded from LOW (3) to
          MEDIUM (8) when the Skill has credential or data exfiltration
          findings.

        Args:
            findings: List of ScanFinding instances.

        Returns:
            Integer security score between 0 and 100.
        """
        has_network_findings = any(
            f.category.value in self._NETWORK_CATEGORIES for f in findings
        )
        has_data_findings = any(
            f.category.value in ("hardcoded_credential", "data_exfiltration")
            for f in findings
        )

        total_deduction = 0
        for f in findings:
            base = self.SEVERITY_WEIGHTS.get(f.severity.value, 0)

            # Upgrade missing section penalties when relevant activity detected
            if (
                f.category == FindingCategory.MISSING_SECTION
                and f.severity == FindingSeverity.LOW
            ):
                desc_lower = f.description.lower()
                if "network access" in desc_lower and has_network_findings:
                    base = self.SEVERITY_WEIGHTS["medium"]
                elif "data handling" in desc_lower and has_data_findings:
                    base = self.SEVERITY_WEIGHTS["medium"]

            total_deduction += base

        return max(0, 100 - total_deduction)

    def calculate_overall(self, results: list[SkillScanResult]) -> float:
        """Calculate the overall security score (arithmetic mean).

        Args:
            results: List of SkillScanResult instances.

        Returns:
            Arithmetic mean of all scores, or 100.0 if the list is empty.
        """
        if not results:
            return 100.0
        return sum(r.score for r in results) / len(results)


class ReportGenerator:
    """Scan report generator.

    Serializes ScanReport to JSON or human-readable text format.
    Supports ``lang`` parameter for i18n (``"en"`` / ``"zh"``).
    """

    def generate(self, report: ScanReport, output_format: str = "text", lang: str = "en") -> str:
        """Generate report output.

        Args:
            report: ScanReport data.
            output_format: ``"text"`` or ``"json"``.
            lang: Language code (``"en"`` or ``"zh"``).

        Returns:
            Formatted report string.
        """
        if output_format == "json":
            return self.to_json(report)
        return self.to_text(report, lang=lang)

    def to_json(self, report: ScanReport) -> str:
        """Serialize a ScanReport to JSON.

        Handles enum values by converting to their ``.value`` and
        dataclasses via ``dataclasses.asdict()``.
        """
        import dataclasses
        import json

        def _convert(obj: Any) -> Any:
            if isinstance(obj, Enum):
                return obj.value
            raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

        raw = dataclasses.asdict(report)
        return json.dumps(raw, default=_convert, indent=2, ensure_ascii=False)

    def _score_bar(self, score: int) -> str:
        """Render a visual score bar like [████████░░] 80."""
        filled = score // 10
        empty = 10 - filled
        return f"[{'█' * filled}{'░' * empty}] {score}"

    def _build_summary(self, report: ScanReport, lang: str = "en") -> list[str]:
        """Build a concise summary section for the text report."""
        lines: list[str] = []
        stats = report.severity_stats

        # Categorize skills by score
        critical_skills = [r for r in report.results if r.score < 50]
        warning_skills = [r for r in report.results if 50 <= r.score < 80]
        good_skills = [r for r in report.results if r.score >= 80]

        best = max(report.results, key=lambda r: r.score) if report.results else None
        worst = min(report.results, key=lambda r: r.score) if report.results else None

        lines.append("")
        lines.append(f"--- {_t(lang, 'summary')} ---")

        # Score distribution with visual bar
        lines.append(
            f"  {_t(lang, 'score_distribution')}: "
            f"🔴 {len(critical_skills)} {_t(lang, 'critical_label')} (<50) | "
            f"🟡 {len(warning_skills)} {_t(lang, 'warning_label')} (50-79) | "
            f"🟢 {len(good_skills)} {_t(lang, 'good_label')} (>=80)"
        )
        if best:
            lines.append(f"  {_t(lang, 'best')}:  {best.skill_name} {self._score_bar(best.score)}")
        if worst and worst.skill_name != (best.skill_name if best else ""):
            lines.append(f"  {_t(lang, 'worst')}: {worst.skill_name} {self._score_bar(worst.score)}")
        lines.append(
            f"  {_t(lang, 'findings')}: "
            f"🔴 {stats.critical} critical, "
            f"🟠 {stats.high} high, "
            f"🟡 {stats.medium} medium, "
            f"🔵 {stats.low} low, "
            f"⚪ {stats.info} info"
        )

        # Category breakdown
        category_counts: dict[str, int] = {}
        for result in report.results:
            for f in result.findings:
                cat = f.category.value
                category_counts[cat] = category_counts.get(cat, 0) + 1
        if category_counts:
            lines.append("")
            lines.append(f"  {_t(lang, 'by_category')}:")
            cat_labels = {
                "shell_injection": ("🐚", "Shell Injection" if lang == "en" else "Shell 注入"),
                "data_exfiltration": ("📤", "Data Exfiltration" if lang == "en" else "数据外泄"),
                "hardcoded_credential": ("🔑", "Hardcoded Credentials" if lang == "en" else "硬编码凭据"),
                "excessive_permission": ("🔓", "Excessive Permissions" if lang == "en" else "过度权限"),
                "prompt_injection": ("💉", "Prompt Injection" if lang == "en" else "提示词注入"),
                "missing_section": ("📄", "Missing Sections" if lang == "en" else "缺少章节"),
                "network_risk": ("🌐", "Network Risk" if lang == "en" else "网络风险"),
                "external_write": ("💾", "External Write" if lang == "en" else "外部写入"),
                "parse_error": ("⚠️", "Parse Error" if lang == "en" else "解析错误"),
                "file_error": ("📁", "File Error" if lang == "en" else "文件错误"),
            }
            for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
                icon, label = cat_labels.get(cat, ("•", cat))
                lines.append(f"    {icon} {label}: {count}")

        # Top issues quick list
        if critical_skills:
            lines.append("")
            lines.append(f"  {_t(lang, 'needs_attention')}:")
            for r in sorted(critical_skills, key=lambda x: x.score):
                critical_findings = [f for f in r.findings if f.severity == FindingSeverity.CRITICAL]
                desc = critical_findings[0].description if critical_findings else _t(lang, "multiple_issues")
                desc = _translate_finding(desc, lang)
                lines.append(f"    🚨 {r.skill_name} {self._score_bar(r.score)}: {desc}")

        return lines

    def _checklist_icon(self, val: bool) -> str:
        return "✅" if val else "❌"

    def to_text(self, report: ScanReport, lang: str = "en") -> str:
        """Format a ScanReport as human-readable text with summary."""
        lines: list[str] = []
        lines.append(_t(lang, "report_title"))
        lines.append(f"{_t(lang, 'scan_time')}: {report.scan_time}")
        lines.append(f"{_t(lang, 'skills_scanned')}: {report.skill_count}")
        lines.append(f"{_t(lang, 'overall_score')}: {self._score_bar(int(report.overall_score))}")

        # Add summary section
        lines.extend(self._build_summary(report, lang=lang))

        # Per-skill details
        lines.append("")
        lines.append(f"--- {_t(lang, 'details')} ---")
        for result in report.results:
            lines.append("")
            # Score with visual bar
            lines.append(f"  {result.skill_name} {self._score_bar(result.score)}")

            # Checklist
            cl = result.checklist
            cl_items = [
                (self._checklist_icon(cl.has_valid_frontmatter), "YAML Frontmatter"),
                (self._checklist_icon(cl.has_permission_declaration), _t(lang, "checklist_perms")),
                (self._checklist_icon(cl.has_permissions_section), "Permissions"),
                (self._checklist_icon(cl.has_data_handling_section), "Data Handling"),
                (self._checklist_icon(cl.has_network_access_section), "Network Access"),
            ]
            lines.append(f"    {_t(lang, 'checklist')}: {' | '.join(f'{icon} {name}' for icon, name in cl_items)}")

            if result.parse_error:
                lines.append(f"    {_t(lang, 'parse_error')}: {result.parse_error}")
            for finding in result.findings:
                severity_tag = finding.severity.value.upper()
                desc = _translate_finding(finding.description, lang)
                lines.append(f"    [{severity_tag}] {desc}")
                if finding.file_path or finding.line_number is not None:
                    parts: list[str] = []
                    if finding.file_path:
                        parts.append(f"{_t(lang, 'file')}: {finding.file_path}")
                    if finding.line_number is not None:
                        parts.append(f"{_t(lang, 'line')}: {finding.line_number}")
                    lines.append(f"      {', '.join(parts)}")
                if finding.recommendation:
                    rec = _translate_recommendation(finding.recommendation, lang)
                    lines.append(f"      {_t(lang, 'recommendation')}: {rec}")

        return "\n".join(lines)


class SkillScanner:
    """Skill security scanner main entry point.

    Coordinates the full scan workflow: discovery → parse → check → score → report.
    """

    # Security sections that should be present in SKILL.md
    _REQUIRED_SECTIONS: list[tuple[str, str]] = [
        ("Permissions", "has_permissions_section"),
        ("Data Handling", "has_data_handling_section"),
        ("Network Access", "has_network_access_section"),
    ]

    def __init__(self) -> None:
        self.parser = SkillMDParser()
        self.discovery = SkillDiscovery()
        self.script_analyzer = ScriptAnalyzer()
        self.network_analyzer = NetworkAnalyzer()
        self.secret_detector = SecretDetector()
        self.permission_checker = PermissionChecker()
        self.prompt_risk_checker = PromptRiskChecker()
        self.score_calculator = ScoreCalculator()
        self.report_generator = ReportGenerator()

    def scan(
        self,
        paths: list[str] | None = None,
        output_format: str = "text",
        min_score: int | None = None,
    ) -> ScanReport:
        """Execute the full scan workflow.

        Args:
            paths: Scan path list. ``None`` uses default paths.
            output_format: ``"text"`` or ``"json"``.
            min_score: Only include Skills with score below this value.

        Returns:
            ScanReport containing all scan results.
        """
        from datetime import datetime, timezone

        skill_dirs = self.discovery.discover_skills(paths)

        results: list[SkillScanResult] = []
        for skill_dir in skill_dirs:
            results.append(self.scan_single_skill(skill_dir))

        # Apply min_score filter
        if min_score is not None:
            results = [r for r in results if r.score < min_score]

        overall_score = self.score_calculator.calculate_overall(results)

        # Calculate severity stats from all findings
        stats = SeverityStats()
        for result in results:
            for finding in result.findings:
                severity_name = finding.severity.value
                current = getattr(stats, severity_name, 0)
                setattr(stats, severity_name, current + 1)

        return ScanReport(
            scan_time=datetime.now(timezone.utc).isoformat(),
            skill_count=len(results),
            results=results,
            overall_score=overall_score,
            severity_stats=stats,
            scanned_paths=[str(d) for d in skill_dirs],
        )

    def scan_single_skill(self, skill_dir: Path) -> SkillScanResult:
        """Scan a single Skill directory.

        Args:
            skill_dir: Directory containing SKILL.md.

        Returns:
            SkillScanResult for this Skill.
        """
        findings: list[ScanFinding] = []
        checklist = SecurityChecklist()
        parse_error: str | None = None

        # Step 1: Parse SKILL.md
        skill_md_path = SkillDiscovery._get_skill_md(skill_dir) or (skill_dir / "SKILL.md")
        parsed: ParsedSkill | None = None
        try:
            parsed = self.parser.parse(skill_md_path)
            checklist.has_valid_frontmatter = True
        except SkillParseError as exc:
            parse_error = str(exc)
            findings.append(
                ScanFinding(
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.PARSE_ERROR,
                    description=f"SKILL.md parse error: {exc}",
                    file_path="SKILL.md",
                    recommendation="Fix the SKILL.md file format (YAML frontmatter + Markdown).",
                )
            )
            # Return early with score 0
            return SkillScanResult(
                skill_name=skill_dir.name,
                skill_path=str(skill_dir),
                score=0,
                findings=findings,
                checklist=checklist,
                parse_error=parse_error,
            )

        # Step 2: Run ScriptAnalyzer
        try:
            findings.extend(self.script_analyzer.analyze_all(skill_dir))
        except Exception as exc:
            findings.append(
                ScanFinding(
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.FILE_ERROR,
                    description=f"ScriptAnalyzer error: {exc}",
                    file_path="SKILL.md",
                    recommendation="Check script files in the Skill directory.",
                )
            )

        # Step 3: Run NetworkAnalyzer on each script file
        try:
            for file_path in sorted(skill_dir.rglob("*")):
                if file_path.is_file() and file_path.suffix in ScriptAnalyzer.SUPPORTED_EXTENSIONS:
                    try:
                        findings.extend(self.network_analyzer.analyze(file_path))
                    except Exception as exc:
                        findings.append(
                            ScanFinding(
                                severity=FindingSeverity.INFO,
                                category=FindingCategory.FILE_ERROR,
                                description=f"NetworkAnalyzer error on {file_path.name}: {exc}",
                                file_path=str(file_path.relative_to(skill_dir)),
                                recommendation="Check the script file for issues.",
                            )
                        )
        except Exception as exc:
            findings.append(
                ScanFinding(
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.FILE_ERROR,
                    description=f"NetworkAnalyzer error: {exc}",
                    file_path="SKILL.md",
                    recommendation="Check script files in the Skill directory.",
                )
            )

        # Step 4: Run SecretDetector on SKILL.md + scripts
        try:
            findings.extend(self.secret_detector.detect(skill_md_path))
        except Exception as exc:
            findings.append(
                ScanFinding(
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.FILE_ERROR,
                    description=f"SecretDetector error on SKILL.md: {exc}",
                    file_path="SKILL.md",
                    recommendation="Check the SKILL.md file for issues.",
                )
            )
        try:
            for file_path in sorted(skill_dir.rglob("*")):
                if file_path.is_file() and file_path.suffix in ScriptAnalyzer.SUPPORTED_EXTENSIONS:
                    try:
                        findings.extend(self.secret_detector.detect(file_path))
                    except Exception as exc:
                        findings.append(
                            ScanFinding(
                                severity=FindingSeverity.INFO,
                                category=FindingCategory.FILE_ERROR,
                                description=f"SecretDetector error on {file_path.name}: {exc}",
                                file_path=str(file_path.relative_to(skill_dir)),
                                recommendation="Check the file for issues.",
                            )
                        )
        except Exception as exc:
            findings.append(
                ScanFinding(
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.FILE_ERROR,
                    description=f"SecretDetector error: {exc}",
                    file_path="SKILL.md",
                    recommendation="Check script files in the Skill directory.",
                )
            )

        # Step 5: Run PermissionChecker
        try:
            findings.extend(self.permission_checker.check(parsed))
            # Check if permission declaration exists
            clawdbot = parsed.metadata.get("metadata", {}).get("clawdbot", {})
            if clawdbot.get("requires"):
                checklist.has_permission_declaration = True
        except Exception as exc:
            findings.append(
                ScanFinding(
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.FILE_ERROR,
                    description=f"PermissionChecker error: {exc}",
                    file_path="SKILL.md",
                    recommendation="Check the SKILL.md permission declarations.",
                )
            )

        # Step 6: Run PromptRiskChecker
        try:
            findings.extend(self.prompt_risk_checker.check(parsed.instructions))
        except Exception as exc:
            findings.append(
                ScanFinding(
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.FILE_ERROR,
                    description=f"PromptRiskChecker error: {exc}",
                    file_path="SKILL.md",
                    recommendation="Check the SKILL.md instructions section.",
                )
            )

        # Step 7: Check security sections
        for section_name, checklist_attr in self._REQUIRED_SECTIONS:
            if section_name in parsed.sections:
                setattr(checklist, checklist_attr, True)
            else:
                findings.append(
                    ScanFinding(
                        severity=FindingSeverity.LOW,
                        category=FindingCategory.MISSING_SECTION,
                        description=f"Missing security section: {section_name}",
                        file_path="SKILL.md",
                        recommendation=f"Add a '{section_name}' section to SKILL.md to document security considerations.",
                    )
                )

        # Step 8: Calculate score
        score = self.score_calculator.calculate(findings)

        return SkillScanResult(
            skill_name=parsed.name,
            skill_path=str(skill_dir),
            score=score,
            findings=findings,
            checklist=checklist,
            parse_error=parse_error,
        )
