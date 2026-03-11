"""Core data models for OpenClaw360."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Decision(Enum):
    """Security decision outcomes."""

    ALLOW = "allow"
    BLOCK = "block"
    CONFIRM = "confirm"


@dataclass
class SecurityResult:
    """Result of a security check."""

    decision: Decision
    risk_score: float  # 0.0 ~ 1.0
    threats: list[str]
    reason: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


class ThreatType(Enum):
    """Types of security threats."""

    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    SOCIAL_ENGINEERING = "social_engineering"
    DATA_EXFILTRATION = "data_exfiltration"
    TOOL_ABUSE = "tool_abuse"


@dataclass
class ThreatDetection:
    """A detected threat from scanning."""

    threat_type: ThreatType
    confidence: float  # 0.0 ~ 1.0
    matched_pattern: Optional[str] = None
    description: Optional[str] = None


class SensitiveDataType(Enum):
    """Types of sensitive data detected by DLP."""

    API_KEY = "api_key"
    PASSWORD = "password"
    TOKEN = "token"
    SSH_KEY = "ssh_key"
    PRIVATE_KEY = "private_key"
    CREDIT_CARD = "credit_card"
    EMAIL = "email"
    IP_ADDRESS = "ip_address"


@dataclass
class SensitiveDataMatch:
    """A match of sensitive data found in text."""

    data_type: SensitiveDataType
    location: tuple[int, int]  # (start, end)
    masked_value: str
    hash_value: str  # SHA-256 hash


@dataclass
class ToolPermission:
    """Permission configuration for a tool."""

    tool_name: str
    allowed_actions: list[str]
    max_risk_level: str  # "low" | "medium" | "high"
    requires_confirmation: bool = False


@dataclass
class RiskScore:
    """Composite risk score from multiple dimensions."""

    action_score: float  # 0.0 ~ 1.0
    data_score: float  # 0.0 ~ 1.0
    context_score: float  # 0.0 ~ 1.0
    total: float  # 0.0 ~ 1.0


@dataclass
class AuditEvent:
    """An audit log entry for agent actions."""

    agent_id: str
    timestamp: str  # ISO 8601
    action: str  # "prompt" | "tool_call" | "output"
    tool: Optional[str]
    risk_score: float
    decision: Decision
    signature: bytes
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackPattern:
    """A rule for detecting a specific attack pattern."""

    id: str
    name: str
    category: ThreatType
    severity: str  # "critical" | "high" | "medium" | "low"
    patterns: list[str]  # regex patterns
    description: str
    examples: list[str]
    enabled: bool = True


@dataclass
class RulePackage:
    """A versioned package of attack detection rules."""

    version: str  # semver
    rules: list[AttackPattern]
    signature: bytes  # Ed25519 signature
    published_at: str  # ISO 8601
    changelog: str


@dataclass
class AgentIdentity:
    """Identity of an AI agent based on Ed25519 keys."""

    agent_id: str  # UUID v4
    public_key: bytes  # Ed25519 public key
    created_at: str  # ISO 8601
    framework: str  # e.g. "openclaw"
    version: str  # e.g. "0.1.0"
