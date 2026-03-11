"""Configuration management and validation for OpenClaw360."""

import math
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class GuardConfig(BaseModel):
    """Global configuration for OpenClaw360 with strict validation.

    Validation rules:
    - prompt_risk_threshold must be in [0.0, 1.0]
    - tool_risk_weights values must sum to 1.0
    - high_risk_threshold must be greater than medium_risk_threshold
    - audit_retention_days must be greater than 0
    """

    # Identity configuration
    identity_path: str = "~/.openclaw360/identity.json"

    # Prompt security configuration
    prompt_risk_threshold: float = 0.7
    enable_llm_classifier: bool = True
    rules_path: str = "~/.openclaw360/rules/"

    # Tool Guard configuration
    tool_risk_weights: dict[str, float] = Field(
        default={"action": 0.4, "data": 0.35, "context": 0.25}
    )
    high_risk_threshold: float = 0.8
    medium_risk_threshold: float = 0.5

    # DLP configuration
    dlp_enabled: bool = True
    zero_knowledge_logging: bool = True

    # Audit configuration
    audit_log_path: str = "~/.openclaw360/audit/"
    audit_retention_days: int = 90

    # Policy configuration
    default_policy: Literal["strict", "standard", "permissive"] = "standard"

    # Rule update configuration
    rule_update_url: str = "https://rules.openclaw360.io/v1"
    rule_check_interval: int = 3600
    auto_update_enabled: bool = True
    rule_signing_public_key: str = ""

    @field_validator("prompt_risk_threshold")
    @classmethod
    def validate_prompt_risk_threshold(cls, v: float) -> float:
        if not (0.0 <= v <= 1.0):
            raise ValueError(
                f"prompt_risk_threshold must be in [0.0, 1.0], got {v}"
            )
        return v

    @field_validator("audit_retention_days")
    @classmethod
    def validate_audit_retention_days(cls, v: int) -> int:
        if v <= 0:
            raise ValueError(
                f"audit_retention_days must be greater than 0, got {v}"
            )
        return v

    @field_validator("tool_risk_weights")
    @classmethod
    def validate_tool_risk_weights_sum(cls, v: dict[str, float]) -> dict[str, float]:
        weight_sum = sum(v.values())
        if not math.isclose(weight_sum, 1.0, abs_tol=1e-9):
            raise ValueError(
                f"tool_risk_weights values must sum to 1.0, got {weight_sum}"
            )
        return v

    @model_validator(mode="after")
    def validate_threshold_ordering(self) -> "GuardConfig":
        if self.high_risk_threshold <= self.medium_risk_threshold:
            raise ValueError(
                f"high_risk_threshold ({self.high_risk_threshold}) must be "
                f"greater than medium_risk_threshold ({self.medium_risk_threshold})"
            )
        return self
