"""Unit tests for GuardConfig validation."""

import pytest
from pydantic import ValidationError

from openclaw360.config import GuardConfig


class TestGuardConfigDefaults:
    """Test that default configuration is valid."""

    def test_default_config_is_valid(self):
        config = GuardConfig()
        assert config.prompt_risk_threshold == 0.7
        assert config.high_risk_threshold == 0.8
        assert config.medium_risk_threshold == 0.5
        assert config.audit_retention_days == 90

    def test_default_tool_risk_weights_sum_to_one(self):
        config = GuardConfig()
        assert abs(sum(config.tool_risk_weights.values()) - 1.0) < 1e-9


class TestPromptRiskThreshold:
    """Requirement 8.1: prompt_risk_threshold in [0.0, 1.0]."""

    def test_valid_boundary_zero(self):
        config = GuardConfig(prompt_risk_threshold=0.0)
        assert config.prompt_risk_threshold == 0.0

    def test_valid_boundary_one(self):
        config = GuardConfig(prompt_risk_threshold=1.0)
        assert config.prompt_risk_threshold == 1.0

    def test_invalid_negative(self):
        with pytest.raises(ValidationError, match="prompt_risk_threshold"):
            GuardConfig(prompt_risk_threshold=-0.1)

    def test_invalid_above_one(self):
        with pytest.raises(ValidationError, match="prompt_risk_threshold"):
            GuardConfig(prompt_risk_threshold=1.1)


class TestToolRiskWeights:
    """Requirement 8.2: tool_risk_weights values sum to 1.0."""

    def test_valid_custom_weights(self):
        config = GuardConfig(tool_risk_weights={"a": 0.5, "b": 0.3, "c": 0.2})
        assert abs(sum(config.tool_risk_weights.values()) - 1.0) < 1e-9

    def test_invalid_weights_sum_not_one(self):
        with pytest.raises(ValidationError, match="tool_risk_weights"):
            GuardConfig(tool_risk_weights={"a": 0.5, "b": 0.3})

    def test_invalid_weights_sum_exceeds_one(self):
        with pytest.raises(ValidationError, match="tool_risk_weights"):
            GuardConfig(tool_risk_weights={"a": 0.6, "b": 0.6})


class TestThresholdOrdering:
    """Requirement 8.3: high_risk_threshold > medium_risk_threshold."""

    def test_valid_ordering(self):
        config = GuardConfig(high_risk_threshold=0.9, medium_risk_threshold=0.4)
        assert config.high_risk_threshold > config.medium_risk_threshold

    def test_invalid_equal_thresholds(self):
        with pytest.raises(ValidationError, match="high_risk_threshold"):
            GuardConfig(high_risk_threshold=0.5, medium_risk_threshold=0.5)

    def test_invalid_reversed_thresholds(self):
        with pytest.raises(ValidationError, match="high_risk_threshold"):
            GuardConfig(high_risk_threshold=0.3, medium_risk_threshold=0.7)


class TestAuditRetentionDays:
    """Requirement 8.4: audit_retention_days > 0."""

    def test_valid_positive(self):
        config = GuardConfig(audit_retention_days=1)
        assert config.audit_retention_days == 1

    def test_invalid_zero(self):
        with pytest.raises(ValidationError, match="audit_retention_days"):
            GuardConfig(audit_retention_days=0)

    def test_invalid_negative(self):
        with pytest.raises(ValidationError, match="audit_retention_days"):
            GuardConfig(audit_retention_days=-10)


class TestValidationErrorMessages:
    """Requirement 8.5: clear error messages on validation failure."""

    def test_error_message_includes_field_name(self):
        with pytest.raises(ValidationError) as exc_info:
            GuardConfig(prompt_risk_threshold=2.0)
        assert "prompt_risk_threshold" in str(exc_info.value)

    def test_error_message_includes_actual_value(self):
        with pytest.raises(ValidationError) as exc_info:
            GuardConfig(audit_retention_days=-5)
        assert "-5" in str(exc_info.value)
