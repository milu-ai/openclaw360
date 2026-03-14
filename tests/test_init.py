"""Tests for openclaw360 package exports."""

import openclaw360


def test_version():
    assert openclaw360.__version__ == "0.1.9"


def test_all_exports_defined():
    expected = [
        "OpenClaw360Skill",
        "GuardConfig",
        "Decision",
        "SecurityResult",
        "ThreatType",
        "ThreatDetection",
        "RiskScore",
    ]
    for name in expected:
        assert name in openclaw360.__all__
        assert hasattr(openclaw360, name)


def test_direct_imports():
    from openclaw360 import (
        OpenClaw360Skill,
        Decision,
        GuardConfig,
        RiskScore,
        SecurityResult,
        ThreatDetection,
        ThreatType,
    )

    assert Decision.ALLOW.value == "allow"
    assert Decision.BLOCK.value == "block"
    assert Decision.CONFIRM.value == "confirm"

    config = GuardConfig()
    assert config.prompt_risk_threshold == 0.7

    result = SecurityResult(
        decision=Decision.ALLOW, risk_score=0.0, threats=[]
    )
    assert result.risk_score == 0.0

    assert ThreatType.PROMPT_INJECTION.value == "prompt_injection"

    score = RiskScore(
        action_score=0.5, data_score=0.3, context_score=0.1, total=0.35
    )
    assert score.total == 0.35
