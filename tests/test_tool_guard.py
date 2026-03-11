"""Unit tests for RiskEngine in openclaw360.tool_guard."""

import pytest

from openclaw360.config import GuardConfig
from openclaw360.models import RiskScore
from openclaw360.models import ToolPermission
from openclaw360.tool_guard import (
    AIRBACEngine,
    DANGEROUS_PATTERNS,
    SENSITIVE_DATA_KEYWORDS,
    TOOL_RISK_BASELINE,
    RiskEngine,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def config() -> GuardConfig:
    return GuardConfig()


@pytest.fixture
def engine(config: GuardConfig) -> RiskEngine:
    return RiskEngine(config)


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestRiskEngineInit:
    def test_uses_config_weights(self, config: GuardConfig):
        eng = RiskEngine(config)
        assert eng.weights == config.tool_risk_weights

    def test_custom_weights(self):
        cfg = GuardConfig(tool_risk_weights={"action": 0.5, "data": 0.3, "context": 0.2})
        eng = RiskEngine(cfg)
        assert eng.weights["action"] == 0.5


# ---------------------------------------------------------------------------
# TOOL_RISK_BASELINE constants
# ---------------------------------------------------------------------------


class TestToolRiskBaseline:
    def test_shell_execute_highest(self):
        assert TOOL_RISK_BASELINE["shell_execute"] == 0.9

    def test_file_read_lowest(self):
        assert TOOL_RISK_BASELINE["file_read"] == 0.3

    def test_all_baselines_in_range(self):
        for name, score in TOOL_RISK_BASELINE.items():
            assert 0.0 <= score <= 1.0, f"{name} baseline out of range"

    def test_expected_tools_present(self):
        expected = {
            "shell_execute", "process_spawn", "eval",
            "file_write", "file_delete", "file_read", "file_move", "file_chmod",
            "browser_navigate", "network_request", "http_post", "http_get",
            "dns_lookup", "ssh_connect",
            "database_query", "database_write", "database_drop",
            "clipboard_access", "env_read", "env_write", "registry_write",
            "cron_schedule", "service_restart",
            "code_execute", "plugin_install", "package_install",
        }
        assert set(TOOL_RISK_BASELINE.keys()) == expected


# ---------------------------------------------------------------------------
# calculate() — returns RiskScore
# ---------------------------------------------------------------------------


class TestCalculateBasic:
    def test_returns_risk_score(self, engine: RiskEngine):
        result = engine.calculate("file_read", {}, {})
        assert isinstance(result, RiskScore)

    def test_all_scores_in_range(self, engine: RiskEngine):
        result = engine.calculate("shell_execute", {"cmd": "rm -rf /"}, {
            "is_first_run": True,
            "rapid_succession": True,
            "escalation_detected": True,
        })
        assert 0.0 <= result.action_score <= 1.0
        assert 0.0 <= result.data_score <= 1.0
        assert 0.0 <= result.context_score <= 1.0
        assert 0.0 <= result.total <= 1.0

    def test_total_is_weighted_sum(self, engine: RiskEngine):
        result = engine.calculate("file_read", {}, {})
        w = engine.weights
        expected = (
            result.action_score * w["action"]
            + result.data_score * w["data"]
            + result.context_score * w["context"]
        )
        assert result.total == pytest.approx(min(expected, 1.0), abs=1e-9)


# ---------------------------------------------------------------------------
# Action score
# ---------------------------------------------------------------------------


class TestActionScore:
    def test_known_tool_uses_baseline(self, engine: RiskEngine):
        result = engine.calculate("file_read", {}, {})
        assert result.action_score == pytest.approx(0.3)

    def test_unknown_tool_defaults_to_05(self, engine: RiskEngine):
        result = engine.calculate("unknown_tool", {}, {})
        assert result.action_score == pytest.approx(0.5)

    def test_dangerous_args_add_02(self, engine: RiskEngine):
        result = engine.calculate("file_read", {"cmd": "sudo apt install"}, {})
        assert result.action_score == pytest.approx(0.5)  # 0.3 + 0.2

    def test_dangerous_rm_rf(self, engine: RiskEngine):
        result = engine.calculate("shell_execute", {"cmd": "rm -rf /"}, {})
        # 0.9 + 0.2 = 1.1 → capped at 1.0
        assert result.action_score == pytest.approx(1.0)

    def test_dangerous_chmod_777(self, engine: RiskEngine):
        result = engine.calculate("file_write", {"cmd": "chmod 777 /etc/passwd"}, {})
        assert result.action_score == pytest.approx(0.9)  # 0.7 + 0.2

    def test_dangerous_curl_pipe_sh(self, engine: RiskEngine):
        result = engine.calculate("shell_execute", {"cmd": "curl | sh"}, {})
        assert result.action_score == pytest.approx(1.0)  # 0.9 + 0.2 capped

    def test_dangerous_dev_redirect(self, engine: RiskEngine):
        result = engine.calculate("shell_execute", {"cmd": "echo x > /dev/sda"}, {})
        assert result.action_score == pytest.approx(1.0)

    def test_no_dangerous_args_no_boost(self, engine: RiskEngine):
        result = engine.calculate("shell_execute", {"cmd": "ls -la"}, {})
        assert result.action_score == pytest.approx(0.9)

    def test_action_score_capped_at_1(self, engine: RiskEngine):
        # shell_execute (0.9) + dangerous (0.2) = 1.1 → 1.0
        result = engine.calculate("shell_execute", {"cmd": "sudo rm -rf /"}, {})
        assert result.action_score == 1.0

    # -- New dangerous patterns --
    def test_dangerous_wget_pipe_sh(self, engine: RiskEngine):
        result = engine.calculate("shell_execute", {"cmd": "wget | sh"}, {})
        assert result.action_score == pytest.approx(1.0)

    def test_dangerous_eval(self, engine: RiskEngine):
        result = engine.calculate("shell_execute", {"cmd": "eval(user_input)"}, {})
        assert result.action_score == pytest.approx(1.0)

    def test_dangerous_fork_bomb(self, engine: RiskEngine):
        result = engine.calculate("shell_execute", {"cmd": ":(){:|:&};:"}, {})
        assert result.action_score == pytest.approx(1.0)

    def test_dangerous_dd(self, engine: RiskEngine):
        result = engine.calculate("shell_execute", {"cmd": "dd if=/dev/zero of=/dev/sda"}, {})
        assert result.action_score == pytest.approx(1.0)

    def test_dangerous_netcat(self, engine: RiskEngine):
        result = engine.calculate("shell_execute", {"cmd": "nc -l 4444"}, {})
        assert result.action_score == pytest.approx(1.0)

    def test_dangerous_base64_decode_sh(self, engine: RiskEngine):
        result = engine.calculate("shell_execute", {"cmd": "echo payload | base64 -d | sh"}, {})
        assert result.action_score == pytest.approx(1.0)

    # -- New tool baselines --
    def test_database_drop_highest(self, engine: RiskEngine):
        result = engine.calculate("database_drop", {}, {})
        assert result.action_score == pytest.approx(0.95)

    def test_eval_tool_high(self, engine: RiskEngine):
        result = engine.calculate("eval", {}, {})
        assert result.action_score == pytest.approx(0.95)

    def test_ssh_connect_high(self, engine: RiskEngine):
        result = engine.calculate("ssh_connect", {}, {})
        assert result.action_score == pytest.approx(0.8)

    def test_file_delete_high(self, engine: RiskEngine):
        result = engine.calculate("file_delete", {}, {})
        assert result.action_score == pytest.approx(0.8)


# ---------------------------------------------------------------------------
# Data score
# ---------------------------------------------------------------------------


class TestDataScore:
    def test_no_sensitive_data_zero(self, engine: RiskEngine):
        result = engine.calculate("file_read", {"path": "/tmp/data.txt"}, {})
        assert result.data_score == pytest.approx(0.0)

    def test_one_keyword_02(self, engine: RiskEngine):
        result = engine.calculate("file_write", {"content": "my password is 123"}, {})
        assert result.data_score == pytest.approx(0.2)

    def test_two_keywords_04(self, engine: RiskEngine):
        result = engine.calculate("file_write", {"content": "password and token here"}, {})
        assert result.data_score == pytest.approx(0.4)

    def test_many_keywords_capped_at_1(self, engine: RiskEngine):
        # Construct args with many sensitive keywords
        args = {"content": "password secret api_key token private_key credential"}
        result = engine.calculate("file_write", args, {})
        assert result.data_score <= 1.0

    def test_case_insensitive_detection(self, engine: RiskEngine):
        result = engine.calculate("file_write", {"content": "PASSWORD=abc"}, {})
        assert result.data_score >= 0.2

    def test_api_key_detected(self, engine: RiskEngine):
        result = engine.calculate("network_request", {"header": "api_key: sk-123"}, {})
        assert result.data_score >= 0.2


# ---------------------------------------------------------------------------
# Context score
# ---------------------------------------------------------------------------


class TestContextScore:
    def test_empty_context_zero(self, engine: RiskEngine):
        result = engine.calculate("file_read", {}, {})
        assert result.context_score == pytest.approx(0.0)

    def test_first_run_01(self, engine: RiskEngine):
        result = engine.calculate("file_read", {}, {"is_first_run": True})
        assert result.context_score == pytest.approx(0.1)

    def test_rapid_succession_02(self, engine: RiskEngine):
        result = engine.calculate("file_read", {}, {"rapid_succession": True})
        assert result.context_score == pytest.approx(0.2)

    def test_escalation_detected_03(self, engine: RiskEngine):
        result = engine.calculate("file_read", {}, {"escalation_detected": True})
        assert result.context_score == pytest.approx(0.3)

    def test_all_factors_combined(self, engine: RiskEngine):
        ctx = {"is_first_run": True, "rapid_succession": True, "escalation_detected": True}
        result = engine.calculate("file_read", {}, ctx)
        # 0.1 + 0.2 + 0.3 = 0.6
        assert result.context_score == pytest.approx(0.6)

    def test_context_score_capped_at_1(self, engine: RiskEngine):
        # Even with all factors, max is 0.6 which is < 1.0
        # But the cap logic should still work
        ctx = {"is_first_run": True, "rapid_succession": True, "escalation_detected": True}
        result = engine.calculate("file_read", {}, ctx)
        assert result.context_score <= 1.0

    def test_false_flags_ignored(self, engine: RiskEngine):
        ctx = {"is_first_run": False, "rapid_succession": False, "escalation_detected": False}
        result = engine.calculate("file_read", {}, ctx)
        assert result.context_score == pytest.approx(0.0)

    def test_missing_flags_treated_as_false(self, engine: RiskEngine):
        result = engine.calculate("file_read", {}, {"unrelated_key": True})
        assert result.context_score == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# Total score — weighted formula
# ---------------------------------------------------------------------------


class TestTotalScore:
    def test_low_risk_tool_no_context(self, engine: RiskEngine):
        result = engine.calculate("file_read", {}, {})
        # action=0.3, data=0.0, context=0.0
        # total = 0.3*0.4 + 0.0*0.35 + 0.0*0.25 = 0.12
        assert result.total == pytest.approx(0.12)

    def test_high_risk_tool_dangerous_args(self, engine: RiskEngine):
        result = engine.calculate("shell_execute", {"cmd": "rm -rf /"}, {})
        # action=1.0, data=0.0, context=0.0
        # total = 1.0*0.4 = 0.4
        assert result.total == pytest.approx(0.4)

    def test_total_capped_at_1(self, engine: RiskEngine):
        # Max possible: action=1.0, data=1.0, context=1.0
        # total = 1.0*0.4 + 1.0*0.35 + 1.0*0.25 = 1.0
        # With weights summing to 1.0 and all scores at 1.0, total = 1.0
        args = {"content": "password secret api_key token private_key credential"}
        ctx = {"is_first_run": True, "rapid_succession": True, "escalation_detected": True}
        result = engine.calculate("shell_execute", {"cmd": "sudo rm -rf /", **args}, ctx)
        assert result.total <= 1.0

    def test_custom_weights_affect_total(self):
        cfg = GuardConfig(tool_risk_weights={"action": 0.8, "data": 0.1, "context": 0.1})
        eng = RiskEngine(cfg)
        result = eng.calculate("shell_execute", {}, {})
        # action=0.9, data=0.0, context=0.0
        # total = 0.9*0.8 = 0.72
        assert result.total == pytest.approx(0.72)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_args(self, engine: RiskEngine):
        result = engine.calculate("file_read", {}, {})
        assert isinstance(result, RiskScore)

    def test_empty_tool_name(self, engine: RiskEngine):
        result = engine.calculate("", {}, {})
        # Unknown tool → baseline 0.5
        assert result.action_score == pytest.approx(0.5)

    def test_nested_args_with_dangerous_pattern(self, engine: RiskEngine):
        args = {"nested": {"deep": {"cmd": "sudo reboot"}}}
        result = engine.calculate("shell_execute", args, {})
        assert result.action_score == pytest.approx(1.0)  # 0.9 + 0.2 capped

    def test_args_with_multiple_dangerous_patterns(self, engine: RiskEngine):
        args = {"cmd": "sudo rm -rf / && chmod 777 /etc"}
        result = engine.calculate("shell_execute", args, {})
        # Still only +0.2 regardless of how many patterns match
        assert result.action_score == pytest.approx(1.0)


# ===========================================================================
# AIRBACEngine tests
# ===========================================================================


@pytest.fixture
def rbac(config: GuardConfig) -> AIRBACEngine:
    return AIRBACEngine(config)


def _make_permission(
    tool: str = "file_read",
    actions: list[str] | None = None,
    risk: str = "low",
) -> ToolPermission:
    return ToolPermission(
        tool_name=tool,
        allowed_actions=actions if actions is not None else ["read"],
        max_risk_level=risk,
    )


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestAIRBACEngineInit:
    def test_stores_config(self, config: GuardConfig):
        eng = AIRBACEngine(config)
        assert eng.config is config

    def test_starts_with_empty_permissions(self, rbac: AIRBACEngine):
        assert rbac._permissions == {}


# ---------------------------------------------------------------------------
# check_permission
# ---------------------------------------------------------------------------


class TestCheckPermission:
    def test_no_permissions_returns_false(self, rbac: AIRBACEngine):
        assert rbac.check_permission("agent-1", "file_read", "read") is False

    def test_unknown_agent_returns_false(self, rbac: AIRBACEngine):
        rbac.grant_permission("agent-1", _make_permission())
        assert rbac.check_permission("agent-2", "file_read", "read") is False

    def test_unknown_tool_returns_false(self, rbac: AIRBACEngine):
        rbac.grant_permission("agent-1", _make_permission("file_read", ["read"]))
        assert rbac.check_permission("agent-1", "file_write", "write") is False

    def test_action_not_in_allowed_returns_false(self, rbac: AIRBACEngine):
        rbac.grant_permission("agent-1", _make_permission("file_read", ["read"]))
        assert rbac.check_permission("agent-1", "file_read", "write") is False

    def test_allowed_action_returns_true(self, rbac: AIRBACEngine):
        rbac.grant_permission("agent-1", _make_permission("file_read", ["read"]))
        assert rbac.check_permission("agent-1", "file_read", "read") is True

    def test_multiple_allowed_actions(self, rbac: AIRBACEngine):
        rbac.grant_permission(
            "agent-1",
            _make_permission("file_write", ["read", "write", "delete"]),
        )
        assert rbac.check_permission("agent-1", "file_write", "read") is True
        assert rbac.check_permission("agent-1", "file_write", "write") is True
        assert rbac.check_permission("agent-1", "file_write", "delete") is True
        assert rbac.check_permission("agent-1", "file_write", "execute") is False


# ---------------------------------------------------------------------------
# grant_permission
# ---------------------------------------------------------------------------


class TestGrantPermission:
    def test_grant_creates_agent_entry(self, rbac: AIRBACEngine):
        rbac.grant_permission("agent-1", _make_permission())
        assert "agent-1" in rbac._permissions

    def test_grant_stores_permission(self, rbac: AIRBACEngine):
        perm = _make_permission("shell_execute", ["execute"], "high")
        rbac.grant_permission("agent-1", perm)
        assert rbac._permissions["agent-1"]["shell_execute"] is perm

    def test_grant_multiple_tools(self, rbac: AIRBACEngine):
        rbac.grant_permission("agent-1", _make_permission("file_read", ["read"]))
        rbac.grant_permission("agent-1", _make_permission("file_write", ["write"]))
        assert len(rbac._permissions["agent-1"]) == 2

    def test_grant_overwrites_existing(self, rbac: AIRBACEngine):
        rbac.grant_permission("agent-1", _make_permission("file_read", ["read"]))
        new_perm = _make_permission("file_read", ["read", "write"])
        rbac.grant_permission("agent-1", new_perm)
        assert rbac._permissions["agent-1"]["file_read"] is new_perm
        assert rbac.check_permission("agent-1", "file_read", "write") is True

    def test_grant_multiple_agents(self, rbac: AIRBACEngine):
        rbac.grant_permission("agent-1", _make_permission("file_read", ["read"]))
        rbac.grant_permission("agent-2", _make_permission("file_write", ["write"]))
        assert rbac.check_permission("agent-1", "file_read", "read") is True
        assert rbac.check_permission("agent-2", "file_write", "write") is True
        assert rbac.check_permission("agent-1", "file_write", "write") is False


# ---------------------------------------------------------------------------
# revoke_permission
# ---------------------------------------------------------------------------


class TestRevokePermission:
    def test_revoke_removes_tool(self, rbac: AIRBACEngine):
        rbac.grant_permission("agent-1", _make_permission("file_read", ["read"]))
        rbac.revoke_permission("agent-1", "file_read")
        assert rbac.check_permission("agent-1", "file_read", "read") is False

    def test_revoke_unknown_agent_no_error(self, rbac: AIRBACEngine):
        rbac.revoke_permission("nonexistent", "file_read")  # should not raise

    def test_revoke_unknown_tool_no_error(self, rbac: AIRBACEngine):
        rbac.grant_permission("agent-1", _make_permission("file_read", ["read"]))
        rbac.revoke_permission("agent-1", "file_write")  # should not raise
        # Original permission still intact
        assert rbac.check_permission("agent-1", "file_read", "read") is True

    def test_revoke_only_affects_target_tool(self, rbac: AIRBACEngine):
        rbac.grant_permission("agent-1", _make_permission("file_read", ["read"]))
        rbac.grant_permission("agent-1", _make_permission("file_write", ["write"]))
        rbac.revoke_permission("agent-1", "file_read")
        assert rbac.check_permission("agent-1", "file_read", "read") is False
        assert rbac.check_permission("agent-1", "file_write", "write") is True

    def test_revoke_only_affects_target_agent(self, rbac: AIRBACEngine):
        perm = _make_permission("file_read", ["read"])
        rbac.grant_permission("agent-1", perm)
        rbac.grant_permission("agent-2", _make_permission("file_read", ["read"]))
        rbac.revoke_permission("agent-1", "file_read")
        assert rbac.check_permission("agent-1", "file_read", "read") is False
        assert rbac.check_permission("agent-2", "file_read", "read") is True


# ===========================================================================
# ToolGuard tests
# ===========================================================================

from openclaw360.models import Decision, SecurityResult
from openclaw360.tool_guard import ToolGuard


@pytest.fixture
def guard(config: GuardConfig) -> ToolGuard:
    return ToolGuard(config)


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestToolGuardInit:
    def test_stores_config(self, config: GuardConfig):
        tg = ToolGuard(config)
        assert tg.config is config

    def test_exposes_rbac(self, guard: ToolGuard):
        assert isinstance(guard.rbac, AIRBACEngine)

    def test_exposes_risk_engine(self, guard: ToolGuard):
        assert isinstance(guard.risk_engine, RiskEngine)


# ---------------------------------------------------------------------------
# evaluate — returns SecurityResult
# ---------------------------------------------------------------------------


class TestToolGuardEvaluateBasic:
    def test_returns_security_result(self, guard: ToolGuard):
        result = guard.evaluate("file_read", {}, {})
        assert isinstance(result, SecurityResult)

    def test_risk_score_in_range(self, guard: ToolGuard):
        result = guard.evaluate("shell_execute", {"cmd": "rm -rf /"}, {})
        assert 0.0 <= result.risk_score <= 1.0

    def test_metadata_contains_breakdown(self, guard: ToolGuard):
        result = guard.evaluate("file_read", {}, {})
        assert "action_score" in result.metadata
        assert "data_score" in result.metadata
        assert "context_score" in result.metadata
        assert "total" in result.metadata


# ---------------------------------------------------------------------------
# evaluate — three-tier risk decision (no RBAC context)
# ---------------------------------------------------------------------------


class TestToolGuardRiskDecision:
    def test_low_risk_allows(self, guard: ToolGuard):
        # file_read with no args/context → total ≈ 0.12 < 0.5 (medium)
        result = guard.evaluate("file_read", {}, {})
        assert result.decision == Decision.ALLOW
        assert result.risk_score < guard.config.medium_risk_threshold

    def test_high_risk_blocks(self, guard: ToolGuard):
        # Use custom config with low thresholds to trigger BLOCK
        cfg = GuardConfig(high_risk_threshold=0.3, medium_risk_threshold=0.1)
        tg = ToolGuard(cfg)
        result = tg.evaluate("shell_execute", {}, {})
        # shell_execute action_score=0.9, total=0.9*0.4=0.36 >= 0.3
        assert result.decision == Decision.BLOCK
        assert "high_risk_tool" in result.threats

    def test_medium_risk_confirms(self, guard: ToolGuard):
        # Use custom config to get CONFIRM range
        cfg = GuardConfig(high_risk_threshold=0.8, medium_risk_threshold=0.1)
        tg = ToolGuard(cfg)
        result = tg.evaluate("file_read", {}, {})
        # file_read total ≈ 0.12, which is >= 0.1 and < 0.8
        assert result.decision == Decision.CONFIRM
        assert "medium_risk_tool" in result.threats

    def test_allow_has_no_threats(self, guard: ToolGuard):
        result = guard.evaluate("file_read", {}, {})
        assert result.decision == Decision.ALLOW
        assert result.threats == []

    def test_reason_is_set(self, guard: ToolGuard):
        result = guard.evaluate("file_read", {}, {})
        assert result.reason is not None
        assert len(result.reason) > 0


# ---------------------------------------------------------------------------
# evaluate — RBAC priority
# ---------------------------------------------------------------------------


class TestToolGuardRBAC:
    def test_rbac_denied_blocks(self, guard: ToolGuard):
        # Agent has no permissions → RBAC denies
        context = {"agent_id": "agent-1", "action": "execute"}
        result = guard.evaluate("shell_execute", {}, context)
        assert result.decision == Decision.BLOCK
        assert "rbac_denied" in result.threats

    def test_rbac_denied_risk_score_zero(self, guard: ToolGuard):
        context = {"agent_id": "agent-1", "action": "execute"}
        result = guard.evaluate("shell_execute", {}, context)
        assert result.risk_score == 0.0

    def test_rbac_allowed_proceeds_to_risk(self, guard: ToolGuard):
        # Grant permission first
        guard.rbac.grant_permission(
            "agent-1",
            _make_permission("file_read", ["read"]),
        )
        context = {"agent_id": "agent-1", "action": "read"}
        result = guard.evaluate("file_read", {}, context)
        # RBAC passes, risk decides
        assert result.decision == Decision.ALLOW
        assert "rbac_denied" not in result.threats

    def test_rbac_denied_overrides_low_risk(self, guard: ToolGuard):
        # file_read is low risk, but RBAC denies
        context = {"agent_id": "agent-1", "action": "read"}
        result = guard.evaluate("file_read", {}, context)
        assert result.decision == Decision.BLOCK
        assert "rbac_denied" in result.threats

    def test_rbac_allowed_high_risk_still_blocks(self, guard: ToolGuard):
        # Grant permission but tool is high risk
        cfg = GuardConfig(high_risk_threshold=0.3, medium_risk_threshold=0.1)
        tg = ToolGuard(cfg)
        tg.rbac.grant_permission(
            "agent-1",
            _make_permission("shell_execute", ["execute"], "high"),
        )
        context = {"agent_id": "agent-1", "action": "execute"}
        result = tg.evaluate("shell_execute", {}, context)
        assert result.decision == Decision.BLOCK
        assert "high_risk_tool" in result.threats


# ---------------------------------------------------------------------------
# evaluate — missing agent_id / action skips RBAC
# ---------------------------------------------------------------------------


class TestToolGuardSkipRBAC:
    def test_no_agent_id_skips_rbac(self, guard: ToolGuard):
        # No agent_id in context → skip RBAC, go straight to risk
        result = guard.evaluate("file_read", {}, {"action": "read"})
        assert result.decision == Decision.ALLOW
        assert "rbac_denied" not in result.threats

    def test_no_action_skips_rbac(self, guard: ToolGuard):
        result = guard.evaluate("file_read", {}, {"agent_id": "agent-1"})
        assert result.decision == Decision.ALLOW
        assert "rbac_denied" not in result.threats

    def test_empty_context_skips_rbac(self, guard: ToolGuard):
        result = guard.evaluate("file_read", {}, {})
        assert result.decision == Decision.ALLOW
        assert "rbac_denied" not in result.threats


# ---------------------------------------------------------------------------
# evaluate — edge cases
# ---------------------------------------------------------------------------


class TestToolGuardEdgeCases:
    def test_risk_exactly_at_high_threshold_blocks(self):
        # Craft a scenario where total == high_risk_threshold
        cfg = GuardConfig(
            high_risk_threshold=0.12,
            medium_risk_threshold=0.05,
        )
        tg = ToolGuard(cfg)
        # file_read total ≈ 0.12 == high_risk_threshold → BLOCK
        result = tg.evaluate("file_read", {}, {})
        assert result.decision == Decision.BLOCK

    def test_risk_exactly_at_medium_threshold_confirms(self):
        cfg = GuardConfig(
            high_risk_threshold=0.8,
            medium_risk_threshold=0.12,
        )
        tg = ToolGuard(cfg)
        # file_read total ≈ 0.12 == medium_risk_threshold → CONFIRM
        result = tg.evaluate("file_read", {}, {})
        assert result.decision == Decision.CONFIRM

    def test_unknown_tool_evaluated(self, guard: ToolGuard):
        result = guard.evaluate("custom_tool", {}, {})
        assert isinstance(result, SecurityResult)
        # unknown tool baseline 0.5 → total = 0.5*0.4 = 0.2 < 0.5
        assert result.decision == Decision.ALLOW
