"""Tool Guard module — risk scoring engine for agent tool calls."""

from openclaw360.config import GuardConfig
from openclaw360.models import Decision, RiskScore, SecurityResult, ToolPermission

# Built-in tool risk baseline scores
TOOL_RISK_BASELINE: dict[str, float] = {
    "shell_execute": 0.9,
    "file_write": 0.7,
    "file_read": 0.3,
    "browser_navigate": 0.5,
    "network_request": 0.6,
    "database_query": 0.4,
    "clipboard_access": 0.5,
}

# Dangerous argument patterns that increase action risk
DANGEROUS_PATTERNS: list[str] = [
    "rm -rf",
    "sudo",
    "chmod 777",
    "> /dev/",
    "curl | sh",
]

# Keywords indicating sensitive data in arguments
SENSITIVE_DATA_KEYWORDS: list[str] = [
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "api-key",
    "token",
    "private_key",
    "private-key",
    "credential",
]


class RiskEngine:
    """Risk scoring engine using a weighted formula.

    Calculates composite risk from three dimensions:
    - action_score: tool type baseline + dangerous argument detection
    - data_score: sensitive data keyword heuristic in args
    - context_score: contextual risk factors (first run, rapid succession, escalation)

    Total = action_score * w_action + data_score * w_data + context_score * w_context
    All scores are clamped to [0.0, 1.0].
    """

    def __init__(self, config: GuardConfig) -> None:
        self.config = config
        self.weights = config.tool_risk_weights

    def calculate(self, tool_name: str, args: dict, context: dict) -> RiskScore:
        """Calculate composite risk score for a tool call.

        Args:
            tool_name: Name of the tool being called.
            args: Arguments passed to the tool.
            context: Contextual information about the call environment.

        Returns:
            RiskScore with action, data, context, and weighted total scores.
        """
        action_score = self._calculate_action_score(tool_name, args)
        data_score = self._calculate_data_score(args)
        context_score = self._calculate_context_score(context)

        total = (
            action_score * self.weights.get("action", 0.4)
            + data_score * self.weights.get("data", 0.35)
            + context_score * self.weights.get("context", 0.25)
        )
        total = _clamp(total)

        return RiskScore(
            action_score=action_score,
            data_score=data_score,
            context_score=context_score,
            total=total,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _calculate_action_score(self, tool_name: str, args: dict) -> float:
        """Baseline from TOOL_RISK_BASELINE + 0.2 if dangerous args detected."""
        baseline = TOOL_RISK_BASELINE.get(tool_name, 0.5)
        arg_str = str(args).lower()
        has_dangerous = any(p in arg_str for p in DANGEROUS_PATTERNS)
        return _clamp(baseline + (0.2 if has_dangerous else 0.0))

    def _calculate_data_score(self, args: dict) -> float:
        """Simple keyword heuristic for sensitive data in args."""
        arg_str = str(args).lower()
        count = sum(1 for kw in SENSITIVE_DATA_KEYWORDS if kw in arg_str)
        return _clamp(count * 0.2)

    def _calculate_context_score(self, context: dict) -> float:
        """Sum of context risk factors, capped at 1.0."""
        score = 0.0
        if context.get("is_first_run", False):
            score += 0.1
        if context.get("rapid_succession", False):
            score += 0.2
        if context.get("escalation_detected", False):
            score += 0.3
        return _clamp(score)


def _clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    """Clamp a value to [lo, hi]."""
    return max(lo, min(hi, value))


class AIRBACEngine:
    """AI Agent Role-Based Access Control engine.

    Maintains an in-memory permission store mapping agent IDs to their
    tool permissions.  Supports granting, revoking, and checking
    permissions for specific tool/action combinations.
    """

    def __init__(self, config: GuardConfig) -> None:
        self.config = config
        # dict[agent_id, dict[tool_name, ToolPermission]]
        self._permissions: dict[str, dict[str, ToolPermission]] = {}

    def check_permission(self, agent_id: str, tool_name: str, action: str) -> bool:
        """Check whether *agent_id* may perform *action* on *tool_name*.

        Returns ``True`` only when the agent has a ``ToolPermission`` for the
        tool **and** the requested action is listed in ``allowed_actions``.
        """
        agent_perms = self._permissions.get(agent_id)
        if agent_perms is None:
            return False
        perm = agent_perms.get(tool_name)
        if perm is None:
            return False
        return action in perm.allowed_actions

    def grant_permission(self, agent_id: str, permission: ToolPermission) -> None:
        """Grant (or update) a tool permission for *agent_id*."""
        if agent_id not in self._permissions:
            self._permissions[agent_id] = {}
        self._permissions[agent_id][permission.tool_name] = permission

    def revoke_permission(self, agent_id: str, tool_name: str) -> None:
        """Revoke the permission for *tool_name* from *agent_id*.

        Silently does nothing if the agent or tool permission does not exist.
        """
        agent_perms = self._permissions.get(agent_id)
        if agent_perms is not None:
            agent_perms.pop(tool_name, None)


class ToolGuard:
    """Tool call security guard — combines RBAC and risk scoring.

    Decision logic:
    1. RBAC check (if agent_id and action present in context):
       - denied → BLOCK immediately
    2. Risk score evaluation:
       - total >= high_risk_threshold → BLOCK
       - medium_risk_threshold <= total < high_risk_threshold → CONFIRM
       - total < medium_risk_threshold → ALLOW
    """

    def __init__(self, config: GuardConfig) -> None:
        self.config = config
        self.rbac = AIRBACEngine(config)
        self.risk_engine = RiskEngine(config)

    def evaluate(self, tool_name: str, args: dict, context: dict) -> SecurityResult:
        """Evaluate the security of a tool call.

        Args:
            tool_name: Name of the tool being called.
            args: Arguments passed to the tool.
            context: Call context; may contain "agent_id" and "action" for RBAC.

        Returns:
            SecurityResult with decision, risk_score, threats, reason, and metadata.
        """
        agent_id = context.get("agent_id")
        action = context.get("action")

        # Step 1: RBAC check (only when both agent_id and action are provided)
        if agent_id is not None and action is not None:
            if not self.rbac.check_permission(agent_id, tool_name, action):
                return SecurityResult(
                    decision=Decision.BLOCK,
                    risk_score=0.0,
                    threats=["rbac_denied"],
                    reason=f"RBAC denied: agent '{agent_id}' lacks permission for {tool_name}:{action}",
                    metadata={},
                )

        # Step 2: Calculate risk score
        risk_score = self.risk_engine.calculate(tool_name, args, context)

        # Step 3: Decision based on thresholds
        total = risk_score.total
        threats: list[str] = []

        if total >= self.config.high_risk_threshold:
            decision = Decision.BLOCK
            threats.append("high_risk_tool")
            reason = f"Risk score {total:.2f} >= high threshold {self.config.high_risk_threshold}"
        elif total >= self.config.medium_risk_threshold:
            decision = Decision.CONFIRM
            threats.append("medium_risk_tool")
            reason = f"Risk score {total:.2f} requires confirmation (medium threshold {self.config.medium_risk_threshold})"
        else:
            decision = Decision.ALLOW
            reason = f"Risk score {total:.2f} below medium threshold {self.config.medium_risk_threshold}"

        return SecurityResult(
            decision=decision,
            risk_score=total,
            threats=threats,
            reason=reason,
            metadata={
                "action_score": risk_score.action_score,
                "data_score": risk_score.data_score,
                "context_score": risk_score.context_score,
                "total": risk_score.total,
            },
        )

