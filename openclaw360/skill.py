"""OpenClaw360 Skill — main entry point coordinating all security modules.

Registers on_prompt, on_tool_call, and on_output hooks that delegate to
PromptSecurityEngine, ToolGuard, and DLPEngine respectively.  Every hook
invocation is recorded via AuditLogger with a signed AuditEvent.

A 500ms timeout wrapper ensures hooks never block the agent runtime:
if a check exceeds the deadline the hook returns ALLOW with
``metadata["timeout"] = True`` and the actual check completes
asynchronously, logging its result.
"""

from __future__ import annotations

import hashlib
import json
import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from openclaw360.audit_logger import AuditLogger
from openclaw360.config import GuardConfig
from openclaw360.dlp_engine import DLPEngine
from openclaw360.identity import AgentIdentityManager
from openclaw360.models import AuditEvent, Decision, SecurityResult
from openclaw360.prompt_engine import PromptSecurityEngine
from openclaw360.tool_guard import ToolGuard

logger = logging.getLogger(__name__)

# Default hook timeout in seconds
_HOOK_TIMEOUT_SECONDS = 0.5


class OpenClaw360Skill:
    """Main OpenClaw360 Skill class — coordinates all security sub-modules.

    Parameters
    ----------
    config:
        Global configuration for all sub-modules.
    llm_fn:
        Optional LLM callable forwarded to :class:`PromptSecurityEngine`.
    hook_timeout:
        Maximum seconds a hook may block before returning a timeout ALLOW.
        Defaults to 0.5 (500 ms).
    """

    def __init__(
        self,
        config: GuardConfig,
        llm_fn: Optional[Callable] = None,
        hook_timeout: float = _HOOK_TIMEOUT_SECONDS,
    ) -> None:
        self.config = config
        self._hook_timeout = hook_timeout

        # --- Sub-modules ---
        self.identity = AgentIdentityManager()
        self.identity.create_identity("openclaw360", "0.1.0")

        self.prompt_engine = PromptSecurityEngine(config, llm_fn=llm_fn)
        self.tool_guard = ToolGuard(config)
        self.dlp_engine = DLPEngine(config)
        self.audit_logger = AuditLogger(config)

        # Attempt to load external rules; on failure the RuleDetector
        # already falls back to BUILTIN_ATTACK_PATTERNS internally.
        try:
            if config.rules_path:
                self.prompt_engine.rule_detector.load_rules(config.rules_path)
        except Exception as exc:
            logger.warning(
                "Rule loading failed during init (%s). "
                "Using built-in minimal rule set.",
                exc,
            )

        # Shared executor for timeout-wrapped hooks
        self._executor = ThreadPoolExecutor(max_workers=2)

    # ------------------------------------------------------------------
    # Hook implementations
    # ------------------------------------------------------------------

    def on_prompt(self, prompt: str, context: dict) -> SecurityResult:
        """Prompt hook — analyse *prompt* for injection / jailbreak threats.

        Delegates to :pymethod:`PromptSecurityEngine.analyze`, logs an
        ``AuditEvent`` with ``action="prompt"``, and returns the result.
        If the check exceeds the timeout, returns ALLOW with
        ``metadata["timeout"] = True``.
        """
        return self._with_timeout(self._on_prompt_inner, prompt, context)

    def on_tool_call(self, tool_name: str, args: dict) -> SecurityResult:
        """Tool hook — evaluate the safety of a tool invocation.

        Delegates to :pymethod:`ToolGuard.evaluate`, logs an ``AuditEvent``
        with ``action="tool_call"``, and returns the result.
        """
        return self._with_timeout(self._on_tool_call_inner, tool_name, args)

    def on_output(self, output: str) -> SecurityResult:
        """Output hook — scan *output* for sensitive data leaks.

        Delegates to :pymethod:`DLPEngine.scan_text`.  If any sensitive
        data is found the decision is BLOCK (risk 1.0); otherwise ALLOW
        (risk 0.0).
        """
        return self._with_timeout(self._on_output_inner, output)

    # ------------------------------------------------------------------
    # Inner (un-timed) implementations
    # ------------------------------------------------------------------

    def _on_prompt_inner(self, prompt: str, context: dict) -> SecurityResult:
        try:
            source = context.get("source", "user")
            result = self.prompt_engine.analyze(prompt, source)
        except Exception as exc:
            logger.error("Prompt security check failed (%s). Degrading to ALLOW.", exc)
            result = _degraded_allow("Prompt security check failed")

        # Build and log audit event (best-effort)
        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()
        source = context.get("source", "user")
        self._log_event(
            action="prompt",
            risk_score=result.risk_score,
            decision=result.decision,
            details={"prompt_hash": prompt_hash, "source": source, "threats": result.threats},
        )
        return result

    def _on_tool_call_inner(self, tool_name: str, args: dict) -> SecurityResult:
        try:
            agent_id = self.identity.identity.agent_id if self.identity.identity else ""
            context = {"agent_id": agent_id}
            result = self.tool_guard.evaluate(tool_name, args, context)
        except Exception as exc:
            logger.error("Tool guard check failed (%s). Degrading to ALLOW.", exc)
            result = _degraded_allow("Tool guard check failed")

        self._log_event(
            action="tool_call",
            risk_score=result.risk_score,
            decision=result.decision,
            tool=tool_name,
            details={"tool_name": tool_name, "threats": result.threats},
        )
        return result

    def _on_output_inner(self, output: str) -> SecurityResult:
        try:
            matches = self.dlp_engine.scan_text(output)

            if matches:
                data_types = list({m.data_type.value for m in matches})
                result = SecurityResult(
                    decision=Decision.BLOCK,
                    risk_score=1.0,
                    threats=data_types,
                    reason=f"Sensitive data detected: {', '.join(data_types)}",
                    metadata={"match_count": len(matches), "data_types": data_types},
                )
            else:
                result = SecurityResult(
                    decision=Decision.ALLOW,
                    risk_score=0.0,
                    threats=[],
                    reason="No sensitive data detected in output",
                )
        except Exception as exc:
            logger.error("DLP check failed (%s). Degrading to ALLOW.", exc)
            result = _degraded_allow("DLP check failed")

        self._log_event(
            action="output",
            risk_score=result.risk_score,
            decision=result.decision,
            details={"threats": result.threats},
        )
        return result

    # ------------------------------------------------------------------
    # Timeout wrapper
    # ------------------------------------------------------------------

    def _with_timeout(self, fn: Callable[..., SecurityResult], *args: Any) -> SecurityResult:
        """Run *fn* with a timeout.

        If *fn* completes within ``self._hook_timeout`` seconds its result
        is returned directly.  Otherwise an ALLOW result with
        ``metadata["timeout"] = True`` is returned immediately and the
        actual check continues in the background — its result is logged
        asynchronously.
        """
        future = self._executor.submit(fn, *args)
        try:
            return future.result(timeout=self._hook_timeout)
        except FuturesTimeoutError:
            logger.warning("Hook timed out after %.1fs — returning ALLOW", self._hook_timeout)

            # Let the background task finish and log its result
            def _log_late_result(fut):
                try:
                    late_result = fut.result(timeout=30)
                    logger.info(
                        "Late hook result: decision=%s risk=%.2f",
                        late_result.decision.value,
                        late_result.risk_score,
                    )
                except Exception as exc:
                    logger.error("Late hook execution failed: %s", exc)

            future.add_done_callback(_log_late_result)

            return SecurityResult(
                decision=Decision.ALLOW,
                risk_score=0.0,
                threats=[],
                reason="Hook timed out",
                metadata={"timeout": True},
            )

    # ------------------------------------------------------------------
    # Audit helpers
    # ------------------------------------------------------------------

    def _log_event(
        self,
        action: str,
        risk_score: float,
        decision: Decision,
        tool: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        """Create a signed AuditEvent and pass it to the AuditLogger.

        Best-effort: if signing or logging fails the error is logged but
        the calling hook is not interrupted.
        """
        try:
            identity = self.identity.identity
            agent_id = identity.agent_id if identity else "unknown"
            timestamp = datetime.now(timezone.utc).isoformat()

            # Serialize event data for signing
            event_data = json.dumps(
                {"agent_id": agent_id, "timestamp": timestamp, "action": action, "risk_score": risk_score},
                sort_keys=True,
            ).encode()

            try:
                signature = self.identity.sign_action(event_data)
            except RuntimeError:
                signature = b""

            event = AuditEvent(
                agent_id=agent_id,
                timestamp=timestamp,
                action=action,
                tool=tool,
                risk_score=risk_score,
                decision=decision,
                signature=signature,
                details=details or {},
            )
            self.audit_logger.log(event)
        except Exception as exc:
            logger.error("Audit logging failed (%s). Event dropped.", exc)


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------


def _degraded_allow(reason: str) -> SecurityResult:
    """Return an ALLOW result that signals degraded mode via metadata."""
    return SecurityResult(
        decision=Decision.ALLOW,
        risk_score=0.0,
        threats=[],
        reason=reason,
        metadata={"degraded": True},
    )
