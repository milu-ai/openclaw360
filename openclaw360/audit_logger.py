"""Audit Logger for recording, querying, and reporting agent actions."""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from openclaw360.config import GuardConfig
from openclaw360.models import AuditEvent, Decision


@dataclass
class AuditReport:
    """Summary report of audit events for a given agent and time range."""

    agent_id: str
    time_range: tuple[str, str]
    total_events: int
    events_by_action: dict[str, int]
    events_by_decision: dict[str, int]
    risk_score_avg: float
    risk_score_max: float


class AuditLogger:
    """Audit logger that records AuditEvents to JSON Lines files.

    Features:
    - Writes one JSON object per line to {audit_log_path}/{agent_id}.jsonl
    - Queries events by agent_id with optional filters (action, decision, time range)
    - Generates summary reports for a given agent and time range
    - Falls back to an in-memory queue (max 1000 events) on disk write failure
    - Flushes the memory queue on the next successful write
    """

    MAX_MEMORY_QUEUE = 1000

    def __init__(self, config: GuardConfig) -> None:
        self._audit_log_path = Path(os.path.expanduser(config.audit_log_path))
        self._memory_queue: list[AuditEvent] = []

    # ------------------------------------------------------------------
    # Serialization helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _serialize_event(event: AuditEvent) -> dict[str, Any]:
        """Convert an AuditEvent to a JSON-serializable dict."""
        return {
            "agent_id": event.agent_id,
            "timestamp": event.timestamp,
            "action": event.action,
            "tool": event.tool,
            "risk_score": event.risk_score,
            "decision": event.decision.value,
            "signature": event.signature.hex(),
            "details": event.details,
        }

    @staticmethod
    def _deserialize_event(data: dict[str, Any]) -> AuditEvent:
        """Reconstruct an AuditEvent from a JSON dict."""
        return AuditEvent(
            agent_id=data["agent_id"],
            timestamp=data["timestamp"],
            action=data["action"],
            tool=data.get("tool"),
            risk_score=data["risk_score"],
            decision=Decision(data["decision"]),
            signature=bytes.fromhex(data["signature"]),
            details=data.get("details", {}),
        )

    # ------------------------------------------------------------------
    # File path helpers
    # ------------------------------------------------------------------

    def _agent_log_path(self, agent_id: str) -> Path:
        """Return the JSONL file path for a given agent."""
        return self._audit_log_path / f"{agent_id}.jsonl"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log(self, event: AuditEvent) -> None:
        """Record an AuditEvent to disk (JSON Lines).

        On disk write failure the event is cached in an in-memory queue
        (capped at MAX_MEMORY_QUEUE, oldest dropped when exceeded).
        On the next successful call the queue is flushed first.
        """
        log_path = self._agent_log_path(event.agent_id)

        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)

            # Flush memory queue first (all queued events for this agent)
            if self._memory_queue:
                self._flush_memory_queue(log_path, event.agent_id)

            line = json.dumps(self._serialize_event(event)) + "\n"
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(line)

        except OSError:
            self._enqueue(event)

    def query(self, agent_id: str, filters: dict | None = None) -> list[AuditEvent]:
        """Query audit events for *agent_id* with optional filters.

        Supported filter keys:
        - action   (str)  – match event.action exactly
        - decision (str)  – match Decision value string (e.g. "allow")
        - start_time (str, ISO 8601) – inclusive lower bound on timestamp
        - end_time   (str, ISO 8601) – inclusive upper bound on timestamp
        """
        filters = filters or {}
        log_path = self._agent_log_path(agent_id)

        if not log_path.exists():
            return []

        events: list[AuditEvent] = []
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                event = self._deserialize_event(data)
                if self._matches_filters(event, filters):
                    events.append(event)

        return events

    def generate_report(
        self, agent_id: str, time_range: tuple[str, str]
    ) -> AuditReport:
        """Generate a summary report for *agent_id* within *time_range*."""
        events = self.query(
            agent_id,
            {"start_time": time_range[0], "end_time": time_range[1]},
        )

        events_by_action: dict[str, int] = {}
        events_by_decision: dict[str, int] = {}
        risk_scores: list[float] = []

        for ev in events:
            events_by_action[ev.action] = events_by_action.get(ev.action, 0) + 1
            dec_val = ev.decision.value
            events_by_decision[dec_val] = events_by_decision.get(dec_val, 0) + 1
            risk_scores.append(ev.risk_score)

        return AuditReport(
            agent_id=agent_id,
            time_range=time_range,
            total_events=len(events),
            events_by_action=events_by_action,
            events_by_decision=events_by_decision,
            risk_score_avg=(sum(risk_scores) / len(risk_scores)) if risk_scores else 0.0,
            risk_score_max=max(risk_scores) if risk_scores else 0.0,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _matches_filters(event: AuditEvent, filters: dict) -> bool:
        """Return True if *event* satisfies all *filters*."""
        if "action" in filters and event.action != filters["action"]:
            return False
        if "decision" in filters and event.decision.value != filters["decision"]:
            return False
        if "start_time" in filters and event.timestamp < filters["start_time"]:
            return False
        if "end_time" in filters and event.timestamp > filters["end_time"]:
            return False
        return True

    def _enqueue(self, event: AuditEvent) -> None:
        """Add event to the in-memory fallback queue, dropping oldest if full."""
        if len(self._memory_queue) >= self.MAX_MEMORY_QUEUE:
            self._memory_queue.pop(0)
        self._memory_queue.append(event)

    def _flush_memory_queue(self, log_path: Path, agent_id: str) -> None:
        """Write all queued events for *agent_id* to disk and remove them."""
        remaining: list[AuditEvent] = []
        lines: list[str] = []

        for ev in self._memory_queue:
            if ev.agent_id == agent_id:
                lines.append(json.dumps(self._serialize_event(ev)) + "\n")
            else:
                remaining.append(ev)

        if lines:
            with open(log_path, "a", encoding="utf-8") as f:
                f.writelines(lines)

        self._memory_queue = remaining
