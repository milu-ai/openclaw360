"""Unit tests for AuditLogger."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from openclaw360.audit_logger import AuditLogger, AuditReport
from openclaw360.config import GuardConfig
from openclaw360.models import AuditEvent, Decision


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(
    agent_id: str = "agent-1",
    timestamp: str = "2024-06-15T10:00:00Z",
    action: str = "prompt",
    tool: str | None = None,
    risk_score: float = 0.3,
    decision: Decision = Decision.ALLOW,
    signature: bytes = b"\xab\xcd",
    details: dict | None = None,
) -> AuditEvent:
    return AuditEvent(
        agent_id=agent_id,
        timestamp=timestamp,
        action=action,
        tool=tool,
        risk_score=risk_score,
        decision=decision,
        signature=signature,
        details=details or {},
    )


def _make_logger(tmp_path: Path) -> AuditLogger:
    config = GuardConfig(audit_log_path=str(tmp_path))
    return AuditLogger(config)


# ===========================================================================
# log()
# ===========================================================================

class TestLog:
    """Requirement 6.1: Record AuditEvent to local JSONL file."""

    def test_creates_jsonl_file(self, tmp_path: Path):
        logger = _make_logger(tmp_path)
        logger.log(_make_event())

        assert (tmp_path / "agent-1.jsonl").exists()

    def test_writes_valid_json_line(self, tmp_path: Path):
        logger = _make_logger(tmp_path)
        event = _make_event()
        logger.log(event)

        lines = (tmp_path / "agent-1.jsonl").read_text().strip().splitlines()
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["agent_id"] == "agent-1"
        assert data["action"] == "prompt"
        assert data["risk_score"] == 0.3

    def test_decision_serialized_as_value_string(self, tmp_path: Path):
        logger = _make_logger(tmp_path)
        logger.log(_make_event(decision=Decision.BLOCK))

        data = json.loads((tmp_path / "agent-1.jsonl").read_text().strip())
        assert data["decision"] == "block"

    def test_signature_serialized_as_hex(self, tmp_path: Path):
        logger = _make_logger(tmp_path)
        logger.log(_make_event(signature=b"\xde\xad\xbe\xef"))

        data = json.loads((tmp_path / "agent-1.jsonl").read_text().strip())
        assert data["signature"] == "deadbeef"

    def test_appends_multiple_events(self, tmp_path: Path):
        logger = _make_logger(tmp_path)
        logger.log(_make_event(timestamp="2024-06-15T10:00:00Z"))
        logger.log(_make_event(timestamp="2024-06-15T11:00:00Z"))

        lines = (tmp_path / "agent-1.jsonl").read_text().strip().splitlines()
        assert len(lines) == 2

    def test_separate_files_per_agent(self, tmp_path: Path):
        logger = _make_logger(tmp_path)
        logger.log(_make_event(agent_id="a1"))
        logger.log(_make_event(agent_id="a2"))

        assert (tmp_path / "a1.jsonl").exists()
        assert (tmp_path / "a2.jsonl").exists()

    def test_creates_parent_directories(self, tmp_path: Path):
        deep = tmp_path / "sub" / "dir"
        config = GuardConfig(audit_log_path=str(deep))
        logger = AuditLogger(config)
        logger.log(_make_event())

        assert (deep / "agent-1.jsonl").exists()

    def test_details_dict_preserved(self, tmp_path: Path):
        logger = _make_logger(tmp_path)
        logger.log(_make_event(details={"hash": "abc123"}))

        data = json.loads((tmp_path / "agent-1.jsonl").read_text().strip())
        assert data["details"] == {"hash": "abc123"}


# ===========================================================================
# Memory queue fallback (Requirement 6.5)
# ===========================================================================

class TestMemoryQueueFallback:
    """Requirement 6.5: Cache to memory on disk failure, flush on recovery."""

    def test_caches_event_on_write_failure(self, tmp_path: Path):
        logger = _make_logger(tmp_path)

        with patch("builtins.open", side_effect=OSError("disk full")):
            with patch.object(Path, "mkdir"):
                logger.log(_make_event())

        assert len(logger._memory_queue) == 1

    def test_flushes_queue_on_next_successful_write(self, tmp_path: Path):
        logger = _make_logger(tmp_path)

        # Simulate disk failure for first event
        with patch("builtins.open", side_effect=OSError("disk full")):
            with patch.object(Path, "mkdir"):
                logger.log(_make_event(timestamp="2024-06-15T09:00:00Z"))

        assert len(logger._memory_queue) == 1

        # Disk recovers — second event should flush the queue too
        logger.log(_make_event(timestamp="2024-06-15T10:00:00Z"))

        assert len(logger._memory_queue) == 0
        lines = (tmp_path / "agent-1.jsonl").read_text().strip().splitlines()
        assert len(lines) == 2
        assert json.loads(lines[0])["timestamp"] == "2024-06-15T09:00:00Z"
        assert json.loads(lines[1])["timestamp"] == "2024-06-15T10:00:00Z"

    def test_drops_oldest_when_queue_exceeds_max(self, tmp_path: Path):
        logger = _make_logger(tmp_path)

        with patch("builtins.open", side_effect=OSError("disk full")):
            with patch.object(Path, "mkdir"):
                for i in range(1001):
                    logger.log(_make_event(timestamp=f"2024-06-15T{i:05d}"))

        assert len(logger._memory_queue) == 1000
        # Oldest (i=0) should have been dropped
        assert logger._memory_queue[0].timestamp == "2024-06-15T00001"

    def test_queue_events_for_different_agents(self, tmp_path: Path):
        logger = _make_logger(tmp_path)

        with patch("builtins.open", side_effect=OSError("disk full")):
            with patch.object(Path, "mkdir"):
                logger.log(_make_event(agent_id="a1"))
                logger.log(_make_event(agent_id="a2"))

        assert len(logger._memory_queue) == 2

        # Recover — log for a1 should only flush a1's queued events
        logger.log(_make_event(agent_id="a1", timestamp="2024-06-15T11:00:00Z"))

        assert len(logger._memory_queue) == 1
        assert logger._memory_queue[0].agent_id == "a2"


# ===========================================================================
# query()
# ===========================================================================

class TestQuery:
    """Requirements 6.3: Query by agent_id, action, decision, time range."""

    def test_returns_all_events_for_agent(self, tmp_path: Path):
        logger = _make_logger(tmp_path)
        logger.log(_make_event())
        logger.log(_make_event(timestamp="2024-06-15T11:00:00Z"))

        events = logger.query("agent-1")
        assert len(events) == 2

    def test_returns_empty_for_unknown_agent(self, tmp_path: Path):
        logger = _make_logger(tmp_path)
        assert logger.query("nonexistent") == []

    def test_filter_by_action(self, tmp_path: Path):
        logger = _make_logger(tmp_path)
        logger.log(_make_event(action="prompt"))
        logger.log(_make_event(action="tool_call", timestamp="2024-06-15T11:00:00Z"))

        events = logger.query("agent-1", {"action": "tool_call"})
        assert len(events) == 1
        assert events[0].action == "tool_call"

    def test_filter_by_decision(self, tmp_path: Path):
        logger = _make_logger(tmp_path)
        logger.log(_make_event(decision=Decision.ALLOW))
        logger.log(
            _make_event(
                decision=Decision.BLOCK,
                timestamp="2024-06-15T11:00:00Z",
            )
        )

        events = logger.query("agent-1", {"decision": "block"})
        assert len(events) == 1
        assert events[0].decision == Decision.BLOCK

    def test_filter_by_time_range(self, tmp_path: Path):
        logger = _make_logger(tmp_path)
        logger.log(_make_event(timestamp="2024-06-01T00:00:00Z"))
        logger.log(_make_event(timestamp="2024-06-15T00:00:00Z"))
        logger.log(_make_event(timestamp="2024-06-30T00:00:00Z"))

        events = logger.query(
            "agent-1",
            {"start_time": "2024-06-10T00:00:00Z", "end_time": "2024-06-20T00:00:00Z"},
        )
        assert len(events) == 1
        assert events[0].timestamp == "2024-06-15T00:00:00Z"

    def test_combined_filters(self, tmp_path: Path):
        logger = _make_logger(tmp_path)
        logger.log(_make_event(action="prompt", decision=Decision.ALLOW))
        logger.log(
            _make_event(
                action="tool_call",
                decision=Decision.BLOCK,
                timestamp="2024-06-15T11:00:00Z",
            )
        )
        logger.log(
            _make_event(
                action="tool_call",
                decision=Decision.ALLOW,
                timestamp="2024-06-15T12:00:00Z",
            )
        )

        events = logger.query(
            "agent-1", {"action": "tool_call", "decision": "block"}
        )
        assert len(events) == 1
        assert events[0].action == "tool_call"
        assert events[0].decision == Decision.BLOCK

    def test_deserialized_event_fields(self, tmp_path: Path):
        logger = _make_logger(tmp_path)
        original = _make_event(
            tool="shell_execute",
            risk_score=0.85,
            decision=Decision.CONFIRM,
            signature=b"\x01\x02\x03",
            details={"key_hash": "sha256:abc"},
        )
        logger.log(original)

        events = logger.query("agent-1")
        assert len(events) == 1
        ev = events[0]
        assert ev.agent_id == original.agent_id
        assert ev.timestamp == original.timestamp
        assert ev.action == original.action
        assert ev.tool == "shell_execute"
        assert ev.risk_score == 0.85
        assert ev.decision == Decision.CONFIRM
        assert ev.signature == b"\x01\x02\x03"
        assert ev.details == {"key_hash": "sha256:abc"}


# ===========================================================================
# generate_report()
# ===========================================================================

class TestGenerateReport:
    """Requirement 6.4: Generate audit report for agent within time range."""

    def test_report_structure(self, tmp_path: Path):
        logger = _make_logger(tmp_path)
        logger.log(_make_event(timestamp="2024-06-15T10:00:00Z", action="prompt", risk_score=0.2))
        logger.log(
            _make_event(
                timestamp="2024-06-15T11:00:00Z",
                action="tool_call",
                risk_score=0.8,
                decision=Decision.BLOCK,
            )
        )

        report = logger.generate_report(
            "agent-1", ("2024-06-01T00:00:00Z", "2024-06-30T23:59:59Z")
        )

        assert isinstance(report, AuditReport)
        assert report.agent_id == "agent-1"
        assert report.total_events == 2
        assert report.events_by_action == {"prompt": 1, "tool_call": 1}
        assert report.events_by_decision == {"allow": 1, "block": 1}
        assert report.risk_score_avg == pytest.approx(0.5)
        assert report.risk_score_max == pytest.approx(0.8)

    def test_report_respects_time_range(self, tmp_path: Path):
        logger = _make_logger(tmp_path)
        logger.log(_make_event(timestamp="2024-05-01T00:00:00Z"))
        logger.log(_make_event(timestamp="2024-06-15T00:00:00Z"))
        logger.log(_make_event(timestamp="2024-07-01T00:00:00Z"))

        report = logger.generate_report(
            "agent-1", ("2024-06-01T00:00:00Z", "2024-06-30T23:59:59Z")
        )
        assert report.total_events == 1

    def test_empty_report(self, tmp_path: Path):
        logger = _make_logger(tmp_path)

        report = logger.generate_report(
            "agent-1", ("2024-06-01T00:00:00Z", "2024-06-30T23:59:59Z")
        )

        assert report.total_events == 0
        assert report.events_by_action == {}
        assert report.events_by_decision == {}
        assert report.risk_score_avg == 0.0
        assert report.risk_score_max == 0.0

    def test_report_time_range_stored(self, tmp_path: Path):
        logger = _make_logger(tmp_path)
        tr = ("2024-06-01T00:00:00Z", "2024-06-30T23:59:59Z")
        report = logger.generate_report("agent-1", tr)
        assert report.time_range == tr


# ===========================================================================
# Zero Knowledge Logging (Requirement 6.2)
# ===========================================================================

class TestZeroKnowledgeLogging:
    """Requirement 6.2: Sensitive data in details should be hashed by caller.
    The logger serializes faithfully — verify it doesn't add raw data."""

    def test_details_with_hashes_only(self, tmp_path: Path):
        logger = _make_logger(tmp_path)
        # Caller is responsible for hashing; logger just stores what it gets
        logger.log(
            _make_event(
                details={
                    "prompt_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "matched_patterns": ["PI-001"],
                }
            )
        )

        data = json.loads((tmp_path / "agent-1.jsonl").read_text().strip())
        assert "prompt_hash" in data["details"]
        # No raw prompt text stored
        assert "raw_prompt" not in data["details"]
