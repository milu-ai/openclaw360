"""Unit tests for openclaw360.cli module."""

import json
import os
from unittest.mock import patch

import pytest

from openclaw360.cli import build_parser, main, cmd_init, cmd_protect


class TestBuildParser:
    """Tests for parser construction and subcommand routing."""

    def test_no_command_prints_help_and_returns_1(self, capsys):
        """No subcommand → print help and return 1."""
        result = main([])
        assert result == 1
        captured = capsys.readouterr()
        assert "usage" in captured.out.lower() or "openclaw360" in captured.out.lower()

    def test_invalid_command_shows_help(self, capsys):
        """Unknown subcommand → argparse error (SystemExit 2)."""
        with pytest.raises(SystemExit) as exc_info:
            main(["nonexistent"])
        assert exc_info.value.code == 2

    def test_parser_has_all_subcommands(self):
        parser = build_parser()
        # Verify subparsers exist by parsing known commands
        for cmd in ["init", "protect", "audit", "report", "update"]:
            args = parser.parse_args([cmd] if cmd != "report" else ["report", "--agent-id", "x"])
            assert args.command == cmd

        args = parser.parse_args(["rollback", "1.0.0"])
        assert args.command == "rollback"
        assert args.version == "1.0.0"


class TestCmdInit:
    """Tests for the init subcommand."""

    def test_init_creates_config_and_identity(self, tmp_path, capsys):
        config_path = str(tmp_path / "config.json")
        identity_path = str(tmp_path / "identity.json")

        # Patch GuardConfig defaults so identity goes to tmp_path
        with patch("openclaw360.cli.GuardConfig") as MockConfig:
            mock_config = MockConfig.return_value
            mock_config.identity_path = identity_path
            mock_config.model_dump.return_value = {
                "identity_path": identity_path,
                "prompt_risk_threshold": 0.7,
            }

            result = main(["--config", config_path, "init"])

        assert result == 0
        captured = capsys.readouterr()
        assert "initialized successfully" in captured.out.lower()
        assert os.path.exists(config_path)

    def test_init_permission_error(self, capsys):
        """Permission error returns 1 with helpful message."""
        with patch("openclaw360.cli.Path.mkdir", side_effect=PermissionError("denied")):
            result = main(["--config", "/root/nope/config.json", "init"])

        assert result == 1
        captured = capsys.readouterr()
        assert "permission" in captured.err.lower() or "error" in captured.err.lower()


class TestCmdProtect:
    """Tests for the protect subcommand."""

    def test_protect_prints_active_message(self, tmp_path, capsys):
        config_path = str(tmp_path / "config.json")
        # Write a minimal valid config
        config_data = {
            "identity_path": str(tmp_path / "identity.json"),
            "rules_path": str(tmp_path / "rules"),
        }
        with open(config_path, "w") as f:
            json.dump(config_data, f)

        result = main(["--config", config_path, "protect"])
        assert result == 0
        captured = capsys.readouterr()
        assert "protection active" in captured.out.lower()


class TestCmdAudit:
    """Tests for the audit subcommand."""

    def test_audit_no_events(self, tmp_path, capsys):
        config_path = str(tmp_path / "config.json")
        config_data = {"audit_log_path": str(tmp_path / "audit")}
        with open(config_path, "w") as f:
            json.dump(config_data, f)

        result = main(["--config", config_path, "audit", "--agent-id", "test-agent"])
        assert result == 0
        captured = capsys.readouterr()
        assert "no audit events found" in captured.out.lower()

    def test_audit_with_events(self, tmp_path, capsys):
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        # Write a fake audit event
        event = {
            "agent_id": "agent-1",
            "timestamp": "2024-01-15T10:00:00Z",
            "action": "prompt",
            "tool": None,
            "risk_score": 0.3,
            "decision": "allow",
            "signature": "aa",
            "details": {},
        }
        (audit_dir / "agent-1.jsonl").write_text(json.dumps(event) + "\n")

        config_path = str(tmp_path / "config.json")
        config_data = {"audit_log_path": str(audit_dir)}
        with open(config_path, "w") as f:
            json.dump(config_data, f)

        result = main(["--config", config_path, "audit", "--agent-id", "agent-1"])
        assert result == 0
        captured = capsys.readouterr()
        assert "agent-1" in captured.out
        assert "prompt" in captured.out
        assert "Total: 1" in captured.out

    def test_audit_with_action_filter(self, tmp_path, capsys):
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        events = [
            {"agent_id": "a1", "timestamp": "2024-01-15T10:00:00Z", "action": "prompt",
             "tool": None, "risk_score": 0.3, "decision": "allow", "signature": "aa", "details": {}},
            {"agent_id": "a1", "timestamp": "2024-01-15T11:00:00Z", "action": "tool_call",
             "tool": "shell", "risk_score": 0.9, "decision": "block", "signature": "bb", "details": {}},
        ]
        (audit_dir / "a1.jsonl").write_text(
            "\n".join(json.dumps(e) for e in events) + "\n"
        )

        config_path = str(tmp_path / "config.json")
        config_data = {"audit_log_path": str(audit_dir)}
        with open(config_path, "w") as f:
            json.dump(config_data, f)

        result = main(["--config", config_path, "audit", "--agent-id", "a1", "--action", "tool_call"])
        assert result == 0
        captured = capsys.readouterr()
        assert "tool_call" in captured.out
        assert "Total: 1" in captured.out


class TestCmdReport:
    """Tests for the report subcommand."""

    def test_report_requires_agent_id(self):
        with pytest.raises(SystemExit) as exc_info:
            main(["report"])
        assert exc_info.value.code == 2

    def test_report_empty(self, tmp_path, capsys):
        config_path = str(tmp_path / "config.json")
        config_data = {"audit_log_path": str(tmp_path / "audit")}
        with open(config_path, "w") as f:
            json.dump(config_data, f)

        result = main([
            "--config", config_path, "report",
            "--agent-id", "agent-1",
            "--start", "2024-01-01T00:00:00Z",
            "--end", "2024-12-31T23:59:59Z",
        ])
        assert result == 0
        captured = capsys.readouterr()
        assert "Total events: 0" in captured.out


class TestCmdUpdate:
    """Tests for the update subcommand."""

    def test_update_no_updates_available(self, tmp_path, capsys):
        config_path = str(tmp_path / "config.json")
        config_data = {"rules_path": str(tmp_path / "rules")}
        with open(config_path, "w") as f:
            json.dump(config_data, f)

        result = main(["--config", config_path, "update"])
        assert result == 0
        captured = capsys.readouterr()
        assert "no rule updates available" in captured.out.lower()


class TestCmdRollback:
    """Tests for the rollback subcommand."""

    def test_rollback_version_not_found(self, tmp_path, capsys):
        config_path = str(tmp_path / "config.json")
        config_data = {"rules_path": str(tmp_path / "rules")}
        with open(config_path, "w") as f:
            json.dump(config_data, f)

        result = main(["--config", config_path, "rollback", "99.0.0"])
        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.err.lower()

    def test_rollback_requires_version_arg(self):
        with pytest.raises(SystemExit) as exc_info:
            main(["rollback"])
        assert exc_info.value.code == 2


class TestMainEntryPoint:
    """Tests for the main() function itself."""

    def test_main_returns_int(self):
        result = main([])
        assert isinstance(result, int)

    def test_global_config_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--config", "/tmp/custom.json", "init"])
        assert args.config == "/tmp/custom.json"
        assert args.command == "init"
