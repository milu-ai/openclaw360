"""CLI entry point for OpenClaw360.

Provides the ``openclaw360`` console command with subcommands:
  init      — generate default config and agent identity
  protect   — start security protection mode
  audit     — query audit logs
  report    — generate an audit report
  update    — trigger rule update check
  rollback  — rollback rules to a specific version
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from openclaw360.config import GuardConfig


_DEFAULT_CONFIG_DIR = "~/.openclaw360"
_DEFAULT_CONFIG_PATH = os.path.join(_DEFAULT_CONFIG_DIR, "config.json")


def _load_config(config_path: str | None = None) -> GuardConfig:
    """Load GuardConfig from a JSON file, falling back to defaults."""
    path = Path(os.path.expanduser(config_path or _DEFAULT_CONFIG_PATH))
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        return GuardConfig(**data)
    return GuardConfig()


def _resolve_config_path(config_path: str | None) -> str:
    return config_path or _DEFAULT_CONFIG_PATH


# ------------------------------------------------------------------
# Subcommand handlers
# ------------------------------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    """Handle ``guard init`` — create default config and agent identity."""
    config_path = Path(os.path.expanduser(_resolve_config_path(args.config)))

    try:
        # Create config directory
        config_path.parent.mkdir(parents=True, exist_ok=True)

        # Write default config
        config = GuardConfig()
        config_path.write_text(
            json.dumps(config.model_dump(), indent=2), encoding="utf-8"
        )
        print(f"Config created at {config_path}")

        # Create agent identity
        from openclaw360.identity import AgentIdentityManager

        manager = AgentIdentityManager()
        identity = manager.create_identity("openclaw360", "0.1.0")
        identity_path = os.path.expanduser(config.identity_path)
        manager.save_identity(identity_path)
        print(f"Agent identity created: {identity.agent_id}")
        print(f"Identity saved to {identity_path}")

        print("OpenClaw360 initialized successfully.")
        return 0

    except PermissionError as exc:
        print(
            f"Error: Permission denied — {exc}\n"
            "Please check directory permissions and try again.",
            file=sys.stderr,
        )
        return 1
    except Exception as exc:
        print(f"Error during initialization: {exc}", file=sys.stderr)
        return 1


def cmd_protect(args: argparse.Namespace) -> int:
    """Handle ``guard protect`` — start security protection mode."""
    try:
        config = _load_config(args.config)

        from openclaw360.skill import OpenClaw360Skill

        OpenClaw360Skill(config)
        print("OpenClaw360 protection active.")
        print("All hooks registered: on_prompt, on_tool_call, on_output")
        return 0

    except Exception as exc:
        print(f"Error starting protection: {exc}", file=sys.stderr)
        return 1


def cmd_audit(args: argparse.Namespace) -> int:
    """Handle ``guard audit`` — query audit logs."""
    try:
        config = _load_config(args.config)

        from openclaw360.audit_logger import AuditLogger

        logger = AuditLogger(config)

        filters: dict = {}
        if args.action:
            filters["action"] = args.action
        if args.decision:
            filters["decision"] = args.decision

        agent_id = args.agent_id or ""
        events = logger.query(agent_id, filters)

        if not events:
            print("No audit events found.")
            return 0

        for ev in events:
            print(
                f"[{ev.timestamp}] agent={ev.agent_id} "
                f"action={ev.action} decision={ev.decision.value} "
                f"risk={ev.risk_score:.2f}"
                + (f" tool={ev.tool}" if ev.tool else "")
            )

        print(f"\nTotal: {len(events)} event(s)")
        return 0

    except Exception as exc:
        print(f"Error querying audit logs: {exc}", file=sys.stderr)
        return 1


def cmd_report(args: argparse.Namespace) -> int:
    """Handle ``guard report`` — generate an audit report."""
    try:
        config = _load_config(args.config)

        from openclaw360.audit_logger import AuditLogger

        logger = AuditLogger(config)

        start = args.start or "1970-01-01T00:00:00Z"
        end = args.end or datetime.now(timezone.utc).isoformat()

        report = logger.generate_report(args.agent_id, (start, end))

        print(f"Audit Report for agent: {report.agent_id}")
        print(f"Time range: {report.time_range[0]} — {report.time_range[1]}")
        print(f"Total events: {report.total_events}")
        print(f"Events by action: {json.dumps(report.events_by_action)}")
        print(f"Events by decision: {json.dumps(report.events_by_decision)}")
        print(f"Average risk score: {report.risk_score_avg:.2f}")
        print(f"Max risk score: {report.risk_score_max:.2f}")
        return 0

    except Exception as exc:
        print(f"Error generating report: {exc}", file=sys.stderr)
        return 1


def cmd_update(args: argparse.Namespace) -> int:
    """Handle ``guard update`` — trigger rule update check."""
    try:
        config = _load_config(args.config)

        from openclaw360.rule_update import RuleUpdateManager

        manager = RuleUpdateManager(config)
        package = manager.check_update()

        if package is None:
            print("No rule updates available.")
            return 0

        success = manager.apply_update(package)
        if success:
            print(f"Rules updated to version {package.version}.")
        else:
            print("Rule update failed. Signature verification may have failed.", file=sys.stderr)
            return 1

        return 0

    except Exception as exc:
        print(f"Error during rule update: {exc}", file=sys.stderr)
        return 1


def cmd_rollback(args: argparse.Namespace) -> int:
    """Handle ``guard rollback <version>`` — rollback rules."""
    try:
        config = _load_config(args.config)

        from openclaw360.rule_update import RuleUpdateManager

        manager = RuleUpdateManager(config)
        success = manager.rollback(args.version)

        if success:
            print(f"Rules rolled back to version {args.version}.")
        else:
            print(f"Rollback failed: version {args.version} not found.", file=sys.stderr)
            return 1

        return 0

    except Exception as exc:
        print(f"Error during rollback: {exc}", file=sys.stderr)
        return 1

def cmd_scan_skills(args: argparse.Namespace) -> int:
    """Handle ``openclaw360 scan-skills`` — scan Skill directories for security risks."""
    try:
        from openclaw360.skill_scanner import SkillScanner

        scanner = SkillScanner()
        paths = [args.path] if args.path else None
        report = scanner.scan(
            paths=paths,
            output_format=args.format,
            min_score=args.min_score,
        )

        lang = getattr(args, "lang", "en") or "en"
        output = scanner.report_generator.generate(report, args.format, lang=lang)
        print(output)
        return 0

    except Exception as exc:
        print(f"Error during skill scan: {exc}", file=sys.stderr)
        return 1

def cmd_check_prompt(args: argparse.Namespace) -> int:
    """Handle ``openclaw360 check-prompt`` — check if a prompt is safe."""
    try:
        config = _load_config(args.config)

        from openclaw360.skill import OpenClaw360Skill

        guard = OpenClaw360Skill(config)
        source = args.source or "user"
        result = guard.on_prompt(args.text, {"source": source})

        output = {
            "text": args.text,
            "source": source,
            "decision": result.decision.value,
            "risk_score": round(result.risk_score, 4),
            "threats": result.threats,
            "reason": result.reason,
            "metadata": result.metadata,
        }

        if args.format == "json":
            print(json.dumps(output, ensure_ascii=False, indent=2))
        else:
            icon = "🚫" if result.decision.value == "block" else ("⚠️" if result.decision.value == "confirm" else "✅")
            print(f"{icon} Decision: {result.decision.value.upper()}")
            print(f"   Risk Score: {result.risk_score:.4f}")
            if result.threats:
                print(f"   Threats: {', '.join(result.threats)}")
            if result.reason:
                print(f"   Reason: {result.reason}")
            if result.metadata:
                for k, v in result.metadata.items():
                    print(f"   {k}: {v}")

        return 0

    except Exception as exc:
        print(f"Error checking prompt: {exc}", file=sys.stderr)
        return 1


def cmd_check_tool(args: argparse.Namespace) -> int:
    """Handle ``openclaw360 check-tool`` — check if a tool call is safe."""
    try:
        config = _load_config(args.config)

        from openclaw360.skill import OpenClaw360Skill

        guard = OpenClaw360Skill(config)

        # Parse params as key=value pairs into a dict
        params: dict = {}
        if args.params:
            for p in args.params:
                if "=" in p:
                    k, v = p.split("=", 1)
                    params[k] = v
                else:
                    params["arg"] = p

        result = guard.on_tool_call(args.tool_name, params)

        output = {
            "tool": args.tool_name,
            "params": params,
            "decision": result.decision.value,
            "risk_score": round(result.risk_score, 4),
            "threats": result.threats,
            "reason": result.reason,
            "metadata": result.metadata,
        }

        if args.format == "json":
            print(json.dumps(output, ensure_ascii=False, indent=2))
        else:
            icon = "🚫" if result.decision.value == "block" else ("⚠️" if result.decision.value == "confirm" else "✅")
            print(f"{icon} Decision: {result.decision.value.upper()}")
            print(f"   Tool: {args.tool_name}")
            print(f"   Risk Score: {result.risk_score:.4f}")
            if result.threats:
                print(f"   Threats: {', '.join(result.threats)}")

        return 0

    except Exception as exc:
        print(f"Error checking tool call: {exc}", file=sys.stderr)
        return 1


def cmd_check_output(args: argparse.Namespace) -> int:
    """Handle ``openclaw360 check-output`` — check if output leaks sensitive data."""
    try:
        config = _load_config(args.config)

        from openclaw360.skill import OpenClaw360Skill

        guard = OpenClaw360Skill(config)
        result = guard.on_output(args.text)

        output = {
            "text": args.text[:100] + ("..." if len(args.text) > 100 else ""),
            "decision": result.decision.value,
            "risk_score": round(result.risk_score, 4),
            "threats": result.threats,
            "reason": result.reason,
            "metadata": result.metadata,
        }

        if args.format == "json":
            print(json.dumps(output, ensure_ascii=False, indent=2))
        else:
            icon = "🚫" if result.decision.value == "block" else "✅"
            print(f"{icon} Decision: {result.decision.value.upper()}")
            print(f"   Risk Score: {result.risk_score:.4f}")
            if result.threats:
                print(f"   Threats: {', '.join(result.threats)}")
            if result.reason:
                print(f"   Reason: {result.reason}")
            if result.metadata:
                for k, v in result.metadata.items():
                    print(f"   {k}: {v}")

        return 0

    except Exception as exc:
        print(f"Error checking output: {exc}", file=sys.stderr)
        return 1




# ------------------------------------------------------------------
# Parser construction
# ------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="openclaw360",
        description="OpenClaw360 — runtime security for AI Agents",
    )
    parser.add_argument(
        "--config", default=None, help="Path to config file (default: ~/.openclaw360/config.json)"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # init
    subparsers.add_parser("init", help="Initialize OpenClaw360 (config + identity)")

    # protect
    subparsers.add_parser("protect", help="Start security protection mode")

    # audit
    audit_parser = subparsers.add_parser("audit", help="Query audit logs")
    audit_parser.add_argument("--agent-id", default=None, help="Filter by agent ID")
    audit_parser.add_argument("--action", default=None, help="Filter by action type")
    audit_parser.add_argument("--decision", default=None, help="Filter by decision")

    # report
    report_parser = subparsers.add_parser("report", help="Generate audit report")
    report_parser.add_argument("--agent-id", required=True, help="Agent ID")
    report_parser.add_argument("--start", default=None, help="Start time (ISO 8601)")
    report_parser.add_argument("--end", default=None, help="End time (ISO 8601)")

    # update
    subparsers.add_parser("update", help="Check and apply rule updates")

    # rollback
    rollback_parser = subparsers.add_parser("rollback", help="Rollback rules to a version")
    rollback_parser.add_argument("version", help="Target version to rollback to")

    # scan-skills
    scan_parser = subparsers.add_parser("scan-skills", help="Scan Skill directories for security risks")
    scan_parser.add_argument("path", nargs="?", default=None, help="Path to scan (default: ~/.openclaw/skills/ and ./skills/)")
    scan_parser.add_argument("--format", choices=["json", "text"], default="text", help="Output format (default: text)")
    scan_parser.add_argument("--min-score", type=int, default=None, help="Only report Skills with score below this value")
    scan_parser.add_argument("--lang", choices=["en", "zh"], default="en", help="Report language (default: en)")

    # check-prompt
    cp_parser = subparsers.add_parser("check-prompt", help="Check if a prompt is safe (injection detection)")
    cp_parser.add_argument("text", help="The prompt text to check")
    cp_parser.add_argument("--source", default="user", choices=["user", "web", "document", "screen"], help="Input source (affects risk weight)")
    cp_parser.add_argument("--format", choices=["json", "text"], default="text", help="Output format")

    # check-tool
    ct_parser = subparsers.add_parser("check-tool", help="Check if a tool call is safe")
    ct_parser.add_argument("tool_name", help="Tool name (e.g., shell_execute, file_write)")
    ct_parser.add_argument("params", nargs="*", help="Tool parameters as key=value pairs (e.g., command='rm -rf /')")
    ct_parser.add_argument("--format", choices=["json", "text"], default="text", help="Output format")

    # check-output
    co_parser = subparsers.add_parser("check-output", help="Check if output leaks sensitive data (DLP)")
    co_parser.add_argument("text", help="The output text to check")
    co_parser.add_argument("--format", choices=["json", "text"], default="text", help="Output format")

    return parser


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for OpenClaw360."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 1

    handlers = {
        "init": cmd_init,
        "protect": cmd_protect,
        "audit": cmd_audit,
        "report": cmd_report,
        "update": cmd_update,
        "rollback": cmd_rollback,
        "scan-skills": cmd_scan_skills,
        "check-prompt": cmd_check_prompt,
        "check-tool": cmd_check_tool,
        "check-output": cmd_check_output,
    }

    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
