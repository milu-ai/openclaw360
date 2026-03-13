"""Bug condition exploration tests for ClawHub Security suspicious flag triggers.

These tests encode the EXPECTED (fixed) behavior. On UNFIXED code they are
expected to FAIL — failure confirms the bug conditions exist.

**Validates: Requirements 1.1, 1.2, 1.3**
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

# ── helpers ──────────────────────────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SKILL_MD = PROJECT_ROOT / "SKILL.md"
SKILL_SCANNER = PROJECT_ROOT / "openclaw360" / "skill_scanner.py"
CLI_PY = PROJECT_ROOT / "openclaw360" / "cli.py"


def _parse_frontmatter(text: str) -> dict:
    """Extract YAML frontmatter between the first pair of ``---`` delimiters."""
    parts = text.split("---", 2)
    if len(parts) < 3:
        pytest.fail("SKILL.md does not contain valid YAML frontmatter (missing --- delimiters)")
    return yaml.safe_load(parts[1])


def _extract_rules_section(text: str) -> str:
    """Return the content under the top-level ``## Rules`` heading."""
    match = re.search(r"^## Rules\b.*?\n(.*?)(?=^## |\Z)", text, re.MULTILINE | re.DOTALL)
    if match is None:
        pytest.fail("SKILL.md does not contain a '## Rules' section")
    return match.group(1)


def _lines_with_context(source: str, needle: str, context: int = 2) -> list[tuple[int, str, list[str]]]:
    """Find all lines containing *needle* and return surrounding context lines.

    Returns a list of ``(line_number, matched_line, context_lines)`` tuples
    where *context_lines* are the ``context`` lines before and after.
    """
    lines = source.splitlines()
    results = []
    for idx, line in enumerate(lines):
        if needle in line:
            start = max(0, idx - context)
            end = min(len(lines), idx + context + 1)
            ctx = lines[start:end]
            results.append((idx + 1, line, ctx))
    return results


# ── Test 1: SKILL.md frontmatter must have a top-level ``install`` field ─────

class TestFrontmatterInstallField:
    """Bug condition (a): ClawHub registry cannot find install spec because
    the install commands are nested under ``metadata.clawdbot.install`` and
    there is no top-level ``install`` key in the frontmatter.
    """

    def test_top_level_install_key_exists(self) -> None:
        """Frontmatter MUST contain a top-level ``install`` key so that
        ClawHub registry recognises the installation specification."""
        content = SKILL_MD.read_text(encoding="utf-8")
        fm = _parse_frontmatter(content)

        # Confirm the nested install exists (precondition)
        nested = fm.get("metadata", {}).get("clawdbot", {}).get("install")
        assert nested is not None, (
            "Precondition: metadata.clawdbot.install should exist in frontmatter"
        )

        # The actual assertion — top-level install must exist
        assert "install" in fm, (
            "SKILL.md frontmatter is missing a top-level 'install' field. "
            "ClawHub registry only reads top-level fields and will report "
            "'No install spec'."
        )


# ── Test 2: skill_scanner.py path references have explanation comments ───────

OPENCLAW_EXPLANATION_PATTERN = re.compile(
    r"openclaw\s+platform|openclaw\s+平台|platform\s+skill\s+dir",
    re.IGNORECASE,
)


class TestPathExplanationInScanner:
    """Bug condition (b): ``~/.openclaw/skills/`` appears in source code
    without an adjacent comment explaining it is the OpenClaw platform Skill
    directory (not openclaw360's own directory ``~/.openclaw360/``).
    """

    def test_skill_scanner_path_has_explanation_comment(self) -> None:
        """Every ``~/.openclaw/skills/`` reference in skill_scanner.py must
        have an explanation comment within 2 lines before or after."""
        source = SKILL_SCANNER.read_text(encoding="utf-8")
        occurrences = _lines_with_context(source, "~/.openclaw/skills/", context=2)

        assert occurrences, "Precondition: ~/.openclaw/skills/ should appear in skill_scanner.py"

        for lineno, _line, ctx in occurrences:
            ctx_text = "\n".join(ctx)
            assert OPENCLAW_EXPLANATION_PATTERN.search(ctx_text), (
                f"skill_scanner.py line {lineno}: ~/.openclaw/skills/ reference "
                f"has no adjacent comment explaining it is the OpenClaw platform "
                f"Skill directory. Context:\n{ctx_text}"
            )


# ── Test 3: cli.py scan-skills help text has path explanation ────────────────

class TestCLIHelpTextExplanation:
    """Bug condition (b continued): The ``scan-skills`` path argument help
    text references ``~/.openclaw/skills/`` without explaining it is the
    OpenClaw platform Skill directory.
    """

    def test_scan_skills_help_contains_platform_explanation(self) -> None:
        """The scan-skills path help text must mention that
        ``~/.openclaw/skills/`` is the OpenClaw platform directory."""
        source = CLI_PY.read_text(encoding="utf-8")
        occurrences = _lines_with_context(source, "~/.openclaw/skills/", context=2)

        assert occurrences, "Precondition: ~/.openclaw/skills/ should appear in cli.py"

        for lineno, _line, ctx in occurrences:
            ctx_text = "\n".join(ctx)
            assert OPENCLAW_EXPLANATION_PATTERN.search(ctx_text), (
                f"cli.py line {lineno}: ~/.openclaw/skills/ reference in help text "
                f"has no OpenClaw platform directory explanation. Context:\n{ctx_text}"
            )


# ── Test 4: SKILL.md Rules section must not contain restrictive language ─────

class TestRestrictiveRulesLanguage:
    """Bug condition (c): The Rules section contains mandatory constraint
    markers (``必须一次完成`` and ``强制``) that ClawHub Security flags as
    "operationally restrictive".
    """

    def test_rules_no_mandatory_one_shot(self) -> None:
        """SKILL.md must NOT contain '必须一次完成' as a mandatory constraint.

        Note: ClawHub Security scans the entire SKILL.md (including
        Instructions and Rules sections) for restrictive language.  The
        phrase appears under '### Skill 安全扫描' in the Instructions
        section, which the scanner also evaluates.
        """
        content = SKILL_MD.read_text(encoding="utf-8")
        # Check both the Rules section and the full content — the scanner
        # evaluates the entire file for operationally restrictive language.
        rules = _extract_rules_section(content)
        full_check = "必须一次完成" not in content
        rules_check = "必须一次完成" not in rules
        assert full_check and rules_check, (
            "SKILL.md contains '必须一次完成' — "
            "ClawHub Security flags this as operationally restrictive."
        )

    def test_rules_no_mandatory_marker(self) -> None:
        """Rules section must NOT contain '强制' as a mandatory constraint marker."""
        content = SKILL_MD.read_text(encoding="utf-8")
        rules = _extract_rules_section(content)
        assert "强制" not in rules, (
            "SKILL.md Rules section contains '强制' — "
            "ClawHub Security flags this as operationally restrictive."
        )


# ══════════════════════════════════════════════════════════════════════════════
# Preservation Property Tests (Task 2)
#
# These tests MUST PASS on UNFIXED code — they establish the baseline behavior
# that must be preserved after the fix.  They guard against regressions.
#
# **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5**
# ══════════════════════════════════════════════════════════════════════════════

import argparse

from openclaw360.skill_scanner import SkillDiscovery
from openclaw360.config import GuardConfig


# ── Preservation Test 1: Default Path Preservation ───────────────────────────


class TestDefaultPathPreservation:
    """**Validates: Requirements 3.1**

    Verify that ``SkillDiscovery`` default paths remain ``~/.openclaw/skills/``
    and ``<workspace>/skills/``, and that ``discover_skills(None)`` resolves to
    paths containing ``~/.openclaw/skills/`` and ``./skills/``.
    """

    def test_default_paths_class_attribute(self) -> None:
        """DEFAULT_PATHS must contain the two expected default scan locations."""
        expected = ["~/.openclaw/skills/", "<workspace>/skills/"]
        assert SkillDiscovery.DEFAULT_PATHS == expected, (
            f"SkillDiscovery.DEFAULT_PATHS changed! "
            f"Expected {expected}, got {SkillDiscovery.DEFAULT_PATHS}"
        )

    def test_discover_skills_none_resolves_openclaw_path(self) -> None:
        """When paths=None, discover_skills resolves ~/.openclaw/skills/ as
        the first default path.  We inspect the source logic rather than
        hitting the filesystem (the directory may not exist)."""
        import os

        # Read the source to confirm the resolution logic
        source = SKILL_SCANNER.read_text(encoding="utf-8")

        # The discover_skills method must expand ~/.openclaw/skills/
        assert 'os.path.expanduser("~/.openclaw/skills/")' in source, (
            "discover_skills() no longer resolves ~/.openclaw/skills/ via expanduser"
        )

        # And must use cwd + skills/ as the second default
        assert 'os.path.join(os.getcwd(), "skills/")' in source or \
               'os.path.join(os.getcwd(), "skills")' in source, (
            "discover_skills() no longer resolves ./skills/ via os.getcwd()"
        )


# ── Preservation Test 2: GuardConfig Data Directory Preservation ─────────────


class TestGuardConfigDataDirectoryPreservation:
    """**Validates: Requirements 3.5**

    Verify that all path fields in ``GuardConfig`` default values point to
    ``~/.openclaw360/`` (not ``~/.openclaw/``).
    """

    def test_identity_path_uses_openclaw360(self) -> None:
        """identity_path must default to ~/.openclaw360/identity.json."""
        config = GuardConfig()
        assert "~/.openclaw360/" in config.identity_path, (
            f"identity_path does not point to ~/.openclaw360/: {config.identity_path}"
        )

    def test_rules_path_uses_openclaw360(self) -> None:
        """rules_path must default to ~/.openclaw360/rules/."""
        config = GuardConfig()
        assert "~/.openclaw360/" in config.rules_path, (
            f"rules_path does not point to ~/.openclaw360/: {config.rules_path}"
        )

    def test_audit_log_path_uses_openclaw360(self) -> None:
        """audit_log_path must default to ~/.openclaw360/audit/."""
        config = GuardConfig()
        assert "~/.openclaw360/" in config.audit_log_path, (
            f"audit_log_path does not point to ~/.openclaw360/: {config.audit_log_path}"
        )

    def test_no_path_field_uses_openclaw_without_360(self) -> None:
        """No path field in GuardConfig should use ~/.openclaw/ (without 360)."""
        config = GuardConfig()
        path_fields = {
            "identity_path": config.identity_path,
            "rules_path": config.rules_path,
            "audit_log_path": config.audit_log_path,
        }
        for field_name, value in path_fields.items():
            # Must contain ~/.openclaw360/ — not bare ~/.openclaw/
            assert "~/.openclaw360/" in value, (
                f"GuardConfig.{field_name} = {value!r} — "
                f"expected ~/.openclaw360/ prefix"
            )


# ── Preservation Test 3: CLI Parser Structure Preservation ───────────────────


class TestCLIParserStructurePreservation:
    """**Validates: Requirements 3.3, 3.4**

    Verify that ``build_parser()`` registers the expected subcommands with
    their arguments.
    """

    @pytest.fixture()
    def parser(self) -> argparse.ArgumentParser:
        from openclaw360.cli import build_parser
        return build_parser()

    def _get_subcommand_names(self, parser: argparse.ArgumentParser) -> set[str]:
        """Extract registered subcommand names from the parser."""
        for action in parser._subparsers._actions:
            if isinstance(action, argparse._SubParsersAction):
                return set(action.choices.keys())
        return set()

    def _get_subparser(
        self, parser: argparse.ArgumentParser, name: str
    ) -> argparse.ArgumentParser:
        """Get the sub-parser for a given subcommand name."""
        for action in parser._subparsers._actions:
            if isinstance(action, argparse._SubParsersAction):
                return action.choices[name]
        pytest.fail(f"Subcommand {name!r} not found")

    def test_scan_skills_subcommand_exists(self, parser: argparse.ArgumentParser) -> None:
        """scan-skills subcommand must be registered."""
        names = self._get_subcommand_names(parser)
        assert "scan-skills" in names, f"scan-skills not in subcommands: {names}"

    def test_scan_skills_has_path_argument(self, parser: argparse.ArgumentParser) -> None:
        """scan-skills must have a positional ``path`` argument."""
        sub = self._get_subparser(parser, "scan-skills")
        positional_names = [
            a.dest for a in sub._actions if not a.option_strings
        ]
        assert "path" in positional_names, (
            f"scan-skills missing 'path' positional arg. Found: {positional_names}"
        )

    def test_scan_skills_has_format_option(self, parser: argparse.ArgumentParser) -> None:
        """scan-skills must have a ``--format`` option."""
        sub = self._get_subparser(parser, "scan-skills")
        option_strings = [s for a in sub._actions for s in a.option_strings]
        assert "--format" in option_strings, (
            f"scan-skills missing --format option. Found: {option_strings}"
        )

    def test_scan_skills_has_lang_option(self, parser: argparse.ArgumentParser) -> None:
        """scan-skills must have a ``--lang`` option."""
        sub = self._get_subparser(parser, "scan-skills")
        option_strings = [s for a in sub._actions for s in a.option_strings]
        assert "--lang" in option_strings, (
            f"scan-skills missing --lang option. Found: {option_strings}"
        )

    def test_check_prompt_subcommand_exists(self, parser: argparse.ArgumentParser) -> None:
        """check-prompt subcommand must be registered."""
        names = self._get_subcommand_names(parser)
        assert "check-prompt" in names, f"check-prompt not in subcommands: {names}"

    def test_check_tool_subcommand_exists(self, parser: argparse.ArgumentParser) -> None:
        """check-tool subcommand must be registered."""
        names = self._get_subcommand_names(parser)
        assert "check-tool" in names, f"check-tool not in subcommands: {names}"

    def test_check_output_subcommand_exists(self, parser: argparse.ArgumentParser) -> None:
        """check-output subcommand must be registered."""
        names = self._get_subcommand_names(parser)
        assert "check-output" in names, f"check-output not in subcommands: {names}"


# ── Preservation Test 4: SKILL.md Metadata Preservation ─────────────────────


class TestSkillMDMetadataPreservation:
    """**Validates: Requirements 3.2**

    Verify that ``metadata.clawdbot`` structure in SKILL.md frontmatter is
    preserved — ``emoji``, ``always``, ``source``, ``install``, ``requires``
    fields all exist.
    """

    @pytest.fixture()
    def clawdbot_metadata(self) -> dict:
        content = SKILL_MD.read_text(encoding="utf-8")
        fm = _parse_frontmatter(content)
        meta = fm.get("metadata", {}).get("clawdbot", {})
        assert meta, "metadata.clawdbot section missing from SKILL.md frontmatter"
        return meta

    def test_emoji_field_exists(self, clawdbot_metadata: dict) -> None:
        assert "emoji" in clawdbot_metadata, "metadata.clawdbot.emoji missing"

    def test_always_field_exists(self, clawdbot_metadata: dict) -> None:
        assert "always" in clawdbot_metadata, "metadata.clawdbot.always missing"

    def test_source_field_exists(self, clawdbot_metadata: dict) -> None:
        assert "source" in clawdbot_metadata, "metadata.clawdbot.source missing"

    def test_install_field_exists(self, clawdbot_metadata: dict) -> None:
        assert "install" in clawdbot_metadata, "metadata.clawdbot.install missing"

    def test_requires_field_exists(self, clawdbot_metadata: dict) -> None:
        assert "requires" in clawdbot_metadata, "metadata.clawdbot.requires missing"
