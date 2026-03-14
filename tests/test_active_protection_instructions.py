"""Tests verifying SKILL.md contains correct active protection instructions.

These tests read the SKILL.md file and check that the「主动防护模式」section
contains all required patterns for the 8 correctness properties defined in
the design document.
"""

import os
import re
import pathlib

import pytest

# ---------------------------------------------------------------------------
# Constants & Helpers (Task 2.1)
# ---------------------------------------------------------------------------

SKILL_MD = pathlib.Path(__file__).resolve().parent.parent / "SKILL.md"


def _read_skill_md() -> str:
    """Return the full text of SKILL.md."""
    return SKILL_MD.read_text(encoding="utf-8")


def _extract_active_protection_section() -> str:
    """Extract the「主动防护模式」section from SKILL.md.

    Returns everything between ``### 主动防护模式`` and the next ``### ``
    heading (exclusive).
    """
    text = _read_skill_md()
    pattern = r"(### 主动防护模式\b.*?)(?=\n### |\Z)"
    match = re.search(pattern, text, re.DOTALL)
    assert match, "SKILL.md does not contain a '### 主动防护模式' section"
    return match.group(1)


def _extract_subsection(heading_keyword: str) -> str:
    """Extract a ``#### <heading_keyword>`` subsection from the active protection section.

    Returns everything between ``#### <heading_keyword>`` (partial match) and
    the next ``#### `` heading or end of section.
    """
    section = _extract_active_protection_section()
    pattern = rf"(#### [^\n]*{re.escape(heading_keyword)}[^\n]*\n.*?)(?=\n#### |\Z)"
    match = re.search(pattern, section, re.DOTALL)
    assert match, f"Active protection section missing '#### ...{heading_keyword}...' subsection"
    return match.group(1)


# ---------------------------------------------------------------------------
# P1 — BLOCK decision terminates execution (Task 2.2)
# ---------------------------------------------------------------------------


class TestP1BlockDecisionTerminatesExecution:
    """**Validates: Requirements 1.2, 2.2, 3.2, 6.2**

    Property 1: BLOCK 决策终止执行并通知用户
    For any Check_Command that returns BLOCK, the instructions mandate stopping
    execution and informing the user with reason and threats.
    """

    def test_input_check_has_block_handling(self):
        sub = _extract_subsection("输入检查")
        assert "block" in sub.lower()
        assert any(kw in sub for kw in ("停止", "拦截")), "输入检查 missing stop/block keyword"
        assert "threats" in sub or "威胁" in sub

    def test_tool_check_has_block_handling(self):
        sub = _extract_subsection("工具调用检查")
        assert "block" in sub.lower()
        assert any(kw in sub for kw in ("停止", "拦截")), "工具调用检查 missing stop/block keyword"
        assert "threats" in sub or "威胁" in sub

    def test_output_check_has_block_handling(self):
        sub = _extract_subsection("输出检查")
        assert "block" in sub.lower()
        assert "threats" in sub or "威胁" in sub

    def test_block_includes_reason(self):
        section = _extract_active_protection_section()
        assert "reason" in section, "Section should mention 'reason' for BLOCK notifications"


# ---------------------------------------------------------------------------
# P2 — CONFIRM decision pauses and requests user confirmation (Task 2.3)
# ---------------------------------------------------------------------------


class TestP2ConfirmDecisionPauses:
    """**Validates: Requirements 1.3, 2.3, 6.3**

    Property 2: CONFIRM 决策暂停并请求用户确认
    For check-prompt and check-tool, CONFIRM mandates pausing, displaying
    risk_score and threats, and waiting for user confirmation.
    """

    def test_input_check_has_confirm_handling(self):
        sub = _extract_subsection("输入检查")
        assert "confirm" in sub.lower()
        assert any(kw in sub for kw in ("暂停", "等待")), "输入检查 missing pause keyword"
        assert "risk_score" in sub
        assert "threats" in sub or "威胁" in sub

    def test_tool_check_has_confirm_handling(self):
        sub = _extract_subsection("工具调用检查")
        assert "confirm" in sub.lower()
        assert any(kw in sub for kw in ("暂停", "等待", "确认")), "工具调用检查 missing confirm keyword"
        assert "risk_score" in sub

    def test_confirm_requires_user_confirmation(self):
        section = _extract_active_protection_section()
        assert "确认" in section, "Section should mention user confirmation"


# ---------------------------------------------------------------------------
# P3 — Three-phase execution order (Task 2.4)
# ---------------------------------------------------------------------------


class TestP3ThreePhaseExecutionOrder:
    """**Validates: Requirements 1.1, 2.1, 3.1, 8.1, 8.2, 8.3, 8.4**

    Property 3: 三阶段执行顺序
    check-prompt before processing, check-tool before each tool invocation,
    check-output before returning response — in this order in the document.
    """

    def test_three_subsections_exist(self):
        section = _extract_active_protection_section()
        assert "输入检查" in section
        assert "工具调用检查" in section
        assert "输出检查" in section

    def test_check_prompt_before_check_tool(self):
        section = _extract_active_protection_section()
        pos_prompt = section.index("check-prompt")
        pos_tool = section.index("check-tool")
        assert pos_prompt < pos_tool, "check-prompt should appear before check-tool"

    def test_check_tool_before_check_output(self):
        section = _extract_active_protection_section()
        pos_tool = section.index("check-tool")
        pos_output = section.index("check-output")
        assert pos_tool < pos_output, "check-tool should appear before check-output"

    def test_input_section_before_tool_section(self):
        section = _extract_active_protection_section()
        pos_input = section.index("输入检查")
        pos_tool = section.index("工具调用检查")
        pos_output = section.index("输出检查")
        assert pos_input < pos_tool < pos_output, (
            "Subsections must appear in order: 输入检查 → 工具调用检查 → 输出检查"
        )


# ---------------------------------------------------------------------------
# P4 — Degraded mode does not block user (Task 2.5)
# ---------------------------------------------------------------------------


class TestP4DegradedModeDoesNotBlock:
    """**Validates: Requirements 4.1, 4.2, 4.4**

    Property 4: 降级模式不阻塞用户
    On command failure, the instructions mandate continuing execution and
    informing the user with the failed command name and error details.
    """

    def test_degraded_section_exists(self):
        sub = _extract_subsection("降级处理")
        assert len(sub) > 0

    def test_continue_execution_on_failure(self):
        sub = _extract_subsection("降级处理")
        assert "继续执行" in sub or "继续" in sub, "降级处理 should instruct to continue execution"

    def test_mentions_command_failure(self):
        sub = _extract_subsection("降级处理")
        assert any(kw in sub for kw in ("不可用", "失败", "非零")), (
            "降级处理 should mention command failure scenarios"
        )

    def test_mentions_error_details(self):
        sub = _extract_subsection("降级处理")
        assert any(kw in sub for kw in ("错误", "error")), (
            "降级处理 should mention error details in notification"
        )


# ---------------------------------------------------------------------------
# P5 — ALLOW decision continues execution (Task 2.6)
# ---------------------------------------------------------------------------


class TestP5AllowDecisionContinues:
    """**Validates: Requirements 6.4**

    Property 5: ALLOW 决策继续执行
    ALLOW handling mandates continuing execution without interruption.
    """

    def test_allow_handling_exists(self):
        section = _extract_active_protection_section()
        assert "allow" in section.lower(), "Section should mention ALLOW decision"

    def test_allow_means_continue(self):
        section = _extract_active_protection_section()
        # Find lines mentioning allow and check they say to continue
        assert "继续" in section, "ALLOW handling should instruct to continue execution"

    def test_allow_in_decision_handling(self):
        sub = _extract_subsection("决策处理")
        assert "allow" in sub.lower(), "决策处理 should define ALLOW handling"
        assert "继续" in sub, "决策处理 ALLOW should say continue"


# ---------------------------------------------------------------------------
# P6 — check-output does not include CONFIRM (Task 2.7)
# ---------------------------------------------------------------------------


class TestP6CheckOutputNoConfirm:
    """**Validates: Requirement 3.3**

    Property 6: check-output 不包含 CONFIRM 处理
    The output check subsection only defines ALLOW and BLOCK, not CONFIRM.
    """

    def test_output_section_has_allow_and_block(self):
        sub = _extract_subsection("输出检查")
        assert "allow" in sub.lower(), "输出检查 should mention allow"
        assert "block" in sub.lower(), "输出检查 should mention block"

    def test_output_section_no_confirm_decision(self):
        sub = _extract_subsection("输出检查")
        # The subsection should not list confirm as a decision option.
        # We check that "confirm" does not appear as a decision handling item.
        # It may appear in a note saying "不返回 confirm", which is fine —
        # we verify there's no "如果 decision 为 `confirm`" pattern.
        assert not re.search(
            r"decision\s*为\s*[`\"']?confirm", sub, re.IGNORECASE
        ), "输出检查 should NOT have confirm as a decision handling option"

    def test_output_section_explicitly_excludes_confirm(self):
        sub = _extract_subsection("输出检查")
        # The section should explicitly state that check-output does not return confirm
        assert any(kw in sub for kw in ("不返回 confirm", "不返回confirm", "只返回 allow 或 block", "只返回allow或block")), (
            "输出检查 should explicitly state confirm is not returned"
        )


# ---------------------------------------------------------------------------
# P7 — All commands use --format json (Task 2.8)
# ---------------------------------------------------------------------------


class TestP7AllCommandsUseFormatJson:
    """**Validates: Requirement 7.1**

    Property 7: 所有 Check_Command 使用 --format json
    Every CLI command invocation in the section includes ``--format json``.
    """

    def test_check_prompt_uses_format_json(self):
        section = _extract_active_protection_section()
        # Find all check-prompt command invocations
        matches = re.findall(r"openclaw360\s+check-prompt\b[^\n]*", section)
        assert len(matches) > 0, "No check-prompt command found"
        for cmd in matches:
            assert "--format json" in cmd, f"check-prompt missing --format json: {cmd}"

    def test_check_tool_uses_format_json(self):
        section = _extract_active_protection_section()
        matches = re.findall(r"openclaw360\s+check-tool\b[^\n]*", section)
        assert len(matches) > 0, "No check-tool command found"
        for cmd in matches:
            assert "--format json" in cmd, f"check-tool missing --format json: {cmd}"

    def test_check_output_uses_format_json(self):
        section = _extract_active_protection_section()
        matches = re.findall(r"openclaw360\s+check-output\b[^\n]*", section)
        assert len(matches) > 0, "No check-output command found"
        for cmd in matches:
            assert "--format json" in cmd, f"check-output missing --format json: {cmd}"


# ---------------------------------------------------------------------------
# P8 — Decision handling completeness (Task 2.9)
# ---------------------------------------------------------------------------


class TestP8DecisionHandlingCompleteness:
    """**Validates: Requirement 6.1**

    Property 8: 决策处理完整性
    The 决策处理 subsection defines handling for all three decisions:
    allow, block, confirm.
    """

    def test_decision_section_exists(self):
        sub = _extract_subsection("决策处理")
        assert len(sub) > 0

    def test_all_three_decisions_defined(self):
        sub = _extract_subsection("决策处理")
        sub_lower = sub.lower()
        assert "allow" in sub_lower, "决策处理 missing ALLOW"
        assert "block" in sub_lower, "决策处理 missing BLOCK"
        assert "confirm" in sub_lower, "决策处理 missing CONFIRM"

    def test_block_has_action(self):
        sub = _extract_subsection("决策处理")
        assert any(kw in sub for kw in ("停止", "拦截")), "决策处理 BLOCK should define stop action"

    def test_confirm_has_action(self):
        sub = _extract_subsection("决策处理")
        assert any(kw in sub for kw in ("暂停", "等待", "确认")), "决策处理 CONFIRM should define pause action"

    def test_allow_has_action(self):
        sub = _extract_subsection("决策处理")
        assert "继续" in sub, "决策处理 ALLOW should define continue action"
