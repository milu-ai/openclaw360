"""Custom exceptions for OpenClaw360."""


class ScanError(Exception):
    """General scanning error (e.g., path doesn't exist or is unreadable)."""

    pass


class SkillParseError(Exception):
    """SKILL.md parse error (YAML format errors, missing frontmatter)."""

    pass
