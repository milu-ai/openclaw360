"""Data Loss Prevention Engine for OpenClaw360.

Detects sensitive data in text (API keys, passwords, tokens, SSH/private keys,
credit cards, emails, IP addresses) and provides masking and outbound scanning.
"""

import hashlib
import re

from openclaw360.config import GuardConfig
from openclaw360.models import (
    Decision,
    SecurityResult,
    SensitiveDataMatch,
    SensitiveDataType,
)

# Built-in sensitive data detection patterns
SENSITIVE_PATTERNS: dict[SensitiveDataType, list[str]] = {
    SensitiveDataType.API_KEY: [
        r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?",
        r"\b(sk-[A-Za-z0-9]{32,})\b",  # OpenAI format
        r"\b(AKIA[0-9A-Z]{16})\b",  # AWS Access Key
    ],
    SensitiveDataType.PASSWORD: [
        r"(?:password|passwd|pwd)\s*[:=]\s*['\"]?(.+?)['\"]?\s",
    ],
    SensitiveDataType.TOKEN: [
        r"\b(ghp_[A-Za-z0-9]{36})\b",  # GitHub Token
        r"\b(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b",  # JWT
    ],
    SensitiveDataType.SSH_KEY: [
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    ],
    SensitiveDataType.PRIVATE_KEY: [
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    ],
    SensitiveDataType.CREDIT_CARD: [
        r"\b([3-6]\d{12,18})\b",  # 13-19 digit sequences starting with 3,4,5,6
    ],
    SensitiveDataType.EMAIL: [
        r"\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b",
    ],
    SensitiveDataType.IP_ADDRESS: [
        r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b",
    ],
}

# IP addresses to exclude (private/loopback ranges)
_EXCLUDED_IP_PREFIXES = ("127.", "0.", "10.", "192.168.", "169.254.")
_EXCLUDED_IP_EXACT = {"0.0.0.0", "255.255.255.255"}


def _is_private_ip(ip: str) -> bool:
    """Check if an IP address is private/loopback and should be excluded."""
    if ip in _EXCLUDED_IP_EXACT:
        return True
    if any(ip.startswith(prefix) for prefix in _EXCLUDED_IP_PREFIXES):
        return True
    # 172.16.0.0 - 172.31.255.255
    parts = ip.split(".")
    if len(parts) == 4:
        try:
            if parts[0] == "172" and 16 <= int(parts[1]) <= 31:
                return True
        except ValueError:
            pass
    return False


def _is_valid_ip(ip: str) -> bool:
    """Check if a string is a valid IPv4 address with each octet 0-255."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        try:
            val = int(part)
            if val < 0 or val > 255:
                return False
        except ValueError:
            return False
    return True


def _mask_value(raw_value: str) -> str:
    """Mask a sensitive value: keep first 4 and last 4 chars if len > 8, else all '*'."""
    if len(raw_value) > 8:
        return raw_value[:4] + "***" + raw_value[-4:]
    return "*" * len(raw_value)


class DLPEngine:
    """Data Loss Prevention Engine.

    Scans text for sensitive data patterns, provides masking,
    and evaluates outbound data for potential leaks.
    """

    def __init__(self, config: GuardConfig | None = None):
        self.config = config or GuardConfig()
        self._patterns = SENSITIVE_PATTERNS

    def scan_text(self, text: str) -> list[SensitiveDataMatch]:
        """Scan text for sensitive data using regex patterns.

        Args:
            text: The text to scan. Empty text returns an empty list.

        Returns:
            List of SensitiveDataMatch with data type, location, masked value,
            and SHA-256 hash. Original text is never modified.
        """
        if not text:
            return []

        matches: list[SensitiveDataMatch] = []

        for data_type, patterns in self._patterns.items():
            for pattern in patterns:
                for match in re.finditer(pattern, text):
                    # Use the captured group if present, otherwise the full match
                    if match.lastindex and match.lastindex >= 1:
                        raw_value = match.group(1)
                        start = match.start(1)
                        end = match.end(1)
                    else:
                        raw_value = match.group(0)
                        start = match.start(0)
                        end = match.end(0)

                    # IP address filtering: skip private/loopback
                    if data_type == SensitiveDataType.IP_ADDRESS:
                        if not _is_valid_ip(raw_value) or _is_private_ip(raw_value):
                            continue

                    # Zero Knowledge: only store SHA-256 hash
                    hash_value = hashlib.sha256(raw_value.encode()).hexdigest()
                    masked_value = _mask_value(raw_value)

                    matches.append(
                        SensitiveDataMatch(
                            data_type=data_type,
                            location=(start, end),
                            masked_value=masked_value,
                            hash_value=hash_value,
                        )
                    )

        return matches

    def mask_sensitive_data(self, text: str, matches: list[SensitiveDataMatch]) -> str:
        """Replace sensitive data regions with masked values.

        Sorts matches by start position descending to avoid offset issues.
        Returns a new string; the original text is not modified.

        Args:
            text: The original text.
            matches: List of SensitiveDataMatch from scan_text.

        Returns:
            A new string with sensitive regions replaced by masked values.
        """
        if not matches:
            return text

        result = text
        # Sort by start position descending so replacements don't shift offsets
        sorted_matches = sorted(matches, key=lambda m: m.location[0], reverse=True)
        for m in sorted_matches:
            start, end = m.location
            result = result[:start] + m.masked_value + result[end:]

        return result

    def scan_outbound(self, destination: str, payload: str) -> SecurityResult:
        """Scan outbound data for sensitive information.

        Args:
            destination: The target destination (URL, service name, etc.).
            payload: The data being sent outbound.

        Returns:
            SecurityResult with BLOCK if sensitive data found, ALLOW otherwise.
        """
        matches = self.scan_text(payload)

        if matches:
            threat_types = list({m.data_type.value for m in matches})
            return SecurityResult(
                decision=Decision.BLOCK,
                risk_score=1.0,
                threats=threat_types,
                reason=f"Sensitive data detected in outbound payload to {destination}",
                metadata={
                    "destination": destination,
                    "match_count": len(matches),
                    "data_types": threat_types,
                },
            )

        return SecurityResult(
            decision=Decision.ALLOW,
            risk_score=0.0,
            threats=[],
            reason=f"No sensitive data detected in outbound payload to {destination}",
            metadata={"destination": destination},
        )
