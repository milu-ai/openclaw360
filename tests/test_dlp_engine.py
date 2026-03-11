"""Unit tests for DLPEngine."""

import hashlib

import pytest

from openclaw360.config import GuardConfig
from openclaw360.dlp_engine import DLPEngine, _is_private_ip, _is_valid_ip, _mask_value
from openclaw360.models import Decision, SensitiveDataMatch, SensitiveDataType


@pytest.fixture
def engine():
    return DLPEngine(GuardConfig())


# ---------------------------------------------------------------------------
# scan_text — empty / basic
# ---------------------------------------------------------------------------

class TestScanTextEmpty:
    """Requirement 4.5: empty text returns empty list."""

    def test_empty_string(self, engine):
        assert engine.scan_text("") == []

    def test_no_sensitive_data(self, engine):
        assert engine.scan_text("Hello, this is a normal sentence.") == []


# ---------------------------------------------------------------------------
# scan_text — API Key detection
# ---------------------------------------------------------------------------

class TestScanTextAPIKey:
    """Requirement 4.3: detect API keys."""

    def test_openai_key(self, engine):
        text = "key is sk-abcdefghijklmnopqrstuvwxyz0123456789"
        matches = engine.scan_text(text)
        types = [m.data_type for m in matches]
        assert SensitiveDataType.API_KEY in types

    def test_aws_access_key(self, engine):
        text = "aws key AKIAIOSFODNN7EXAMPLE"
        matches = engine.scan_text(text)
        types = [m.data_type for m in matches]
        assert SensitiveDataType.API_KEY in types

    def test_generic_api_key(self, engine):
        text = 'api_key = "abcdefghijklmnopqrstuvwxyz"'
        matches = engine.scan_text(text)
        types = [m.data_type for m in matches]
        assert SensitiveDataType.API_KEY in types


# ---------------------------------------------------------------------------
# scan_text — Password detection
# ---------------------------------------------------------------------------

class TestScanTextPassword:
    """Requirement 4.3: detect passwords."""

    def test_password_equals(self, engine):
        text = "password = mysecretpassword123 "
        matches = engine.scan_text(text)
        types = [m.data_type for m in matches]
        assert SensitiveDataType.PASSWORD in types

    def test_pwd_colon(self, engine):
        text = "pwd: hunter2 "
        matches = engine.scan_text(text)
        types = [m.data_type for m in matches]
        assert SensitiveDataType.PASSWORD in types


# ---------------------------------------------------------------------------
# scan_text — Token detection
# ---------------------------------------------------------------------------

class TestScanTextToken:
    """Requirement 4.3: detect tokens."""

    def test_github_token(self, engine):
        text = "token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        matches = engine.scan_text(text)
        types = [m.data_type for m in matches]
        assert SensitiveDataType.TOKEN in types

    def test_jwt_token(self, engine):
        # Minimal valid JWT structure
        text = "auth eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456"
        matches = engine.scan_text(text)
        types = [m.data_type for m in matches]
        assert SensitiveDataType.TOKEN in types


# ---------------------------------------------------------------------------
# scan_text — SSH Key / Private Key detection
# ---------------------------------------------------------------------------

class TestScanTextSSHKey:
    """Requirement 4.3: detect SSH keys and private keys."""

    def test_rsa_private_key(self, engine):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."
        matches = engine.scan_text(text)
        types = [m.data_type for m in matches]
        assert SensitiveDataType.SSH_KEY in types
        assert SensitiveDataType.PRIVATE_KEY in types

    def test_ec_private_key(self, engine):
        text = "-----BEGIN EC PRIVATE KEY-----"
        matches = engine.scan_text(text)
        types = [m.data_type for m in matches]
        assert SensitiveDataType.SSH_KEY in types

    def test_openssh_private_key(self, engine):
        text = "-----BEGIN OPENSSH PRIVATE KEY-----"
        matches = engine.scan_text(text)
        types = [m.data_type for m in matches]
        assert SensitiveDataType.SSH_KEY in types

    def test_generic_private_key(self, engine):
        text = "-----BEGIN PRIVATE KEY-----"
        matches = engine.scan_text(text)
        types = [m.data_type for m in matches]
        assert SensitiveDataType.PRIVATE_KEY in types


# ---------------------------------------------------------------------------
# scan_text — Credit Card detection
# ---------------------------------------------------------------------------

class TestScanTextCreditCard:
    """Requirement 4.3: detect credit card numbers."""

    def test_visa_card(self, engine):
        text = "card number 4111111111111111"
        matches = engine.scan_text(text)
        types = [m.data_type for m in matches]
        assert SensitiveDataType.CREDIT_CARD in types

    def test_mastercard(self, engine):
        text = "pay with 5500000000000004"
        matches = engine.scan_text(text)
        types = [m.data_type for m in matches]
        assert SensitiveDataType.CREDIT_CARD in types


# ---------------------------------------------------------------------------
# scan_text — Email detection
# ---------------------------------------------------------------------------

class TestScanTextEmail:
    """Requirement 4.3: detect email addresses."""

    def test_simple_email(self, engine):
        text = "contact user@example.com for info"
        matches = engine.scan_text(text)
        types = [m.data_type for m in matches]
        assert SensitiveDataType.EMAIL in types

    def test_email_with_plus(self, engine):
        text = "send to user+tag@domain.org "
        matches = engine.scan_text(text)
        types = [m.data_type for m in matches]
        assert SensitiveDataType.EMAIL in types


# ---------------------------------------------------------------------------
# scan_text — IP Address detection
# ---------------------------------------------------------------------------

class TestScanTextIPAddress:
    """Requirement 4.3: detect IP addresses, excluding private/loopback."""

    def test_public_ip(self, engine):
        text = "server at 8.8.8.8 is up"
        matches = engine.scan_text(text)
        types = [m.data_type for m in matches]
        assert SensitiveDataType.IP_ADDRESS in types

    def test_loopback_excluded(self, engine):
        text = "localhost 127.0.0.1"
        matches = engine.scan_text(text)
        ip_matches = [m for m in matches if m.data_type == SensitiveDataType.IP_ADDRESS]
        assert len(ip_matches) == 0

    def test_private_10_excluded(self, engine):
        text = "internal 10.0.0.1"
        matches = engine.scan_text(text)
        ip_matches = [m for m in matches if m.data_type == SensitiveDataType.IP_ADDRESS]
        assert len(ip_matches) == 0

    def test_private_192_168_excluded(self, engine):
        text = "lan 192.168.1.1"
        matches = engine.scan_text(text)
        ip_matches = [m for m in matches if m.data_type == SensitiveDataType.IP_ADDRESS]
        assert len(ip_matches) == 0

    def test_private_172_16_excluded(self, engine):
        text = "internal 172.16.0.1"
        matches = engine.scan_text(text)
        ip_matches = [m for m in matches if m.data_type == SensitiveDataType.IP_ADDRESS]
        assert len(ip_matches) == 0

    def test_public_172_ip_not_excluded(self, engine):
        text = "server 172.15.0.1"
        matches = engine.scan_text(text)
        ip_matches = [m for m in matches if m.data_type == SensitiveDataType.IP_ADDRESS]
        assert len(ip_matches) == 1


# ---------------------------------------------------------------------------
# scan_text — location and hash correctness
# ---------------------------------------------------------------------------

class TestScanTextLocationAndHash:
    """Requirements 4.2, 4.6: location validity and SHA-256 hash."""

    def test_location_bounds(self, engine):
        text = "contact user@example.com for info"
        matches = engine.scan_text(text)
        for m in matches:
            start, end = m.location
            assert 0 <= start < end <= len(text)

    def test_hash_is_sha256(self, engine):
        text = "contact user@example.com for info"
        matches = engine.scan_text(text)
        for m in matches:
            start, end = m.location
            raw = text[start:end]
            expected_hash = hashlib.sha256(raw.encode()).hexdigest()
            assert m.hash_value == expected_hash

    def test_location_extracts_correct_text(self, engine):
        text = "server at 8.8.8.8 is up"
        matches = engine.scan_text(text)
        ip_matches = [m for m in matches if m.data_type == SensitiveDataType.IP_ADDRESS]
        assert len(ip_matches) >= 1
        m = ip_matches[0]
        assert text[m.location[0]:m.location[1]] == "8.8.8.8"


# ---------------------------------------------------------------------------
# scan_text — original text not modified
# ---------------------------------------------------------------------------

class TestScanTextNoSideEffects:
    """Requirement 4.7: original text is not modified."""

    def test_original_text_unchanged(self, engine):
        text = 'api_key = "sk-abcdefghijklmnopqrstuvwxyz0123456789" '
        original = text
        engine.scan_text(text)
        assert text == original


# ---------------------------------------------------------------------------
# mask_value helper
# ---------------------------------------------------------------------------

class TestMaskValue:
    """Requirement 4.4: masking logic."""

    def test_long_value_keeps_first4_last4(self):
        assert _mask_value("1234567890") == "1234***7890"

    def test_exactly_9_chars(self):
        assert _mask_value("123456789") == "1234***6789"

    def test_8_chars_all_stars(self):
        assert _mask_value("12345678") == "********"

    def test_short_value_all_stars(self):
        assert _mask_value("abc") == "***"

    def test_empty_value(self):
        assert _mask_value("") == ""


# ---------------------------------------------------------------------------
# mask_sensitive_data
# ---------------------------------------------------------------------------

class TestMaskSensitiveData:
    """Requirement 4.4: masking replaces sensitive regions."""

    def test_mask_replaces_sensitive_region(self, engine):
        text = "contact user@example.com for info"
        matches = engine.scan_text(text)
        masked = engine.mask_sensitive_data(text, matches)
        assert "user@example.com" not in masked
        assert "***" in masked

    def test_mask_does_not_modify_original(self, engine):
        text = "contact user@example.com for info"
        original = text
        matches = engine.scan_text(text)
        engine.mask_sensitive_data(text, matches)
        assert text == original

    def test_mask_no_matches_returns_same(self, engine):
        text = "nothing sensitive here"
        result = engine.mask_sensitive_data(text, [])
        assert result == text

    def test_mask_multiple_matches(self, engine):
        text = "email user@example.com and server 8.8.8.8 "
        matches = engine.scan_text(text)
        masked = engine.mask_sensitive_data(text, matches)
        assert "user@example.com" not in masked
        assert "8.8.8.8" not in masked


# ---------------------------------------------------------------------------
# scan_outbound
# ---------------------------------------------------------------------------

class TestScanOutbound:
    """Requirement 4.1: outbound scanning returns SecurityResult."""

    def test_block_when_sensitive_data_found(self, engine):
        payload = 'config = {"api_key": "sk-abc123def456ghi789jkl012mno345pqr"}'
        result = engine.scan_outbound("https://api.example.com", payload)
        assert result.decision == Decision.BLOCK
        assert result.risk_score == 1.0
        assert len(result.threats) > 0

    def test_allow_when_no_sensitive_data(self, engine):
        payload = "Hello, this is a normal message."
        result = engine.scan_outbound("https://api.example.com", payload)
        assert result.decision == Decision.ALLOW
        assert result.risk_score == 0.0
        assert result.threats == []

    def test_outbound_metadata_includes_destination(self, engine):
        payload = "safe payload"
        result = engine.scan_outbound("https://target.com", payload)
        assert result.metadata["destination"] == "https://target.com"

    def test_outbound_block_includes_data_types(self, engine):
        payload = "send to user@example.com "
        result = engine.scan_outbound("https://target.com", payload)
        assert result.decision == Decision.BLOCK
        assert "email" in result.threats


# ---------------------------------------------------------------------------
# IP address helpers
# ---------------------------------------------------------------------------

class TestIPHelpers:
    def test_is_private_ip_loopback(self):
        assert _is_private_ip("127.0.0.1") is True

    def test_is_private_ip_10_range(self):
        assert _is_private_ip("10.255.0.1") is True

    def test_is_private_ip_192_168(self):
        assert _is_private_ip("192.168.0.1") is True

    def test_is_private_ip_172_16(self):
        assert _is_private_ip("172.16.0.1") is True

    def test_is_private_ip_172_31(self):
        assert _is_private_ip("172.31.255.255") is True

    def test_is_not_private_ip(self):
        assert _is_private_ip("8.8.8.8") is False

    def test_is_not_private_172_15(self):
        assert _is_private_ip("172.15.0.1") is False

    def test_is_valid_ip(self):
        assert _is_valid_ip("8.8.8.8") is True

    def test_is_valid_ip_boundary(self):
        assert _is_valid_ip("255.255.255.255") is True

    def test_is_invalid_ip_octet_too_large(self):
        assert _is_valid_ip("256.0.0.1") is False

    def test_is_invalid_ip_not_enough_parts(self):
        assert _is_valid_ip("8.8.8") is False


# ---------------------------------------------------------------------------
# DLPEngine with default config
# ---------------------------------------------------------------------------

class TestDLPEngineDefaultConfig:
    def test_creates_with_no_config(self):
        engine = DLPEngine()
        assert engine.config is not None

    def test_creates_with_explicit_config(self):
        config = GuardConfig()
        engine = DLPEngine(config)
        assert engine.config is config
