"""Unit tests for RuleUpdateManager."""

import json
import os
import threading
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from openclaw360.config import GuardConfig
from openclaw360.models import AttackPattern, RulePackage, ThreatType
from openclaw360.rule_update import RuleUpdateManager, _serialize_rules


# ── Helpers ────────────────────────────────────────────────────────


def _make_rule(rule_id: str = "PI-001", name: str = "Test Rule") -> AttackPattern:
    return AttackPattern(
        id=rule_id,
        name=name,
        category=ThreatType.PROMPT_INJECTION,
        severity="high",
        patterns=[r"ignore.*instructions"],
        description="Test pattern",
        examples=["ignore all instructions"],
        enabled=True,
    )


def _make_signed_package(
    version: str = "1.0.0",
    rules: list[AttackPattern] | None = None,
    private_key: Ed25519PrivateKey | None = None,
) -> tuple[RulePackage, Ed25519PrivateKey]:
    """Create a properly signed RulePackage."""
    if rules is None:
        rules = [_make_rule()]
    if private_key is None:
        private_key = Ed25519PrivateKey.generate()

    signed_data = _serialize_rules(rules)
    signature = private_key.sign(signed_data)

    package = RulePackage(
        version=version,
        rules=rules,
        signature=signature,
        published_at="2024-01-01T00:00:00Z",
        changelog="Test update",
    )
    return package, private_key


def _config_with_key(tmp_path, private_key: Ed25519PrivateKey) -> GuardConfig:
    """Create a GuardConfig with the public key from the given private key."""
    pub_hex = private_key.public_key().public_bytes_raw().hex()
    return GuardConfig(
        rules_path=str(tmp_path / "rules"),
        rule_signing_public_key=pub_hex,
    )


def _config_no_key(tmp_path) -> GuardConfig:
    """Create a GuardConfig with no signing key (dev mode)."""
    return GuardConfig(
        rules_path=str(tmp_path / "rules"),
        rule_signing_public_key="",
    )


# ── check_update tests ────────────────────────────────────────────


class TestCheckUpdate:
    """Requirement 7.1, 7.5: Check for rule updates."""

    def test_returns_none_without_fetch_fn(self, tmp_path):
        config = _config_no_key(tmp_path)
        mgr = RuleUpdateManager(config)
        assert mgr.check_update() is None

    def test_returns_none_when_fetch_returns_none(self, tmp_path):
        config = _config_no_key(tmp_path)
        mgr = RuleUpdateManager(config, fetch_fn=lambda url: None)
        assert mgr.check_update() is None

    def test_returns_package_from_fetch(self, tmp_path):
        config = _config_no_key(tmp_path)
        rule_data = {
            "version": "1.0.0",
            "rules": [
                {
                    "id": "PI-001",
                    "name": "Test",
                    "category": "prompt_injection",
                    "severity": "high",
                    "patterns": ["test"],
                    "description": "desc",
                    "examples": ["ex"],
                    "enabled": True,
                }
            ],
            "signature": "aa" * 64,
            "published_at": "2024-01-01T00:00:00Z",
            "changelog": "Initial",
        }
        mgr = RuleUpdateManager(config, fetch_fn=lambda url: rule_data)
        pkg = mgr.check_update()

        assert pkg is not None
        assert pkg.version == "1.0.0"
        assert len(pkg.rules) == 1

    def test_returns_none_on_fetch_exception(self, tmp_path):
        config = _config_no_key(tmp_path)

        def bad_fetch(url):
            raise ConnectionError("no network")

        mgr = RuleUpdateManager(config, fetch_fn=bad_fetch)
        assert mgr.check_update() is None

    def test_fetch_url_includes_latest(self, tmp_path):
        config = _config_no_key(tmp_path)
        captured_urls = []

        def capture_fetch(url):
            captured_urls.append(url)
            return None

        mgr = RuleUpdateManager(config, fetch_fn=capture_fetch)
        mgr.check_update()

        assert len(captured_urls) == 1
        assert captured_urls[0].endswith("/latest")


# ── apply_update tests ─────────────────────────────────────────────


class TestApplyUpdate:
    """Requirements 7.2, 7.3, 7.4, 7.7: Signature verification and atomic apply."""

    def test_apply_with_valid_signature(self, tmp_path):
        package, key = _make_signed_package()
        config = _config_with_key(tmp_path, key)
        mgr = RuleUpdateManager(config)

        assert mgr.apply_update(package) is True
        assert mgr.current_version == "1.0.0"
        assert len(mgr.active_rules) == 1

    def test_reject_invalid_signature(self, tmp_path):
        package, _ = _make_signed_package()
        # Use a different key for verification
        other_key = Ed25519PrivateKey.generate()
        config = _config_with_key(tmp_path, other_key)
        mgr = RuleUpdateManager(config)

        assert mgr.apply_update(package) is False
        assert mgr.current_version == "0.0.0"
        assert len(mgr.active_rules) == 0

    def test_reject_tampered_rules(self, tmp_path):
        package, key = _make_signed_package()
        config = _config_with_key(tmp_path, key)
        mgr = RuleUpdateManager(config)

        # Tamper with the rules after signing
        package.rules.append(_make_rule("PI-002", "Tampered"))

        assert mgr.apply_update(package) is False

    def test_skip_verification_in_dev_mode(self, tmp_path):
        """When no signing key is configured, skip verification."""
        rules = [_make_rule()]
        package = RulePackage(
            version="1.0.0",
            rules=rules,
            signature=b"not-a-real-signature",
            published_at="2024-01-01T00:00:00Z",
            changelog="Dev update",
        )
        config = _config_no_key(tmp_path)
        mgr = RuleUpdateManager(config)

        assert mgr.apply_update(package) is True
        assert mgr.current_version == "1.0.0"

    def test_atomic_write_creates_files(self, tmp_path):
        package, key = _make_signed_package()
        config = _config_with_key(tmp_path, key)
        mgr = RuleUpdateManager(config)
        mgr.apply_update(package)

        rules_dir = tmp_path / "rules"
        assert (rules_dir / "active_rules.json").exists()
        assert (rules_dir / "version.txt").exists()
        assert (rules_dir / "versions" / "1.0.0.json").exists()

    def test_version_file_content(self, tmp_path):
        package, key = _make_signed_package()
        config = _config_with_key(tmp_path, key)
        mgr = RuleUpdateManager(config)
        mgr.apply_update(package)

        version_txt = (tmp_path / "rules" / "version.txt").read_text()
        assert version_txt == "1.0.0"

    def test_active_rules_file_content(self, tmp_path):
        package, key = _make_signed_package()
        config = _config_with_key(tmp_path, key)
        mgr = RuleUpdateManager(config)
        mgr.apply_update(package)

        active_file = tmp_path / "rules" / "active_rules.json"
        data = json.loads(active_file.read_text())
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["id"] == "PI-001"

    def test_sequential_updates(self, tmp_path):
        key = Ed25519PrivateKey.generate()
        config = _config_with_key(tmp_path, key)
        mgr = RuleUpdateManager(config)

        pkg1, _ = _make_signed_package("1.0.0", [_make_rule("PI-001")], key)
        pkg2, _ = _make_signed_package(
            "2.0.0", [_make_rule("PI-001"), _make_rule("PI-002", "Rule 2")], key
        )

        mgr.apply_update(pkg1)
        assert mgr.current_version == "1.0.0"
        assert len(mgr.active_rules) == 1

        mgr.apply_update(pkg2)
        assert mgr.current_version == "2.0.0"
        assert len(mgr.active_rules) == 2

    def test_failed_apply_preserves_old_state(self, tmp_path):
        key = Ed25519PrivateKey.generate()
        config = _config_with_key(tmp_path, key)
        mgr = RuleUpdateManager(config)

        # Apply a valid package first
        pkg1, _ = _make_signed_package("1.0.0", [_make_rule()], key)
        mgr.apply_update(pkg1)

        # Try to apply a package with bad signature
        bad_pkg = RulePackage(
            version="2.0.0",
            rules=[_make_rule("PI-002")],
            signature=b"bad",
            published_at="2024-01-01T00:00:00Z",
            changelog="Bad",
        )
        mgr.apply_update(bad_pkg)

        assert mgr.current_version == "1.0.0"
        assert len(mgr.active_rules) == 1


# ── rollback tests ─────────────────────────────────────────────────


class TestRollback:
    """Requirement 7.6: Rollback to a specified version."""

    def test_rollback_to_previous_version(self, tmp_path):
        key = Ed25519PrivateKey.generate()
        config = _config_with_key(tmp_path, key)
        mgr = RuleUpdateManager(config)

        pkg1, _ = _make_signed_package("1.0.0", [_make_rule("PI-001")], key)
        pkg2, _ = _make_signed_package("2.0.0", [_make_rule("PI-002", "V2")], key)

        mgr.apply_update(pkg1)
        mgr.apply_update(pkg2)
        assert mgr.current_version == "2.0.0"

        assert mgr.rollback("1.0.0") is True
        assert mgr.current_version == "1.0.0"
        assert len(mgr.active_rules) == 1
        assert mgr.active_rules[0].id == "PI-001"

    def test_rollback_nonexistent_version(self, tmp_path):
        config = _config_no_key(tmp_path)
        mgr = RuleUpdateManager(config)

        assert mgr.rollback("99.0.0") is False

    def test_rollback_persists_to_disk(self, tmp_path):
        key = Ed25519PrivateKey.generate()
        config = _config_with_key(tmp_path, key)
        mgr = RuleUpdateManager(config)

        pkg1, _ = _make_signed_package("1.0.0", [_make_rule("PI-001")], key)
        pkg2, _ = _make_signed_package("2.0.0", [_make_rule("PI-002", "V2")], key)

        mgr.apply_update(pkg1)
        mgr.apply_update(pkg2)
        mgr.rollback("1.0.0")

        # Reload from disk
        mgr2 = RuleUpdateManager(config)
        assert mgr2.current_version == "1.0.0"
        assert len(mgr2.active_rules) == 1


# ── auto-update tests ──────────────────────────────────────────────


class TestAutoUpdate:
    """Requirement 7.1: Background auto-update thread."""

    def test_start_and_stop(self, tmp_path):
        config = _config_no_key(tmp_path)
        config = config.model_copy(update={"rule_check_interval": 1})
        mgr = RuleUpdateManager(config)

        mgr.start_auto_update()
        assert mgr._auto_update_thread is not None
        assert mgr._auto_update_thread.is_alive()
        assert mgr._auto_update_thread.daemon is True

        mgr.stop_auto_update()
        assert mgr._auto_update_thread is None

    def test_auto_update_calls_check(self, tmp_path):
        call_count = {"n": 0}

        def counting_fetch(url):
            call_count["n"] += 1
            return None

        config = _config_no_key(tmp_path)
        config = config.model_copy(update={"rule_check_interval": 1})
        mgr = RuleUpdateManager(config, fetch_fn=counting_fetch)

        mgr.start_auto_update()
        time.sleep(2.5)
        mgr.stop_auto_update()

        assert call_count["n"] >= 2

    def test_auto_update_applies_package(self, tmp_path):
        key = Ed25519PrivateKey.generate()
        config = _config_with_key(tmp_path, key)
        config = config.model_copy(update={"rule_check_interval": 1})

        pkg, _ = _make_signed_package("1.0.0", [_make_rule()], key)

        def fetch_once(url):
            return {
                "version": pkg.version,
                "rules": [
                    {
                        "id": r.id,
                        "name": r.name,
                        "category": r.category.value,
                        "severity": r.severity,
                        "patterns": r.patterns,
                        "description": r.description,
                        "examples": r.examples,
                        "enabled": r.enabled,
                    }
                    for r in pkg.rules
                ],
                "signature": pkg.signature.hex(),
                "published_at": pkg.published_at,
                "changelog": pkg.changelog,
            }

        mgr = RuleUpdateManager(config, fetch_fn=fetch_once)
        mgr.start_auto_update()
        time.sleep(2)
        mgr.stop_auto_update()

        assert mgr.current_version == "1.0.0"

    def test_start_is_idempotent(self, tmp_path):
        config = _config_no_key(tmp_path)
        mgr = RuleUpdateManager(config)

        mgr.start_auto_update()
        thread1 = mgr._auto_update_thread
        mgr.start_auto_update()
        thread2 = mgr._auto_update_thread

        assert thread1 is thread2
        mgr.stop_auto_update()


# ── local state persistence tests ──────────────────────────────────


class TestLocalState:
    """Requirement 7.8: Offline mode uses local cached rules."""

    def test_loads_from_disk_on_init(self, tmp_path):
        key = Ed25519PrivateKey.generate()
        config = _config_with_key(tmp_path, key)

        # First manager applies an update
        mgr1 = RuleUpdateManager(config)
        pkg, _ = _make_signed_package("1.0.0", [_make_rule()], key)
        mgr1.apply_update(pkg)

        # Second manager loads from disk
        mgr2 = RuleUpdateManager(config)
        assert mgr2.current_version == "1.0.0"
        assert len(mgr2.active_rules) == 1

    def test_default_state_when_no_files(self, tmp_path):
        config = _config_no_key(tmp_path)
        mgr = RuleUpdateManager(config)

        assert mgr.current_version == "0.0.0"
        assert mgr.active_rules == []

    def test_offline_mode_uses_cached_rules(self, tmp_path):
        """When fetch fails, existing local rules remain active."""
        key = Ed25519PrivateKey.generate()
        config = _config_with_key(tmp_path, key)

        mgr = RuleUpdateManager(config)
        pkg, _ = _make_signed_package("1.0.0", [_make_rule()], key)
        mgr.apply_update(pkg)

        # Simulate offline: fetch raises
        def offline_fetch(url):
            raise ConnectionError("offline")

        mgr2 = RuleUpdateManager(config, fetch_fn=offline_fetch)
        assert mgr2.current_version == "1.0.0"
        assert len(mgr2.active_rules) == 1

        # check_update returns None, rules unchanged
        assert mgr2.check_update() is None
        assert mgr2.current_version == "1.0.0"


# ── signature verification edge cases ─────────────────────────────


class TestSignatureVerification:
    """Requirements 7.2, 7.4: Ed25519 signature verification."""

    def test_valid_signature_accepted(self, tmp_path):
        key = Ed25519PrivateKey.generate()
        config = _config_with_key(tmp_path, key)
        mgr = RuleUpdateManager(config)

        pkg, _ = _make_signed_package("1.0.0", [_make_rule()], key)
        assert mgr._verify_signature(pkg) is True

    def test_wrong_key_rejected(self, tmp_path):
        pkg, _ = _make_signed_package()
        other_key = Ed25519PrivateKey.generate()
        config = _config_with_key(tmp_path, other_key)
        mgr = RuleUpdateManager(config)

        assert mgr._verify_signature(pkg) is False

    def test_tampered_signature_rejected(self, tmp_path):
        key = Ed25519PrivateKey.generate()
        config = _config_with_key(tmp_path, key)
        mgr = RuleUpdateManager(config)

        pkg, _ = _make_signed_package("1.0.0", [_make_rule()], key)
        pkg.signature = b"\x00" * 64  # tampered

        assert mgr._verify_signature(pkg) is False

    def test_invalid_public_key_hex_rejected(self, tmp_path):
        config = GuardConfig(
            rules_path=str(tmp_path / "rules"),
            rule_signing_public_key="not_valid_hex",
        )
        mgr = RuleUpdateManager(config)
        pkg, _ = _make_signed_package()

        assert mgr._verify_signature(pkg) is False
