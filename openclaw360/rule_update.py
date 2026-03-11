"""Rule Update Manager for OpenClaw360.

Handles checking, downloading, verifying, and applying rule package updates.
Supports atomic updates, rollback, and background auto-update.
"""

import json
import logging
import os
import tempfile
import threading
import time
from typing import Callable, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from openclaw360.config import GuardConfig
from openclaw360.models import AttackPattern, RulePackage, ThreatType

logger = logging.getLogger(__name__)


def _serialize_rules(rules: list[AttackPattern]) -> bytes:
    """Deterministic JSON serialization of rules for signature verification."""
    data = [
        {
            "id": r.id,
            "name": r.name,
            "category": r.category.value,
            "severity": r.severity,
            "patterns": sorted(r.patterns),
            "description": r.description,
            "examples": sorted(r.examples),
            "enabled": r.enabled,
        }
        for r in sorted(rules, key=lambda r: r.id)
    ]
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _rules_to_dicts(rules: list[AttackPattern]) -> list[dict]:
    """Convert AttackPattern list to serializable dicts."""
    return [
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
        for r in rules
    ]


def _dicts_to_rules(data: list[dict]) -> list[AttackPattern]:
    """Convert dicts back to AttackPattern list."""
    return [
        AttackPattern(
            id=d["id"],
            name=d["name"],
            category=ThreatType(d["category"]),
            severity=d["severity"],
            patterns=d["patterns"],
            description=d["description"],
            examples=d["examples"],
            enabled=d.get("enabled", True),
        )
        for d in data
    ]


class RuleUpdateManager:
    """Manages rule package updates with signature verification and atomic apply.

    Supports:
    - Checking for updates via a pluggable fetch function
    - Ed25519 signature verification of rule packages
    - Atomic rule replacement (write-to-temp then rename)
    - Version history for rollback
    - Background auto-update thread
    - Offline mode (uses local cached rules)
    """

    def __init__(
        self,
        config: GuardConfig,
        fetch_fn: Optional[Callable[[str], Optional[dict]]] = None,
    ):
        self.update_url = config.rule_update_url
        self.check_interval = config.rule_check_interval
        self.signing_public_key = config.rule_signing_public_key
        self.rules_path = os.path.expanduser(config.rules_path)
        self._fetch_fn = fetch_fn

        self._active_rules: list[AttackPattern] = []
        self._current_version: str = "0.0.0"

        self._auto_update_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        self._load_local_state()

    # ── Public properties ──────────────────────────────────────────

    @property
    def current_version(self) -> str:
        return self._current_version

    @property
    def active_rules(self) -> list[AttackPattern]:
        return list(self._active_rules)

    # ── Core API ───────────────────────────────────────────────────

    def check_update(self) -> Optional[RulePackage]:
        """Check the remote rule server for a new version.

        In MVP this is a stub that returns None unless a fetch_fn is provided.
        """
        if self._fetch_fn is None:
            return None

        try:
            url = f"{self.update_url}/latest"
            data = self._fetch_fn(url)
            if data is None:
                return None
            return self._parse_rule_package(data)
        except Exception:
            logger.warning("Failed to check for rule updates", exc_info=True)
            return None

    def apply_update(self, package: RulePackage) -> bool:
        """Verify Ed25519 signature and atomically apply a rule update.

        Returns True on success, False on failure.
        """
        # Verify signature (skip if no public key configured — dev mode)
        if self.signing_public_key:
            if not self._verify_signature(package):
                logger.warning(
                    "Rule package signature verification FAILED for version %s. "
                    "Rejecting update.",
                    package.version,
                )
                return False

        try:
            self._atomic_apply(package)
            return True
        except Exception:
            logger.error(
                "Failed to apply rule update %s", package.version, exc_info=True
            )
            return False

    def rollback(self, version: str) -> bool:
        """Rollback to a previously stored version.

        Returns True on success, False if version not found.
        """
        version_file = os.path.join(self.rules_path, "versions", f"{version}.json")
        if not os.path.exists(version_file):
            logger.warning("Rollback version %s not found", version)
            return False

        try:
            with open(version_file, "r") as f:
                data = json.load(f)

            rules = _dicts_to_rules(data["rules"])

            # Atomically replace active rules
            self._write_active_rules(rules)
            self._write_version(version)
            self._active_rules = rules
            self._current_version = version
            return True
        except Exception:
            logger.error("Failed to rollback to version %s", version, exc_info=True)
            return False

    def start_auto_update(self) -> None:
        """Start a daemon thread that periodically checks for updates."""
        if self._auto_update_thread is not None and self._auto_update_thread.is_alive():
            return

        self._stop_event.clear()
        self._auto_update_thread = threading.Thread(
            target=self._auto_update_loop, daemon=True
        )
        self._auto_update_thread.start()

    def stop_auto_update(self) -> None:
        """Stop the background auto-update thread."""
        self._stop_event.set()
        if self._auto_update_thread is not None:
            self._auto_update_thread.join(timeout=5)
            self._auto_update_thread = None

    # ── Internal helpers ───────────────────────────────────────────

    def _load_local_state(self) -> None:
        """Load current version and active rules from local storage."""
        version_file = os.path.join(self.rules_path, "version.txt")
        active_file = os.path.join(self.rules_path, "active_rules.json")

        if os.path.exists(version_file):
            try:
                with open(version_file, "r") as f:
                    self._current_version = f.read().strip()
            except Exception:
                self._current_version = "0.0.0"

        if os.path.exists(active_file):
            try:
                with open(active_file, "r") as f:
                    data = json.load(f)
                self._active_rules = _dicts_to_rules(data)
            except Exception:
                self._active_rules = []

    def _verify_signature(self, package: RulePackage) -> bool:
        """Verify the Ed25519 signature of a rule package."""
        try:
            pub_key_bytes = bytes.fromhex(self.signing_public_key)
            public_key = Ed25519PublicKey.from_public_bytes(pub_key_bytes)
            signed_data = _serialize_rules(package.rules)
            public_key.verify(package.signature, signed_data)
            return True
        except (InvalidSignature, ValueError, Exception):
            return False

    def _atomic_apply(self, package: RulePackage) -> None:
        """Atomically replace active rules and save version history.

        Writes to a temp file first, then renames for atomicity.
        """
        os.makedirs(self.rules_path, exist_ok=True)
        versions_dir = os.path.join(self.rules_path, "versions")
        os.makedirs(versions_dir, exist_ok=True)

        rules_data = _rules_to_dicts(package.rules)

        # Save version history
        version_file = os.path.join(versions_dir, f"{package.version}.json")
        version_data = {
            "version": package.version,
            "rules": rules_data,
            "published_at": package.published_at,
            "changelog": package.changelog,
        }
        self._atomic_write(version_file, json.dumps(version_data, indent=2))

        # Atomically replace active rules
        self._write_active_rules(package.rules)
        self._write_version(package.version)

        # Update in-memory state
        self._active_rules = list(package.rules)
        self._current_version = package.version

    def _write_active_rules(self, rules: list[AttackPattern]) -> None:
        """Atomically write active rules file."""
        os.makedirs(self.rules_path, exist_ok=True)
        active_file = os.path.join(self.rules_path, "active_rules.json")
        rules_data = _rules_to_dicts(rules)
        self._atomic_write(active_file, json.dumps(rules_data, indent=2))

    def _write_version(self, version: str) -> None:
        """Atomically write version file."""
        os.makedirs(self.rules_path, exist_ok=True)
        version_file = os.path.join(self.rules_path, "version.txt")
        self._atomic_write(version_file, version)

    def _atomic_write(self, target_path: str, content: str) -> None:
        """Write content to a temp file then rename for atomicity."""
        dir_name = os.path.dirname(target_path)
        fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(content)
            os.replace(tmp_path, target_path)
        except Exception:
            # Clean up temp file on failure
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def _auto_update_loop(self) -> None:
        """Background loop that checks for updates periodically."""
        while not self._stop_event.is_set():
            try:
                package = self.check_update()
                if package is not None:
                    self.apply_update(package)
            except Exception:
                logger.warning("Auto-update check failed", exc_info=True)

            self._stop_event.wait(timeout=self.check_interval)

    def _parse_rule_package(self, data: dict) -> RulePackage:
        """Parse a dict into a RulePackage."""
        rules = _dicts_to_rules(data.get("rules", []))
        signature = data.get("signature", b"")
        if isinstance(signature, str):
            signature = bytes.fromhex(signature)
        return RulePackage(
            version=data["version"],
            rules=rules,
            signature=signature,
            published_at=data.get("published_at", ""),
            changelog=data.get("changelog", ""),
        )
