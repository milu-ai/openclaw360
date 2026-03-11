"""Unit tests for AgentIdentityManager."""

import json
import os
import stat
import uuid

import pytest

from openclaw360.identity import AgentIdentityManager
from openclaw360.models import AgentIdentity


class TestCreateIdentity:
    """Requirement 5.1: Generate Ed25519 key pair and UUID v4 identity."""

    def test_creates_valid_identity(self):
        mgr = AgentIdentityManager()
        identity = mgr.create_identity("openclaw", "0.1.0")

        assert isinstance(identity, AgentIdentity)
        assert identity.framework == "openclaw"
        assert identity.version == "0.1.0"

    def test_agent_id_is_uuid4(self):
        mgr = AgentIdentityManager()
        identity = mgr.create_identity("openclaw", "0.1.0")

        parsed = uuid.UUID(identity.agent_id)
        assert parsed.version == 4

    def test_public_key_is_32_bytes(self):
        mgr = AgentIdentityManager()
        identity = mgr.create_identity("openclaw", "0.1.0")

        # Ed25519 public keys are 32 bytes raw
        assert len(identity.public_key) == 32

    def test_created_at_is_iso_format(self):
        mgr = AgentIdentityManager()
        identity = mgr.create_identity("openclaw", "0.1.0")

        from datetime import datetime

        # Should parse without error
        datetime.fromisoformat(identity.created_at)

    def test_identity_stored_on_manager(self):
        mgr = AgentIdentityManager()
        identity = mgr.create_identity("openclaw", "0.1.0")

        assert mgr.identity is identity

    def test_each_call_generates_unique_id(self):
        mgr = AgentIdentityManager()
        id1 = mgr.create_identity("openclaw", "0.1.0")
        id2 = mgr.create_identity("openclaw", "0.1.0")

        assert id1.agent_id != id2.agent_id


class TestSignAndVerify:
    """Requirements 5.2, 5.3, 5.4: Sign actions and verify signatures."""

    def test_sign_and_verify_roundtrip(self):
        mgr = AgentIdentityManager()
        identity = mgr.create_identity("openclaw", "0.1.0")

        data = b"tool_call:shell_execute:rm -rf /"
        signature = mgr.sign_action(data)

        assert mgr.verify_signature(data, signature, identity.public_key) is True

    def test_verify_fails_with_wrong_public_key(self):
        mgr = AgentIdentityManager()
        mgr.create_identity("openclaw", "0.1.0")

        data = b"some action data"
        signature = mgr.sign_action(data)

        # Create a different key pair
        other_mgr = AgentIdentityManager()
        other_identity = other_mgr.create_identity("openclaw", "0.1.0")

        assert (
            mgr.verify_signature(data, signature, other_identity.public_key) is False
        )

    def test_verify_fails_with_tampered_data(self):
        mgr = AgentIdentityManager()
        identity = mgr.create_identity("openclaw", "0.1.0")

        data = b"original data"
        signature = mgr.sign_action(data)

        tampered = b"tampered data"
        assert mgr.verify_signature(tampered, signature, identity.public_key) is False

    def test_sign_without_identity_raises(self):
        mgr = AgentIdentityManager()

        with pytest.raises(RuntimeError, match="No private key"):
            mgr.sign_action(b"data")

    def test_verify_with_invalid_public_key_returns_false(self):
        mgr = AgentIdentityManager()
        assert mgr.verify_signature(b"data", b"sig", b"bad_key") is False


class TestSaveAndLoadIdentity:
    """Requirements 5.1, 5.6: Persist identity with 0600 key permissions."""

    def test_save_and_load_roundtrip(self, tmp_path):
        mgr = AgentIdentityManager()
        original = mgr.create_identity("openclaw", "0.1.0")

        identity_path = str(tmp_path / "identity.json")
        mgr.save_identity(identity_path)

        # Load into a fresh manager
        new_mgr = AgentIdentityManager()
        loaded = new_mgr.load_identity(identity_path)

        assert loaded.agent_id == original.agent_id
        assert loaded.public_key == original.public_key
        assert loaded.framework == original.framework
        assert loaded.version == original.version

    def test_loaded_identity_can_sign_and_verify(self, tmp_path):
        mgr = AgentIdentityManager()
        original = mgr.create_identity("openclaw", "0.1.0")

        identity_path = str(tmp_path / "identity.json")
        mgr.save_identity(identity_path)

        new_mgr = AgentIdentityManager()
        new_mgr.load_identity(identity_path)

        data = b"test action"
        signature = new_mgr.sign_action(data)
        assert new_mgr.verify_signature(data, signature, original.public_key) is True

    def test_private_key_file_has_0600_permissions(self, tmp_path):
        mgr = AgentIdentityManager()
        mgr.create_identity("openclaw", "0.1.0")

        identity_path = str(tmp_path / "identity.json")
        mgr.save_identity(identity_path)

        key_path = tmp_path / "identity.key"
        mode = stat.S_IMODE(os.stat(key_path).st_mode)
        assert mode == 0o600

    def test_identity_json_contains_expected_fields(self, tmp_path):
        mgr = AgentIdentityManager()
        identity = mgr.create_identity("openclaw", "0.1.0")

        identity_path = str(tmp_path / "identity.json")
        mgr.save_identity(identity_path)

        data = json.loads((tmp_path / "identity.json").read_text())
        assert data["agent_id"] == identity.agent_id
        assert data["public_key"] == identity.public_key.hex()
        assert data["framework"] == "openclaw"
        assert data["version"] == "0.1.0"
        assert "created_at" in data

    def test_save_creates_parent_directories(self, tmp_path):
        mgr = AgentIdentityManager()
        mgr.create_identity("openclaw", "0.1.0")

        deep_path = str(tmp_path / "a" / "b" / "identity.json")
        mgr.save_identity(deep_path)

        assert os.path.exists(deep_path)

    def test_save_without_identity_raises(self, tmp_path):
        mgr = AgentIdentityManager()

        with pytest.raises(RuntimeError, match="No identity to save"):
            mgr.save_identity(str(tmp_path / "identity.json"))

    def test_load_nonexistent_file_raises(self, tmp_path):
        mgr = AgentIdentityManager()

        with pytest.raises(FileNotFoundError):
            mgr.load_identity(str(tmp_path / "nonexistent.json"))


class TestCorruptedKeyHandling:
    """Requirement 5.5: Corrupted key file triggers regeneration and revocation."""

    def test_corrupted_key_generates_new_identity(self, tmp_path):
        mgr = AgentIdentityManager()
        original = mgr.create_identity("openclaw", "0.1.0")

        identity_path = str(tmp_path / "identity.json")
        mgr.save_identity(identity_path)

        # Corrupt the key file
        key_path = tmp_path / "identity.key"
        key_path.write_text("corrupted data")

        new_mgr = AgentIdentityManager()
        loaded = new_mgr.load_identity(identity_path)

        # New identity should have a different agent_id
        assert loaded.agent_id != original.agent_id
        # But same framework/version
        assert loaded.framework == original.framework
        assert loaded.version == original.version

    def test_corrupted_key_marks_old_identity_revoked(self, tmp_path):
        mgr = AgentIdentityManager()
        original = mgr.create_identity("openclaw", "0.1.0")

        identity_path = str(tmp_path / "identity.json")
        mgr.save_identity(identity_path)

        # Corrupt the key file
        key_path = tmp_path / "identity.key"
        key_path.write_text("corrupted data")

        new_mgr = AgentIdentityManager()
        new_mgr.load_identity(identity_path)

        assert original.agent_id in new_mgr.revoked_ids

    def test_missing_key_file_generates_new_identity(self, tmp_path):
        mgr = AgentIdentityManager()
        original = mgr.create_identity("openclaw", "0.1.0")

        identity_path = str(tmp_path / "identity.json")
        mgr.save_identity(identity_path)

        # Delete the key file
        key_path = tmp_path / "identity.key"
        key_path.unlink()

        new_mgr = AgentIdentityManager()
        loaded = new_mgr.load_identity(identity_path)

        assert loaded.agent_id != original.agent_id
        assert original.agent_id in new_mgr.revoked_ids

    def test_regenerated_identity_is_persisted(self, tmp_path):
        mgr = AgentIdentityManager()
        mgr.create_identity("openclaw", "0.1.0")

        identity_path = str(tmp_path / "identity.json")
        mgr.save_identity(identity_path)

        # Corrupt the key file
        (tmp_path / "identity.key").write_text("bad")

        new_mgr = AgentIdentityManager()
        regenerated = new_mgr.load_identity(identity_path)

        # The new identity should be saved — load again to verify
        third_mgr = AgentIdentityManager()
        reloaded = third_mgr.load_identity(identity_path)

        assert reloaded.agent_id == regenerated.agent_id
        assert reloaded.public_key == regenerated.public_key

    def test_regenerated_identity_can_sign(self, tmp_path):
        mgr = AgentIdentityManager()
        mgr.create_identity("openclaw", "0.1.0")

        identity_path = str(tmp_path / "identity.json")
        mgr.save_identity(identity_path)

        # Corrupt the key file
        (tmp_path / "identity.key").write_text("bad")

        new_mgr = AgentIdentityManager()
        new_identity = new_mgr.load_identity(identity_path)

        data = b"action after regeneration"
        sig = new_mgr.sign_action(data)
        assert new_mgr.verify_signature(data, sig, new_identity.public_key) is True
