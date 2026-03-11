"""Agent Identity Manager — Ed25519 key pair management and action signing.

Handles creation, persistence, signing, and verification of agent identities.
Private keys are stored with 0600 permissions for security.
"""

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from openclaw360.models import AgentIdentity

logger = logging.getLogger(__name__)


class AgentIdentityManager:
    """Manages Agent identity creation, persistence, and action signing.

    Each agent gets a unique Ed25519 key pair and UUID v4 identity.
    The private key is used to sign actions for non-repudiation.
    """

    def __init__(self) -> None:
        self._private_key: Ed25519PrivateKey | None = None
        self._identity: AgentIdentity | None = None
        self._revoked_ids: list[str] = []

    @property
    def identity(self) -> AgentIdentity | None:
        return self._identity

    @property
    def revoked_ids(self) -> list[str]:
        return list(self._revoked_ids)

    def create_identity(self, framework: str, version: str) -> AgentIdentity:
        """Generate a new Ed25519 key pair and UUID v4 agent identity.

        Args:
            framework: The agent framework name (e.g. "openclaw").
            version: The agent version (e.g. "0.1.0").

        Returns:
            The newly created AgentIdentity.
        """
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        identity = AgentIdentity(
            agent_id=str(uuid.uuid4()),
            public_key=public_key.public_bytes(Encoding.Raw, PublicFormat.Raw),
            created_at=datetime.now(timezone.utc).isoformat(),
            framework=framework,
            version=version,
        )

        self._private_key = private_key
        self._identity = identity
        return identity

    def save_identity(self, path: str) -> None:
        """Save identity to JSON and private key to a separate file.

        The identity JSON is saved at `path`. The private key is saved
        alongside it with a `.key` suffix and 0600 permissions.

        Args:
            path: File path for the identity JSON.

        Raises:
            RuntimeError: If no identity has been created or loaded.
        """
        if self._identity is None or self._private_key is None:
            raise RuntimeError("No identity to save. Call create_identity first.")

        resolved = Path(path).expanduser()
        resolved.parent.mkdir(parents=True, exist_ok=True)

        # Save identity JSON (public info)
        identity_data = {
            "agent_id": self._identity.agent_id,
            "public_key": self._identity.public_key.hex(),
            "created_at": self._identity.created_at,
            "framework": self._identity.framework,
            "version": self._identity.version,
        }
        resolved.write_text(json.dumps(identity_data, indent=2), encoding="utf-8")

        # Save private key with 0600 permissions
        key_path = resolved.with_suffix(".key")
        key_bytes = self._private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
        # Write then set permissions (atomic-ish on POSIX)
        key_path.write_bytes(key_bytes)
        os.chmod(key_path, 0o600)

    def load_identity(self, path: str) -> AgentIdentity:
        """Load an existing identity from disk.

        If the key file is corrupted or unreadable, a new key pair is
        generated and the old identity is marked as revoked.

        Args:
            path: File path of the identity JSON.

        Returns:
            The loaded (or newly regenerated) AgentIdentity.

        Raises:
            FileNotFoundError: If the identity JSON file does not exist.
        """
        resolved = Path(path).expanduser()
        key_path = resolved.with_suffix(".key")

        # Load identity JSON
        identity_data = json.loads(resolved.read_text(encoding="utf-8"))

        identity = AgentIdentity(
            agent_id=identity_data["agent_id"],
            public_key=bytes.fromhex(identity_data["public_key"]),
            created_at=identity_data["created_at"],
            framework=identity_data["framework"],
            version=identity_data["version"],
        )

        # Try loading the private key
        try:
            key_bytes = key_path.read_bytes()
            from cryptography.hazmat.primitives.serialization import load_pem_private_key

            private_key = load_pem_private_key(key_bytes, password=None)
            if not isinstance(private_key, Ed25519PrivateKey):
                raise ValueError("Loaded key is not an Ed25519 private key")

            # Verify the loaded private key matches the public key in identity
            loaded_pub = private_key.public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw
            )
            if loaded_pub != identity.public_key:
                raise ValueError("Private key does not match identity public key")

            self._private_key = private_key
            self._identity = identity
            return identity

        except Exception as exc:
            logger.warning(
                "Key file corrupted or unreadable at %s: %s. "
                "Generating new key pair, old identity marked as revoked.",
                key_path,
                exc,
            )
            # Mark old identity as revoked
            self._revoked_ids.append(identity.agent_id)

            # Generate new key pair, keep framework/version from old identity
            new_identity = self.create_identity(
                framework=identity.framework,
                version=identity.version,
            )

            # Persist the new identity to the same path
            self.save_identity(path)

            return new_identity

    def sign_action(self, action_data: bytes) -> bytes:
        """Sign action data with the agent's Ed25519 private key.

        Args:
            action_data: The raw bytes of the action to sign.

        Returns:
            The Ed25519 signature bytes.

        Raises:
            RuntimeError: If no identity/private key is available.
        """
        if self._private_key is None:
            raise RuntimeError(
                "No private key available. Call create_identity or load_identity first."
            )
        return self._private_key.sign(action_data)

    def verify_signature(
        self, action_data: bytes, signature: bytes, public_key: bytes
    ) -> bool:
        """Verify an Ed25519 signature against action data and a public key.

        Args:
            action_data: The original action data that was signed.
            signature: The signature to verify.
            public_key: The raw Ed25519 public key bytes (32 bytes).

        Returns:
            True if the signature is valid, False otherwise.
        """
        try:
            pub = Ed25519PublicKey.from_public_bytes(public_key)
            pub.verify(signature, action_data)
            return True
        except (InvalidSignature, ValueError):
            return False
