"""Backup system for OpenClaw360 — data models, config, and validation helpers."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import shutil
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field, field_validator

if TYPE_CHECKING:
    from openclaw360.identity import AgentIdentityManager

# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

_BACKUP_ID_RE = re.compile(r"^backup-\d{8}-\d{6}(-[\w-]+)?$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def validate_backup_id(backup_id: str) -> bool:
    """Return True if *backup_id* matches ``backup-YYYYMMDD-HHMMSS[-tag]``."""
    return bool(_BACKUP_ID_RE.match(backup_id))


def validate_sha256(hash_str: str) -> bool:
    """Return True if *hash_str* is a 64-character hex string."""
    return bool(_SHA256_RE.match(hash_str))


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class BackupTrigger(Enum):
    """Backup trigger type."""

    MANUAL = "manual"
    SCHEDULED = "scheduled"
    PRE_INSTALL = "pre_install"
    PRE_RESTORE = "pre_restore"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class FileEntry:
    """A single file entry inside a backup."""

    relative_path: str
    sha256: str
    size: int
    mtime: float


@dataclass
class BackupManifest:
    """Manifest describing the full contents of a single backup."""

    backup_id: str
    created_at: str  # ISO 8601
    trigger: BackupTrigger
    tag: str
    files: list[FileEntry]
    total_size: int
    file_count: int
    signature: bytes = b""
    source_dir: str = ""


@dataclass
class BackupSnapshot:
    """Lightweight backup summary used for listing."""

    backup_id: str
    created_at: str
    trigger: BackupTrigger
    tag: str
    file_count: int
    total_size: int


@dataclass
class BackupResult:
    """Result of a backup operation."""

    success: bool
    backup_id: str = ""
    message: str = ""
    error: str = ""


@dataclass
class RestoreResult:
    """Result of a restore operation."""

    success: bool
    restored_files: int = 0
    pre_restore_backup_id: str = ""
    message: str = ""
    error: str = ""


@dataclass
class VerifyResult:
    """Result of a backup verification."""

    valid: bool
    checked_files: int = 0
    corrupted_files: list[str] = field(default_factory=list)
    signature_valid: bool = True
    message: str = ""


@dataclass
class CleanupResult:
    """Result of a cleanup operation."""

    deleted_count: int = 0
    freed_bytes: int = 0
    remaining_count: int = 0


# ---------------------------------------------------------------------------
# Configuration (Pydantic)
# ---------------------------------------------------------------------------


class BackupConfig(BaseModel):
    """Backup system configuration."""

    backup_dir: str = "~/.openclaw360/backups"
    source_dir: str = "~/.openclaw360"
    schedule_cron: str = "0 2 * * *"

    max_backups: int = Field(default=30, ge=1)
    max_backup_size_mb: int = Field(default=500, ge=10)
    retention_days: int = Field(default=90, ge=1)

    pre_install_backup: bool = True
    pre_restore_backup: bool = True

    exclude_patterns: list[str] = Field(
        default=["backups/**", "*.tmp", "*.log", "__pycache__/**"]
    )

    sign_backups: bool = True

    @field_validator("schedule_cron")
    @classmethod
    def validate_cron(cls, v: str) -> str:
        if v and len(v.split()) != 5:
            raise ValueError(f"无效的 cron 表达式: {v}")
        return v


# ---------------------------------------------------------------------------
# SnapshotEngine
# ---------------------------------------------------------------------------


class SnapshotEngine:
    """Snapshot engine — file scanning, hashing, and snapshot creation/restore."""

    def __init__(self, exclude_patterns: list[str] | None = None) -> None:
        self.exclude_patterns: list[str] = exclude_patterns or []

    def compute_file_hash(self, file_path: Path) -> str:
        """Return the SHA-256 hex digest of *file_path* using 64 KB block reads."""
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(65536)  # 64 KB
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    def _is_excluded(self, relative_path: str) -> bool:
        """Return True if *relative_path* matches any exclude pattern."""
        for pattern in self.exclude_patterns:
            if fnmatch.fnmatch(relative_path, pattern):
                return True
            # For directory glob patterns like "backups/**", also check prefix
            if pattern.endswith("/**"):
                prefix = pattern[:-3]  # strip "/**"
                if relative_path.startswith(prefix + "/") or relative_path == prefix:
                    return True
        return False

    def scan_directory(self, directory: Path) -> list[FileEntry]:
        """Recursively scan *directory*, skipping symlinks and excluded files."""
        entries: list[FileEntry] = []
        for root, dirs, files in os.walk(directory, followlinks=False):
            root_path = Path(root)
            # Filter out symlinked directories
            dirs[:] = [d for d in dirs if not (root_path / d).is_symlink()]
            for name in files:
                full_path = root_path / name
                if full_path.is_symlink():
                    continue
                rel = str(full_path.relative_to(directory))
                if self._is_excluded(rel):
                    continue
                stat = full_path.stat()
                entries.append(
                    FileEntry(
                        relative_path=rel,
                        sha256=self.compute_file_hash(full_path),
                        size=stat.st_size,
                        mtime=stat.st_mtime,
                    )
                )
        return entries

    def create_snapshot(self, source_dir: Path) -> BackupManifest:
        """Scan *source_dir* and return a populated BackupManifest."""
        files = self.scan_directory(source_dir)
        total_size = sum(f.size for f in files)
        return BackupManifest(
            backup_id="",
            created_at=datetime.now(timezone.utc).isoformat(),
            trigger=BackupTrigger.MANUAL,
            tag="",
            files=files,
            total_size=total_size,
            file_count=len(files),
            source_dir=str(source_dir),
        )

    def restore_snapshot(
        self,
        manifest: BackupManifest,
        backup_dir: Path,
        target_dir: Path,
    ) -> None:
        """Copy files listed in *manifest* from *backup_dir* to *target_dir*."""
        for entry in manifest.files:
            src = backup_dir / entry.relative_path
            dst = target_dir / entry.relative_path
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(src), str(dst))


# ---------------------------------------------------------------------------
# BackupStore
# ---------------------------------------------------------------------------


class BackupStore:
    """Backup storage layer — manages backup directory structure and persistence."""

    def __init__(self, backup_root: Path) -> None:
        self.backup_root = backup_root

    def get_backup_dir(self, backup_id: str) -> Path:
        """Return the directory path for *backup_id*."""
        return self.backup_root / backup_id

    def save_snapshot(self, manifest: BackupManifest, source_dir: Path) -> str:
        """Atomically save a backup: write to .tmp then rename.

        Returns the backup_id.
        """
        backup_id = manifest.backup_id
        final_dir = self.get_backup_dir(backup_id)
        tmp_dir = final_dir.parent / (final_dir.name + ".tmp")

        # Ensure backup root exists
        self.backup_root.mkdir(parents=True, exist_ok=True)

        # Write to tmp dir
        tmp_dir.mkdir(parents=True, exist_ok=True)
        data_dir = tmp_dir / "data"
        data_dir.mkdir(exist_ok=True)

        # Copy files
        for entry in manifest.files:
            src = source_dir / entry.relative_path
            dst = data_dir / entry.relative_path
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(src), str(dst))
            # Preserve identity.key 0600 permissions
            if entry.relative_path.endswith("identity.key"):
                os.chmod(dst, 0o600)

        # Write manifest.json
        manifest_dict = self._manifest_to_dict(manifest)
        manifest_path = tmp_dir / "manifest.json"
        manifest_path.write_text(
            json.dumps(manifest_dict, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        # Atomic rename
        os.rename(str(tmp_dir), str(final_dir))

        # Update index
        self.update_index(manifest)

        return backup_id

    def load_manifest(self, backup_id: str) -> BackupManifest:
        """Load and return the BackupManifest for *backup_id*."""
        manifest_path = self.get_backup_dir(backup_id) / "manifest.json"
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        return self._dict_to_manifest(data)

    def list_all(self) -> list[BackupSnapshot]:
        """List all backups sorted by created_at descending."""
        snapshots: list[BackupSnapshot] = []
        if not self.backup_root.exists():
            return snapshots
        for entry in self.backup_root.iterdir():
            if not entry.is_dir():
                continue
            manifest_path = entry / "manifest.json"
            if not manifest_path.exists():
                continue
            try:
                data = json.loads(manifest_path.read_text(encoding="utf-8"))
                snapshots.append(
                    BackupSnapshot(
                        backup_id=data["backup_id"],
                        created_at=data["created_at"],
                        trigger=BackupTrigger(data["trigger"]),
                        tag=data.get("tag", ""),
                        file_count=data["file_count"],
                        total_size=data["total_size"],
                    )
                )
            except (json.JSONDecodeError, KeyError, ValueError):
                continue
        snapshots.sort(key=lambda s: s.created_at, reverse=True)
        return snapshots

    def delete(self, backup_id: str) -> bool:
        """Delete the backup directory for *backup_id*. Returns True on success."""
        backup_dir = self.get_backup_dir(backup_id)
        if not backup_dir.exists():
            return False
        shutil.rmtree(backup_dir)
        return True

    def get_total_size(self) -> int:
        """Return the sum of total_size across all backups."""
        return sum(s.total_size for s in self.list_all())

    def update_index(self, manifest: BackupManifest) -> None:
        """Update backup.index.json with the given manifest entry."""
        index_path = self.backup_root / "backup.index.json"
        index: list[dict] = []
        if index_path.exists():
            try:
                index = json.loads(index_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, ValueError):
                index = []

        # Remove existing entry for this backup_id
        index = [e for e in index if e.get("backup_id") != manifest.backup_id]

        # Add new entry
        index.append(
            {
                "backup_id": manifest.backup_id,
                "created_at": manifest.created_at,
                "trigger": manifest.trigger.value,
                "tag": manifest.tag,
                "file_count": manifest.file_count,
                "total_size": manifest.total_size,
            }
        )
        index_path.write_text(
            json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    # -- serialization helpers -----------------------------------------------

    @staticmethod
    def _manifest_to_dict(manifest: BackupManifest) -> dict:
        """Convert a BackupManifest to a JSON-serialisable dict."""
        d = asdict(manifest)
        d["trigger"] = manifest.trigger.value
        d["signature"] = manifest.signature.hex() if manifest.signature else ""
        return d

    @staticmethod
    def _dict_to_manifest(data: dict) -> BackupManifest:
        """Reconstruct a BackupManifest from a dict (loaded from JSON)."""
        files = [
            FileEntry(
                relative_path=f["relative_path"],
                sha256=f["sha256"],
                size=f["size"],
                mtime=f["mtime"],
            )
            for f in data.get("files", [])
        ]
        sig_hex = data.get("signature", "")
        signature = bytes.fromhex(sig_hex) if sig_hex else b""
        return BackupManifest(
            backup_id=data["backup_id"],
            created_at=data["created_at"],
            trigger=BackupTrigger(data["trigger"]),
            tag=data.get("tag", ""),
            files=files,
            total_size=data["total_size"],
            file_count=data["file_count"],
            signature=signature,
            source_dir=data.get("source_dir", ""),
        )


# ---------------------------------------------------------------------------
# BackupVerifier
# ---------------------------------------------------------------------------


class BackupVerifier:
    """Backup integrity verifier — hash checking and Ed25519 signing."""

    def __init__(self, identity_manager: AgentIdentityManager | None = None) -> None:
        self.identity_manager = identity_manager

    def verify(self, manifest: BackupManifest, backup_dir: Path) -> VerifyResult:
        """Verify each file in *manifest* against *backup_dir*.

        Returns a VerifyResult with corrupted_files listing any mismatches.
        """
        engine = SnapshotEngine()
        corrupted: list[str] = []
        checked = 0
        for entry in manifest.files:
            file_path = backup_dir / entry.relative_path
            if not file_path.exists():
                corrupted.append(entry.relative_path)
                checked += 1
                continue
            actual_hash = engine.compute_file_hash(file_path)
            if actual_hash != entry.sha256:
                corrupted.append(entry.relative_path)
            checked += 1
        valid = len(corrupted) == 0
        return VerifyResult(
            valid=valid,
            checked_files=checked,
            corrupted_files=corrupted,
        )

    def _canonical_manifest_json(self, manifest: BackupManifest) -> bytes:
        """Serialize manifest to canonical JSON for signing (no signature field)."""
        d = asdict(manifest)
        d["trigger"] = manifest.trigger.value
        d.pop("signature", None)
        return json.dumps(d, sort_keys=True, ensure_ascii=False).encode("utf-8")

    def sign_manifest(self, manifest: BackupManifest) -> bytes:
        """Sign the manifest content with Ed25519 using the identity_manager."""
        if self.identity_manager is None:
            raise RuntimeError("No identity_manager available for signing.")
        data = self._canonical_manifest_json(manifest)
        return self.identity_manager.sign_action(data)

    def verify_signature(self, manifest: BackupManifest, signature: bytes) -> bool:
        """Verify an Ed25519 signature against the manifest content."""
        if self.identity_manager is None:
            raise RuntimeError("No identity_manager available for verification.")
        identity = self.identity_manager.identity
        if identity is None:
            return False
        data = self._canonical_manifest_json(manifest)
        return self.identity_manager.verify_signature(data, signature, identity.public_key)

# ---------------------------------------------------------------------------
# BackupManager
# ---------------------------------------------------------------------------


class BackupManager:
    """Backup core manager — coordinates all backup operations."""

    def __init__(
        self,
        config: BackupConfig,
        identity_manager: "AgentIdentityManager | None" = None,
    ) -> None:
        self.config = config
        self.snapshot_engine = SnapshotEngine(config.exclude_patterns)
        self.store = BackupStore(Path(os.path.expanduser(config.backup_dir)))
        self.verifier = BackupVerifier(identity_manager)
        self.identity_manager = identity_manager

    # -- backup_id generation ------------------------------------------------

    _last_ts: str = ""

    def _generate_backup_id(self, tag: str) -> str:
        """Generate a unique backup_id: ``backup-YYYYMMDD-HHMMSS[-tag]``."""
        import time

        now = datetime.now(timezone.utc)
        ts = now.strftime("%Y%m%d-%H%M%S")
        # Ensure uniqueness for rapid successive calls
        if ts == self.__class__._last_ts:
            time.sleep(0.01)
            now = datetime.now(timezone.utc)
            ts = now.strftime("%Y%m%d-%H%M%S")
        # If still the same (sub-second), append microseconds
        if ts == self.__class__._last_ts:
            ts = now.strftime("%Y%m%d-%H%M%S") + f"-{now.microsecond}"
        self.__class__._last_ts = ts
        suffix = f"-{tag}" if tag else ""
        return f"backup-{ts}{suffix}"

    # -- create_backup -------------------------------------------------------

    def create_backup(
        self,
        tag: str = "",
        trigger: BackupTrigger = BackupTrigger.MANUAL,
    ) -> BackupResult:
        """Create a full backup snapshot.

        Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 2.1, 2.2, 2.3
        """
        backup_id = self._generate_backup_id(tag)
        source_dir = Path(os.path.expanduser(self.config.source_dir))
        tmp_dir = self.store.get_backup_dir(backup_id).parent / (backup_id + ".tmp")

        try:
            # Create snapshot manifest
            manifest = self.snapshot_engine.create_snapshot(source_dir)
            manifest.backup_id = backup_id
            manifest.trigger = trigger
            manifest.tag = tag
            manifest.source_dir = str(source_dir)

            # Sign manifest before saving
            if self.config.sign_backups and self.identity_manager:
                manifest.signature = self.verifier.sign_manifest(manifest)

            # Save via BackupStore (handles atomic .tmp + rename)
            self.store.save_snapshot(manifest, source_dir)

            # Trigger cleanup after success
            self.cleanup()

            return BackupResult(success=True, backup_id=backup_id)

        except Exception as e:
            # Atomic cleanup: remove tmp dir if it exists
            if tmp_dir.exists():
                shutil.rmtree(tmp_dir, ignore_errors=True)
            # Also remove final dir if partially created
            final_dir = self.store.get_backup_dir(backup_id)
            if final_dir.exists():
                shutil.rmtree(final_dir, ignore_errors=True)
            return BackupResult(success=False, error=str(e))

    # -- restore_backup ------------------------------------------------------

    def restore_backup(self, backup_id: str) -> RestoreResult:
        """Restore from a specified backup.

        Requirements: 3.1, 3.2, 3.3, 3.4, 4.1, 4.2
        """
        try:
            # Load and verify backup integrity
            manifest = self.store.load_manifest(backup_id)
            backup_data_dir = self.store.get_backup_dir(backup_id) / "data"
            verify_result = self.verifier.verify(manifest, backup_data_dir)
            if not verify_result.valid:
                return RestoreResult(
                    success=False,
                    error=f"备份校验失败: {verify_result.corrupted_files}",
                )

            # Pre-restore backup (safety net)
            pre_restore_id = ""
            if self.config.pre_restore_backup:
                pre_result = self.create_backup(
                    tag="pre-restore",
                    trigger=BackupTrigger.PRE_RESTORE,
                )
                if pre_result.success:
                    pre_restore_id = pre_result.backup_id

            # Atomic restore
            target_dir = Path(os.path.expanduser(self.config.source_dir))
            tmp_restore = target_dir.parent / (target_dir.name + ".restore-tmp")

            # Copy current dir for rollback
            if tmp_restore.exists():
                shutil.rmtree(tmp_restore, ignore_errors=True)
            if target_dir.exists():
                shutil.copytree(str(target_dir), str(tmp_restore))

            # Restore files
            restored_count = 0
            for entry in manifest.files:
                src = backup_data_dir / entry.relative_path
                dst = target_dir / entry.relative_path
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(src), str(dst))

                # Verify hash after restore
                actual_hash = self.snapshot_engine.compute_file_hash(dst)
                if actual_hash != entry.sha256:
                    raise RuntimeError(
                        f"Hash mismatch after restore: {entry.relative_path}"
                    )
                restored_count += 1

            # Success — clean up rollback dir
            if tmp_restore.exists():
                shutil.rmtree(tmp_restore, ignore_errors=True)

            return RestoreResult(
                success=True,
                restored_files=restored_count,
                pre_restore_backup_id=pre_restore_id,
            )

        except Exception as e:
            # Rollback from tmp_restore
            target_dir = Path(os.path.expanduser(self.config.source_dir))
            tmp_restore = target_dir.parent / (target_dir.name + ".restore-tmp")
            if tmp_restore.exists():
                if target_dir.exists():
                    shutil.rmtree(target_dir, ignore_errors=True)
                tmp_restore.rename(target_dir)
            return RestoreResult(success=False, error=f"恢复失败，已回滚: {e}")

    # -- cleanup -------------------------------------------------------------

    def cleanup(self) -> CleanupResult:
        """Clean up backups based on retention policy.

        Priority-based deletion: SCHEDULED(0) > MANUAL(1) > PRE_INSTALL(2) > PRE_RESTORE(3)
        Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6
        """
        backups = self.store.list_all()
        original_count = len(backups)
        now = datetime.now(timezone.utc)

        # Sort by (priority, created_at) — lowest priority + oldest first
        priority = {
            BackupTrigger.SCHEDULED: 0,
            BackupTrigger.MANUAL: 1,
            BackupTrigger.PRE_INSTALL: 2,
            BackupTrigger.PRE_RESTORE: 3,
        }
        backups.sort(key=lambda b: (priority.get(b.trigger, 0), b.created_at))

        to_delete: list[str] = []

        # Rule 1: delete backups older than retention_days
        for b in backups:
            created = datetime.fromisoformat(b.created_at)
            # Ensure created is timezone-aware for comparison
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age_days = (now - created).days
            if age_days > self.config.retention_days:
                to_delete.append(b.backup_id)

        # Rule 2: if still > max_backups, delete lowest priority + oldest
        remaining = [b for b in backups if b.backup_id not in to_delete]
        while len(remaining) > self.config.max_backups:
            victim = remaining.pop(0)  # lowest priority + oldest
            to_delete.append(victim.backup_id)

        # Rule 3: if total size > max_backup_size_mb, delete more
        remaining = [b for b in backups if b.backup_id not in to_delete]
        total_size = sum(b.total_size for b in remaining)
        max_bytes = self.config.max_backup_size_mb * 1024 * 1024
        while total_size > max_bytes and remaining:
            victim = remaining.pop(0)
            to_delete.append(victim.backup_id)
            total_size -= victim.total_size

        # Execute deletions
        deleted_count = 0
        freed_bytes = 0
        for backup_id in to_delete:
            # Find the backup's size for freed_bytes tracking
            matching = [b for b in backups if b.backup_id == backup_id]
            if matching:
                freed_bytes += matching[0].total_size
            if self.store.delete(backup_id):
                deleted_count += 1

        remaining_count = original_count - deleted_count
        return CleanupResult(
            deleted_count=deleted_count,
            freed_bytes=freed_bytes,
            remaining_count=remaining_count,
        )

    # -- list_backups --------------------------------------------------------

    def list_backups(
        self,
        limit: int = 20,
        trigger_filter: BackupTrigger | None = None,
    ) -> list[BackupSnapshot]:
        """List backups, optionally filtered by trigger type.

        Requirements: 12.3, 12.4, 12.6
        """
        snapshots = self.store.list_all()
        if trigger_filter is not None:
            snapshots = [s for s in snapshots if s.trigger == trigger_filter]
        return snapshots[:limit]

    # -- delete_backup -------------------------------------------------------

    def delete_backup(self, backup_id: str) -> bool:
        """Delete a specific backup.

        Requirements: 12.4
        """
        return self.store.delete(backup_id)

    # -- verify_backup -------------------------------------------------------

    def verify_backup(self, backup_id: str) -> VerifyResult:
        """Verify the integrity of a specific backup.

        Requirements: 12.6
        """
        manifest = self.store.load_manifest(backup_id)
        backup_data_dir = self.store.get_backup_dir(backup_id) / "data"
        return self.verifier.verify(manifest, backup_data_dir)



# ---------------------------------------------------------------------------
# BackupScheduler — cron-based scheduled backups (Requirements: 10.1–10.4)
# ---------------------------------------------------------------------------


def _parse_cron_next(cron_expr: str, now: datetime | None = None) -> datetime:
    """Parse a 5-field cron expression and compute the next matching datetime.

    Supports: minute, hour, day-of-month, month, day-of-week.
    Each field may be ``*`` (any) or a single integer value.
    """
    parts = cron_expr.split()
    if len(parts) != 5:
        raise ValueError(f"Invalid cron expression: {cron_expr}")

    def _match(field_val: str, current: int) -> bool:
        if field_val == "*":
            return True
        return int(field_val) == current

    if now is None:
        now = datetime.now(timezone.utc)

    # Start searching from the next minute
    candidate = now.replace(second=0, microsecond=0)
    from datetime import timedelta

    candidate += timedelta(minutes=1)

    # Search up to 366 days ahead (enough for any valid cron)
    limit = 366 * 24 * 60
    for _ in range(limit):
        minute_ok = _match(parts[0], candidate.minute)
        hour_ok = _match(parts[1], candidate.hour)
        dom_ok = _match(parts[2], candidate.day)
        month_ok = _match(parts[3], candidate.month)
        # cron day-of-week: 0=Sunday … 6=Saturday
        dow_ok = _match(parts[4], (candidate.weekday() + 1) % 7)

        if minute_ok and hour_ok and dom_ok and month_ok and dow_ok:
            return candidate
        candidate += timedelta(minutes=1)

    raise RuntimeError(f"Could not find next run time for cron: {cron_expr}")


class BackupScheduler:
    """Scheduled backup scheduler using cron expressions.

    Requirements: 10.1, 10.2, 10.3, 10.4
    """

    def __init__(self, config: BackupConfig, backup_manager: BackupManager) -> None:
        self._config = config
        self._manager = backup_manager
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._next_run: datetime | None = None

    # -- public API ----------------------------------------------------------

    def start(self) -> None:
        """Start the scheduler daemon thread.

        If ``schedule_cron`` is empty the scheduler is disabled (no-op).
        """
        if not self._config.schedule_cron:
            return  # disabled

        self._stop_event.clear()
        self._next_run = _parse_cron_next(self._config.schedule_cron)
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Signal the scheduler thread to stop and wait for it to exit."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def next_run_time(self) -> str | None:
        """Return the next scheduled run time as an ISO 8601 string, or None."""
        if self._next_run is None:
            return None
        return self._next_run.isoformat()

    def is_running(self) -> bool:
        """Return whether the scheduler thread is alive."""
        return self._thread is not None and self._thread.is_alive()

    # -- internal ------------------------------------------------------------

    def _run_loop(self) -> None:
        """Daemon thread loop: sleep until next_run_time, create backup, repeat."""
        while not self._stop_event.is_set():
            now = datetime.now(timezone.utc)
            self._next_run = _parse_cron_next(self._config.schedule_cron, now)
            wait_seconds = max(0, (self._next_run - now).total_seconds())

            # Wait, but wake up if stop is signalled
            if self._stop_event.wait(timeout=wait_seconds):
                break  # stop requested

            # Time to run
            self._manager.create_backup(trigger=BackupTrigger.SCHEDULED)


# ---------------------------------------------------------------------------
# SkillInstallHook — pre-install backup hook (Requirements: 9.1–9.3)
# ---------------------------------------------------------------------------


class SkillInstallHook:
    """Pre-install backup hook for Skill installation.

    Creates a backup before a Skill is installed so the user can roll back
    if the new Skill causes problems.

    Requirements: 9.1, 9.2, 9.3
    """

    def __init__(self, backup_manager: BackupManager) -> None:
        self._manager = backup_manager

    def pre_install_backup(self, skill_name: str) -> BackupResult:
        """Create a PRE_INSTALL backup tagged with the skill name.

        Returns the ``BackupResult``.  If ``result.success`` is False the
        caller should **not** proceed with the installation.
        """
        return self._manager.create_backup(
            tag=f"pre-install-{skill_name}",
            trigger=BackupTrigger.PRE_INSTALL,
        )
