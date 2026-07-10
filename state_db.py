"""Audit state database with atomic writes, file locking, and content-hash resume.

Replaces the previous mtime-only resume logic (B10) and silent corruption
recovery (A4). State DB entries include SHA-256 of file content so that
`cp -p` style preservation does not cause silent skips.
"""
from __future__ import annotations

import contextlib
import errno
import fcntl
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterator

from logging_setup import get_logger

logger = get_logger()


class StateCorruptionError(RuntimeError):
    """Raised when the state DB exists but is unreadable / malformed."""


class _FileLock:
    """POSIX advisory file lock. No-op on Windows (best-effort)."""

    def __init__(self, fd: int) -> None:
        self._fd = fd

    def __enter__(self) -> None:
        if sys.platform == "win32":
            return
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX)
        except OSError as e:
            logger.warning("Could not acquire state DB lock: %s", e)

    def __exit__(self, exc_type, exc, tb) -> None:
        if sys.platform == "win32":
            return
        try:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
        except OSError as e:
            logger.warning("Could not release state DB lock: %s", e)


class StateDB:
    """JSON-backed audit state with atomic writes and content-hash resume.

    Schema (forward-compatible):
        {
          "version": 2,
          "processed_workflows": {
            "<rel_path>": {
              "status": "completed" | "failed",
              "last_mtime": float,
              "content_sha256": str,
              "violations": [...],
              "violations_count": int,
              "workflow_ast": {...},
              "error": str | None,
              "timestamp": str
            }
          }
        }
    """

    SCHEMA_VERSION = 2

    def __init__(self, path: Path, reset: bool = False) -> None:
        self.path = Path(path)
        self._fd: int | None = None
        if reset and self.path.exists():
            self.path.unlink()
        self._data: dict[str, Any] = self._load()
        self._open_lock()

    def _open_lock(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Open in append mode so the file is created if missing but the lock fd
        # stays valid across truncations performed by _save().
        self._fd = os.open(str(self.path), os.O_RDWR | os.O_CREAT, 0o644)

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"version": self.SCHEMA_VERSION, "processed_workflows": {}}
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                raw = f.read()
        except OSError as e:
            raise StateCorruptionError(
                f"State DB at {self.path} could not be read: {e}"
            ) from e
        if not raw.strip():
            return {"version": self.SCHEMA_VERSION, "processed_workflows": {}}
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise StateCorruptionError(
                f"State DB at {self.path} is not valid JSON: {e}. "
                "Re-run with --reset to discard and start fresh."
            ) from e
        if not isinstance(data, dict) or "processed_workflows" not in data:
            raise StateCorruptionError(
                f"State DB at {self.path} is missing required keys."
            )
        # Migrate v1 (mtime-only) entries by clearing them so they're re-audited.
        if data.get("version", 1) < 2:
            logger.info(
                "Migrating state DB from v%d to v%d (clearing mtime-only entries).",
                data.get("version", 1),
                self.SCHEMA_VERSION,
            )
            return {"version": self.SCHEMA_VERSION, "processed_workflows": {}}
        return data

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        assert self._fd is not None
        with _FileLock(self._fd):
            yield

    def _save_unlocked(self) -> None:
        """Atomically write the state DB. Caller must hold the lock."""
        tmp_fd, tmp_path = tempfile.mkstemp(
            prefix=".actions_audit_state.", suffix=".json.tmp",
            dir=str(self.path.parent),
        )
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.path)
        except OSError:
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)
            raise

    def flush(self) -> None:
        """Atomically merge in-memory changes with on-disk state, then write.

        Multiple processes (or multiple StateDB instances on the same file)
        can safely call flush concurrently. The read-modify-write happens
        entirely under the file lock.
        """
        with self._locked():
            on_disk = self._read_locked()
            # Merge: prefer the on-disk entry unless we have a fresher record.
            disk_workflows = on_disk.get("processed_workflows", {})
            mem_workflows = self._data.get("processed_workflows", {})
            merged = dict(disk_workflows)
            for k, v in mem_workflows.items():
                disk_entry = disk_workflows.get(k)
                if disk_entry is None or v.get("last_mtime", 0) >= disk_entry.get("last_mtime", 0):
                    merged[k] = v
            self._data["processed_workflows"] = merged
            self._save_unlocked()

    def _read_locked(self) -> dict[str, Any]:
        """Re-read state from disk. Caller must hold the lock."""
        if not self.path.exists():
            return {"version": self.SCHEMA_VERSION, "processed_workflows": {}}
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                raw = f.read()
        except OSError:
            return {"version": self.SCHEMA_VERSION, "processed_workflows": {}}
        if not raw.strip():
            return {"version": self.SCHEMA_VERSION, "processed_workflows": {}}
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return {"version": self.SCHEMA_VERSION, "processed_workflows": {}}
        if not isinstance(data, dict) or "processed_workflows" not in data:
            return {"version": self.SCHEMA_VERSION, "processed_workflows": {}}
        return data

    def close(self) -> None:
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None

    def __enter__(self) -> "StateDB":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def get(self, rel_path: str) -> dict[str, Any] | None:
        return self._data.get("processed_workflows", {}).get(rel_path)

    def should_skip(
        self, rel_path: str, mtime: float, content_sha256: str
    ) -> bool:
        entry = self.get(rel_path)
        if not entry:
            return False
        if entry.get("status") != "completed":
            return False
        if entry.get("last_mtime") != mtime:
            return False
        if entry.get("content_sha256") != content_sha256:
            return False
        return True

    def record(
        self,
        rel_path: str,
        mtime: float,
        content_sha256: str,
        payload: dict[str, Any],
    ) -> None:
        self._data.setdefault("processed_workflows", {})[rel_path] = {
            **payload,
            "last_mtime": mtime,
            "content_sha256": content_sha256,
        }

    def get_resume_payload(self, rel_path: str) -> dict[str, Any] | None:
        """Return the violations + AST for an entry that should be skipped."""
        return self.get(rel_path)


def compute_file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise FileNotFoundError(str(path)) from e
        raise
