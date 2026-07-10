"""StateDB tests: atomic writes, content-hash, mtime, corruption rejection."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from state_db import (
    StateCorruptionError,
    StateDB,
    compute_file_sha256,
)


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def test_atomic_write_does_not_leave_temp_file(tmp_path: Path) -> None:
    db_path = tmp_path / "state.json"
    db = StateDB(db_path, reset=True)
    db.record(
        "a.yml",
        mtime=1.0,
        content_sha256="abc",
        payload={"status": "completed", "violations_count": 0, "violations": []},
    )
    db.flush()
    db.close()
    assert db_path.exists()
    leftovers = list(tmp_path.glob(".actions_audit_state.*.tmp"))
    assert not leftovers, f"Temp file left behind: {leftovers}"
    data = json.loads(db_path.read_text())
    assert data["version"] == 2
    assert "a.yml" in data["processed_workflows"]


def test_corruption_raises_state_corruption_error(tmp_path: Path) -> None:
    db_path = tmp_path / "state.json"
    db_path.write_text("{ this is not valid json", encoding="utf-8")
    with pytest.raises(StateCorruptionError):
        StateDB(db_path, reset=False)


def test_empty_file_is_treated_as_empty_state(tmp_path: Path) -> None:
    db_path = tmp_path / "state.json"
    db_path.write_text("", encoding="utf-8")
    db = StateDB(db_path, reset=False)
    db.close()
    assert db_path.read_text() == "" or db_path.read_text().strip() == ""


def test_resume_skips_only_on_matching_hash_and_mtime(tmp_path: Path) -> None:
    db_path = tmp_path / "state.json"
    file_path = tmp_path / "wf.yml"
    _write(file_path, "name: x\n")
    stat = file_path.stat()
    mtime = stat.st_mtime
    sha = compute_file_sha256(file_path)

    db = StateDB(db_path, reset=True)
    db.record(str(file_path), mtime, sha, {
        "status": "completed", "violations_count": 0, "violations": []
    })
    db.flush()
    db.close()

    # Same content & mtime -> skipped
    db2 = StateDB(db_path, reset=False)
    assert db2.should_skip(str(file_path), mtime, sha)
    db2.close()

    # Different sha (e.g. content edited but mtime preserved via cp -p) -> not skipped
    db3 = StateDB(db_path, reset=False)
    assert not db3.should_skip(str(file_path), mtime, "different_sha")
    db3.close()


def test_v1_migration_clears_mtime_only_entries(tmp_path: Path) -> None:
    db_path = tmp_path / "state.json"
    v1 = {
        "version": 1,
        "processed_workflows": {
            "a.yml": {"status": "completed", "last_mtime": 1.0, "violations": []}
        },
    }
    db_path.write_text(json.dumps(v1), encoding="utf-8")
    db = StateDB(db_path, reset=False)
    # After migration, the v1 entry should be cleared.
    assert db.get("a.yml") is None
    db.close()


def test_recorded_entry_round_trips(tmp_path: Path) -> None:
    db_path = tmp_path / "state.json"
    db = StateDB(db_path, reset=True)
    payload = {
        "status": "completed",
        "violations_count": 2,
        "violations": [
            {"rule": "pin-action-sha", "severity": "error"},
            {"rule": "coverity-scan", "severity": "warning"},
        ],
        "workflow_ast": {"name": "x"},
    }
    db.record("a.yml", 1.0, "abc", payload)
    db.flush()
    db.close()

    db2 = StateDB(db_path, reset=False)
    entry = db2.get("a.yml")
    assert entry is not None
    assert entry["content_sha256"] == "abc"
    assert entry["violations_count"] == 2
    db2.close()


def _state_worker(idx: int, db_path_str: str, barrier) -> None:
    db = StateDB(Path(db_path_str), reset=False)
    try:
        for i in range(5):
            db.record(
                f"file_{idx}_{i}.yml",
                mtime=float(idx * 100 + i),
                content_sha256=f"sha-{idx}-{i}",
                payload={"status": "completed", "violations_count": i, "violations": []},
            )
            db.flush()
        barrier.wait()
    finally:
        db.close()


def test_file_lock_serializes_concurrent_processes(tmp_path: Path) -> None:
    """Two processes writing to the same state DB should not corrupt it.

    POSIX fcntl.flock is process-level; threads in the same process share
    the same fd table and cannot reliably block each other. We exercise
    the cross-process path with the multiprocessing module.
    """
    import multiprocessing as mp

    db_path = tmp_path / "state.json"

    barrier = mp.Barrier(3)
    procs = [
        mp.Process(target=_state_worker, args=(i, str(db_path), barrier))
        for i in range(3)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join()
    for p in procs:
        assert p.exitcode == 0, f"Worker exited with {p.exitcode}"

    data = json.loads(db_path.read_text())
    assert len(data["processed_workflows"]) == 15
