"""
Assignment 11 — Audit Log.

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input metadata and return a correlation ID."""
        correlation_id = request_id or user_id or uuid.uuid4().hex
        self._open[correlation_id] = time.perf_counter()
        self.logs.append({
            "request_id": correlation_id,
            "user_id": user_id,
            "input": text,
            "started_at": utc_now_iso(),
            "output": None,
            "blocked": None,
            "layer": None,
            "latency_ms": None,
        })
        return correlation_id

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Complete the matching audit entry with the decision and latency."""
        correlation_id = request_id or user_id
        started = self._open.pop(correlation_id, None)
        entry = next(
            (row for row in reversed(self.logs) if row["request_id"] == correlation_id),
            None,
        )
        if entry is None:
            entry = {
                "request_id": correlation_id,
                "user_id": user_id,
                "input": None,
                "started_at": utc_now_iso(),
            }
            self.logs.append(entry)
        entry.update({
            "output": text,
            "blocked": bool(blocked),
            "layer": layer,
            "completed_at": utc_now_iso(),
            "latency_ms": round((time.perf_counter() - started) * 1000, 3)
            if started is not None else None,
        })
        return entry

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
