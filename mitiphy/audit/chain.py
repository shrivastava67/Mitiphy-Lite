"""SQLite-backed append-only audit chain with hash linkage.

Each row stores (event, timestamp, prev_hash, this_hash). this_hash is the
SHA-256 of (prev_hash || event_json || timestamp). The first row (genesis) has
prev_hash = "0" * 64 and event_kind = "genesis".

Verify pass: walk the table in order; recompute each this_hash; assert match.
Any mismatch = tampered chain.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

GENESIS_PREV_HASH = "0" * 64


class AuditChain:
    """Append-only audit log with hash chain."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _conn(self) -> Any:
        conn = sqlite3.connect(self.db_path, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    kind TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    prev_hash TEXT NOT NULL,
                    this_hash TEXT NOT NULL UNIQUE
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_kind ON audit(kind)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(timestamp)")

    @staticmethod
    def _compute_hash(prev_hash: str, kind: str, payload_json: str, timestamp: float) -> str:
        h = hashlib.sha256()
        h.update(prev_hash.encode("ascii"))
        h.update(b"\x1e")
        h.update(kind.encode("utf-8"))
        h.update(b"\x1e")
        h.update(payload_json.encode("utf-8"))
        h.update(b"\x1e")
        h.update(f"{timestamp:.6f}".encode("ascii"))
        return h.hexdigest()

    def _tail_hash(self, conn: sqlite3.Connection) -> str:
        row = conn.execute(
            "SELECT this_hash FROM audit ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else GENESIS_PREV_HASH

    def ensure_genesis(self, installer_version: str) -> None:
        """Write the genesis row if the chain is empty.

        Genesis payload anchors the chain to the installer version + boot timestamp.
        """
        with self._conn() as conn:
            existing = conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
            if existing > 0:
                return
            payload = {"installer_version": installer_version, "anchor": "mitiphy-genesis"}
            ts = time.time()
            payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            this_hash = self._compute_hash(GENESIS_PREV_HASH, "genesis", payload_json, ts)
            conn.execute(
                "INSERT INTO audit (kind, payload, timestamp, prev_hash, this_hash) "
                "VALUES (?, ?, ?, ?, ?)",
                ("genesis", payload_json, ts, GENESIS_PREV_HASH, this_hash),
            )

    def append(self, kind: str, payload: dict[str, Any]) -> str:
        """Append a row; return the new tail hash."""
        with self._conn() as conn:
            prev = self._tail_hash(conn)
            ts = time.time()
            payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            this_hash = self._compute_hash(prev, kind, payload_json, ts)
            conn.execute(
                "INSERT INTO audit (kind, payload, timestamp, prev_hash, this_hash) "
                "VALUES (?, ?, ?, ?, ?)",
                (kind, payload_json, ts, prev, this_hash),
            )
            return this_hash

    def verify(self) -> tuple[bool, int, str | None]:
        """Walk the chain; return (ok, rows_checked, first_bad_id_or_none)."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, kind, payload, timestamp, prev_hash, this_hash "
                "FROM audit ORDER BY id ASC"
            ).fetchall()
        if not rows:
            return True, 0, None
        prev_expected = GENESIS_PREV_HASH
        for row in rows:
            id_, kind, payload_json, ts, prev_hash, this_hash = row
            if prev_hash != prev_expected:
                return False, len(rows), str(id_)
            recomputed = self._compute_hash(prev_hash, kind, payload_json, ts)
            if recomputed != this_hash:
                return False, len(rows), str(id_)
            prev_expected = this_hash
        return True, len(rows), None

    def count(self) -> int:
        with self._conn() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0])

    def tail(self) -> str:
        with self._conn() as conn:
            return self._tail_hash(conn)
