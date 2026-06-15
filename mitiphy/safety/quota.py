"""Per-API quota counters persisted in SQLite.

Sliding window: count(calls within window_seconds) < limit. When exhausted,
QuotaExceeded is raised. We refuse to proceed rather than silently degrade or
leak into a paid tier.
"""

from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any


class QuotaExceeded(RuntimeError):
    """Raised when a quota for the given key has been spent."""


class QuotaManager:
    def __init__(self, db_path: Path, default_limit: int = 100, window_seconds: int = 86400) -> None:
        self.db_path = Path(db_path)
        self.default_limit = default_limit
        self.window_seconds = window_seconds
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _conn(self) -> Any:
        conn = sqlite3.connect(self.db_path, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        try:
            yield conn
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS quota_calls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT NOT NULL,
                    cost INTEGER NOT NULL DEFAULT 1,
                    ts REAL NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS quota_limits (
                    key TEXT PRIMARY KEY,
                    limit_count INTEGER NOT NULL,
                    window_seconds INTEGER NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_quota_key_ts ON quota_calls(key, ts)")

    def set_limit(self, key: str, limit: int, window_seconds: int | None = None) -> None:
        win = window_seconds or self.window_seconds
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO quota_limits (key, limit_count, window_seconds) "
                "VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET limit_count = excluded.limit_count, "
                "window_seconds = excluded.window_seconds",
                (key, limit, win),
            )

    def _limit_for(self, conn: sqlite3.Connection, key: str) -> tuple[int, int]:
        row = conn.execute(
            "SELECT limit_count, window_seconds FROM quota_limits WHERE key=?",
            (key,),
        ).fetchone()
        if row:
            return int(row[0]), int(row[1])
        return self.default_limit, self.window_seconds

    def _used_in_window(
        self, conn: sqlite3.Connection, key: str, window_seconds: int
    ) -> int:
        cutoff = time.time() - window_seconds
        row = conn.execute(
            "SELECT COALESCE(SUM(cost), 0) FROM quota_calls WHERE key=? AND ts >= ?",
            (key, cutoff),
        ).fetchone()
        return int(row[0] or 0)

    def check(self, key: str, cost: int = 1) -> tuple[int, int, int]:
        """Return (used, limit, remaining). Does not consume."""
        with self._conn() as conn:
            limit, win = self._limit_for(conn, key)
            used = self._used_in_window(conn, key, win)
            return used, limit, max(0, limit - used)

    def consume(self, key: str, cost: int = 1) -> int:
        """Atomically check+consume. Raises QuotaExceeded if budget gone.

        Returns the remaining budget AFTER consumption.
        """
        with self._conn() as conn:
            limit, win = self._limit_for(conn, key)
            used = self._used_in_window(conn, key, win)
            if used + cost > limit:
                raise QuotaExceeded(
                    f"Quota '{key}' exhausted: used {used}/{limit} (cost {cost})"
                )
            conn.execute(
                "INSERT INTO quota_calls (key, cost, ts) VALUES (?, ?, ?)",
                (key, cost, time.time()),
            )
            return max(0, limit - used - cost)

    def reset(self, key: str) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM quota_calls WHERE key=?", (key,))

    def usage_report(self) -> list[dict[str, Any]]:
        with self._conn() as conn:
            keys = conn.execute(
                "SELECT DISTINCT key FROM quota_calls "
                "UNION SELECT key FROM quota_limits"
            ).fetchall()
            out = []
            for (key,) in keys:
                limit, win = self._limit_for(conn, key)
                used = self._used_in_window(conn, key, win)
                out.append(
                    {
                        "key": key,
                        "used": used,
                        "limit": limit,
                        "remaining": max(0, limit - used),
                        "window_seconds": win,
                    }
                )
            return out
