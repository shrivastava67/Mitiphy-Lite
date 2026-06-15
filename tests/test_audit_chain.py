"""Audit chain tamper-evidence."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from mitiphy.audit.chain import AuditChain


def test_genesis_idempotent(tmp_path: Path) -> None:
    db = tmp_path / "a.db"
    chain = AuditChain(db)
    chain.ensure_genesis("test-v0")
    chain.ensure_genesis("test-v0")  # second call must not duplicate
    assert chain.count() == 1


def test_chain_links_and_verifies(tmp_path: Path) -> None:
    db = tmp_path / "a.db"
    chain = AuditChain(db)
    chain.ensure_genesis("test-v0")
    chain.append("event1", {"k": "v"})
    chain.append("event2", {"k": "w"})
    chain.append("event3", {"items": [1, 2, 3]})
    ok, n, bad = chain.verify()
    assert ok is True
    assert n == 4
    assert bad is None


def test_tampering_is_detected(tmp_path: Path) -> None:
    db = tmp_path / "a.db"
    chain = AuditChain(db)
    chain.ensure_genesis("test-v0")
    chain.append("event1", {"k": "v"})
    chain.append("event2", {"k": "w"})

    # Tamper: silently overwrite the payload of the middle row.
    conn = sqlite3.connect(db)
    conn.execute("UPDATE audit SET payload = ? WHERE id = ?", ('{"k":"TAMPERED"}', 2))
    conn.commit()
    conn.close()

    ok, n, bad = chain.verify()
    assert ok is False
    assert bad == "2"


def test_tail_advances(tmp_path: Path) -> None:
    db = tmp_path / "a.db"
    chain = AuditChain(db)
    chain.ensure_genesis("test-v0")
    t0 = chain.tail()
    chain.append("k", {"v": 1})
    t1 = chain.tail()
    assert t0 != t1
