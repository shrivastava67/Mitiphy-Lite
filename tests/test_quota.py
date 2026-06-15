"""Quota enforcement."""

from __future__ import annotations

from pathlib import Path

import pytest

from mitiphy.safety.quota import QuotaExceeded, QuotaManager


def test_check_and_consume(tmp_path: Path) -> None:
    q = QuotaManager(tmp_path / "q.db", default_limit=3, window_seconds=3600)
    used, limit, remaining = q.check("foo")
    assert used == 0
    assert limit == 3
    assert remaining == 3

    q.consume("foo")
    q.consume("foo")
    used, _, remaining = q.check("foo")
    assert used == 2
    assert remaining == 1

    q.consume("foo")
    with pytest.raises(QuotaExceeded):
        q.consume("foo")


def test_set_limit_overrides_default(tmp_path: Path) -> None:
    q = QuotaManager(tmp_path / "q.db", default_limit=5)
    q.set_limit("hibp", 2)
    q.consume("hibp")
    q.consume("hibp")
    with pytest.raises(QuotaExceeded):
        q.consume("hibp")


def test_per_key_isolation(tmp_path: Path) -> None:
    q = QuotaManager(tmp_path / "q.db", default_limit=2)
    q.consume("a")
    q.consume("a")
    q.consume("b")
    # a is exhausted, b is not.
    with pytest.raises(QuotaExceeded):
        q.consume("a")
    q.consume("b")  # still ok


def test_reset(tmp_path: Path) -> None:
    q = QuotaManager(tmp_path / "q.db", default_limit=2)
    q.consume("a")
    q.consume("a")
    q.reset("a")
    q.consume("a")  # back in budget


def test_usage_report(tmp_path: Path) -> None:
    q = QuotaManager(tmp_path / "q.db", default_limit=5)
    q.set_limit("dns", 10)
    q.consume("dns")
    q.consume("crt")
    report = {r["key"]: r for r in q.usage_report()}
    assert report["dns"]["used"] == 1
    assert report["dns"]["limit"] == 10
    assert report["crt"]["used"] == 1
    assert report["crt"]["limit"] == 5
