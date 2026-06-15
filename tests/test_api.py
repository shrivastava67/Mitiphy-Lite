"""FastAPI surface (no network — uses test client)."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from mitiphy.core.config import get_settings
from mitiphy.frontends.api import create_app


def test_healthz_returns_ok(isolated_state: Path) -> None:
    client = TestClient(create_app())
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_version_endpoint(isolated_state: Path) -> None:
    client = TestClient(create_app())
    r = client.get("/version")
    assert r.status_code == 200
    body = r.json()
    assert "version" in body
    assert body["profile"] == "lite"


def test_quotas_endpoint(isolated_state: Path) -> None:
    client = TestClient(create_app())
    r = client.get("/quotas")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_audit_verify_endpoint(isolated_state: Path) -> None:
    # Touch audit chain so it exists.
    s = get_settings()
    s.ensure_dirs()
    from mitiphy.audit.chain import AuditChain

    AuditChain(s.audit_db).ensure_genesis("test")
    client = TestClient(create_app())
    r = client.get("/audit/verify")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True


def test_root_returns_html(isolated_state: Path) -> None:
    client = TestClient(create_app())
    r = client.get("/")
    assert r.status_code == 200
    assert "Mitiphy" in r.text


def test_cases_empty_by_default(isolated_state: Path) -> None:
    client = TestClient(create_app())
    r = client.get("/cases")
    assert r.status_code == 200
    assert r.json() == []
