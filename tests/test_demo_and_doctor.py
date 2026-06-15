"""Demo + doctor smoke tests (no network beyond DNS, which is best-effort)."""

from __future__ import annotations

from pathlib import Path

from mitiphy.ops.demo import run_demo
from mitiphy.ops.doctor import run_doctor


def test_demo_runs_and_writes_outputs(isolated_state: Path) -> None:
    written = run_demo(dry_run=True)
    assert "json" in written
    assert "md" in written
    assert "html" in written
    for path_str in written.values():
        assert Path(path_str).exists()


def test_doctor_returns_report(isolated_state: Path) -> None:
    report = run_doctor()
    names = {c.name for c in report.checks}
    expected = {
        "state_dir_writable",
        "audit_chain_verifies",
        "quota_db_ok",
        "aup_accepted",
        "plugins_discovered",
        "llm_provider",
        "network_reachable",
        "telemetry_disabled",
    }
    assert expected.issubset(names)


def test_doctor_telemetry_always_disabled(isolated_state: Path) -> None:
    report = run_doctor()
    tel = next(c for c in report.checks if c.name == "telemetry_disabled")
    assert tel.ok is True
