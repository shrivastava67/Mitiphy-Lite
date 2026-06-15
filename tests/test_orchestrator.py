"""End-to-end orchestrator (no network)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from mitiphy.audit.chain import AuditChain
from mitiphy.core.config import get_settings
from mitiphy.core.observation import Confidence, Observation, Severity
from mitiphy.core.plugin import BaseCollector, CollectorRegistry
from mitiphy.core.target import Target, TargetType
from mitiphy.ops.orchestrator import Orchestrator
from mitiphy.safety.aup import AUPGate


class StubDomainCollector(BaseCollector):
    name = "stub"
    target_types = {TargetType.DOMAIN}
    cost = 1
    requires = ["network"]

    async def run(self, target: Target) -> AsyncIterator[Observation]:
        yield Observation(
            kind="subdomain", value=f"www.{target.value}", source=self.name,
            severity=Severity.INFO, confidence=Confidence.HIGH,
        )
        yield Observation(
            kind="kev_match", value="CVE-2024-3094", source=self.name,
            severity=Severity.CRITICAL, confidence=Confidence.HIGH,
        )


@pytest.mark.asyncio
async def test_orchestrator_runs_end_to_end(isolated_state: Path) -> None:
    # Accept AUP first.
    s = get_settings()
    s.ensure_dirs()
    AUPGate(s.aup_acceptance_file, s.aup_revision).record_acceptance("ok")

    reg = CollectorRegistry(collectors={"stub": StubDomainCollector()})
    orch = Orchestrator(registry=reg)
    case = await orch.run(Target.from_string("example.com"), notes="unit test")

    assert case.case_id.startswith("CASE-")
    assert case.target.type == TargetType.DOMAIN
    assert len(case.observations) >= 2
    assert case.score.score > 0.0

    # Reports written.
    out_dir = s.cases_dir / case.case_id
    assert (out_dir / "report.json").exists()
    assert (out_dir / "report.md").exists()
    assert (out_dir / "report.html").exists()

    # Audit chain has the entire flow recorded.
    chain = AuditChain(s.audit_db)
    ok, n, _ = chain.verify()
    assert ok
    assert n >= 5  # genesis + case_start + plan + collector + score + case_end


@pytest.mark.asyncio
async def test_orchestrator_refuses_without_aup(isolated_state: Path) -> None:
    reg = CollectorRegistry(collectors={"stub": StubDomainCollector()})
    orch = Orchestrator(registry=reg)
    with pytest.raises(PermissionError):
        await orch.run(Target.from_string("example.com"))
