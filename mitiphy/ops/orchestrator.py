"""End-to-end case orchestrator.

Glues:
  Target -> Planner -> Collectors -> Bus -> Enricher -> Scorer -> Reporter
  +  Audit chain entries at every stage
  +  Quota consumption per collector call
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from pathlib import Path

from .. import __version__
from ..audit.chain import AuditChain
from ..brain.planner import Planner
from ..core.config import Settings, get_settings
from ..core.observation import Observation
from ..core.plugin import CollectorRegistry
from ..core.target import Target
from ..enrich.attck import ATTCKEnricher
from ..report.renderer import Case, Reporter
from ..safety.aup import AUPGate
from ..safety.quota import QuotaExceeded, QuotaManager
from ..score.scorer import RiskScorer

log = logging.getLogger(__name__)


class Orchestrator:
    def __init__(
        self,
        settings: Settings | None = None,
        registry: CollectorRegistry | None = None,
        allow_active: bool = False,
    ) -> None:
        self.settings = settings or get_settings()
        self.settings.ensure_dirs()
        self.registry = registry or CollectorRegistry.discover(self.settings.plugins_dir)
        self.allow_active = allow_active
        self.audit = AuditChain(self.settings.audit_db)
        self.audit.ensure_genesis(installer_version=__version__)
        self.quota = QuotaManager(
            self.settings.quota_db,
            default_limit=self.settings.quota_default,
            window_seconds=self.settings.quota_window_seconds,
        )
        self.aup = AUPGate(self.settings.aup_acceptance_file, self.settings.aup_revision)
        self.planner = Planner(self.registry, allow_active=allow_active)
        self.enricher = ATTCKEnricher()
        self.scorer = RiskScorer()

    def require_aup(self) -> None:
        if not self.aup.is_accepted():
            raise PermissionError(
                "AUP not accepted. Run `mitiphy aup --accept` first."
            )

    def new_case_dir(self) -> tuple[str, Path]:
        case_id = f"CASE-{int(time.time())}-{secrets.token_hex(3)}"
        out = self.settings.cases_dir / case_id
        out.mkdir(parents=True, exist_ok=True)
        return case_id, out

    async def run(self, target: Target, notes: str = "") -> Case:
        self.require_aup()
        self.audit.append("case_start", {"target": target.to_dict(), "allow_active": self.allow_active})
        case_id, case_dir = self.new_case_dir()
        plan = self.planner.plan(target)
        self.audit.append("plan", {"case_id": case_id, "summary": plan.summary()})

        observations: list[Observation] = []
        for collector in plan.steps:
            try:
                self.quota.consume(collector.name, cost=collector.cost)
            except QuotaExceeded as exc:
                self.audit.append("quota_exceeded", {"collector": collector.name, "detail": str(exc)})
                continue
            self.audit.append("collector_start", {"collector": collector.name})
            try:
                async for obs in collector.run(target):
                    observations.append(obs)
            except Exception as exc:
                log.warning("Collector %s failed: %s", collector.name, exc)
                self.audit.append(
                    "collector_error",
                    {"collector": collector.name, "error": repr(exc)},
                )
                continue
            self.audit.append(
                "collector_done",
                {"collector": collector.name, "observation_count": len(observations)},
            )
            await asyncio.sleep(0)

        techniques = self.enricher.enrich(observations)
        score = self.scorer.score(observations)
        self.audit.append(
            "score",
            {"case_id": case_id, "score": score.score, "components": score.components},
        )

        case = Case(
            case_id=case_id,
            target=target,
            observations=[o.to_dict() for o in observations],
            techniques=techniques,
            score=score,
            notes=notes,
        )
        reporter = Reporter(case_dir)
        written = reporter.write_all(case)
        # Best-effort additional exports.
        try:
            written["misp"] = reporter.write_misp(case)
            written["stix"] = reporter.write_stix(case)
        except Exception as exc:
            log.debug("Optional export failed: %s", exc)

        self.audit.append(
            "case_end",
            {
                "case_id": case_id,
                "outputs": {k: str(v) for k, v in written.items()},
                "observation_count": len(observations),
                "score": score.score,
            },
        )
        return case
