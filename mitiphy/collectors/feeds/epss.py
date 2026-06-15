"""FIRST EPSS (Exploit Prediction Scoring System) lookup.

We hit the public CSV/JSON API on a per-CVE basis. EPSS gives us a probability
of in-the-wild exploitation in the next 30 days; the scorer uses it as one of
the six components.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from ...core.observation import Confidence, Observation, Severity
from ...core.plugin import BaseCollector
from ...core.target import Target, TargetType
from ..http import get_client
from .kev import _extract_cves_from_target

EPSS_URL = "https://api.first.org/data/v1/epss?cve={cve}"


class EPSSCollector(BaseCollector):
    name = "epss"
    target_types = {TargetType.DOMAIN, TargetType.URL, TargetType.IP}
    cost = 1
    requires = ["network"]

    async def run(self, target: Target) -> AsyncIterator[Observation]:
        cves = _extract_cves_from_target(target)
        if not cves:
            return
        client = get_client()
        for cve in cves[:20]:
            try:
                resp = await client.get(EPSS_URL.format(cve=cve))
                resp.raise_for_status()
                payload = resp.json()
            except Exception as exc:
                yield Observation(
                    kind="error",
                    value=f"EPSS query failed for {cve}: {exc}",
                    source=self.name,
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                )
                continue
            for entry in payload.get("data") or []:
                try:
                    score = float(entry.get("epss", 0))
                    percentile = float(entry.get("percentile", 0))
                except (TypeError, ValueError):
                    continue
                sev = (
                    Severity.CRITICAL
                    if score > 0.7
                    else Severity.HIGH
                    if score > 0.3
                    else Severity.MEDIUM
                    if score > 0.05
                    else Severity.LOW
                )
                yield Observation(
                    kind="epss_score",
                    value=cve,
                    source=self.name,
                    severity=sev,
                    confidence=Confidence.HIGH,
                    payload={
                        "epss": score,
                        "percentile": percentile,
                        "date": entry.get("date"),
                    },
                )
