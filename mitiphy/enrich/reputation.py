"""Reputation rollup from observations.

In Lite we don't ship VirusTotal/AbuseIPDB adapters by default (those require
keys). Reputation is computed from severity distribution of observations
already collected — KEV hits, EPSS scores, OSV vulns, etc.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from ..core.observation import Observation, Severity


@dataclass
class ReputationSummary:
    score: float  # 0.0 - 1.0 (higher = worse)
    hits: int
    by_severity: dict[str, int]


class ReputationEnricher:
    """Compute a normalized reputation score from observation severities."""

    weights = {
        Severity.CRITICAL: 1.0,
        Severity.HIGH: 0.7,
        Severity.MEDIUM: 0.4,
        Severity.LOW: 0.15,
        Severity.INFO: 0.0,
    }

    def summarize(self, observations: Iterable[Observation]) -> ReputationSummary:
        by_sev: dict[str, int] = {s.value: 0 for s in Severity}
        weighted = 0.0
        hits = 0
        for o in observations:
            by_sev[o.severity.value] += 1
            w = self.weights.get(o.severity, 0.0)
            if w > 0:
                weighted += w
                hits += 1
        # Logistic-style cap so a single CRITICAL doesn't max out, but several do.
        score = 1.0 - 1.0 / (1.0 + weighted / 2.0) if weighted > 0 else 0.0
        return ReputationSummary(score=round(score, 4), hits=hits, by_severity=by_sev)
