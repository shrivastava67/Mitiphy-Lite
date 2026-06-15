"""Explainable risk scorer.

Implements the six-component weighted score from DESIGN.md §7:

  score = clamp_0_100(
      0.25 * reputation_hits
    + 0.20 * blocklist_confidence
    + 0.20 * kev_or_active_cve
    + 0.15 * leak_recency
    + 0.10 * graph_centrality
    + 0.10 * exposure_signals
  )

Every component is computed from concrete observation evidence. The result
includes a full breakdown so users can defend the score.
"""

from __future__ import annotations

import math
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from ..core.observation import Observation, Severity


@dataclass
class ScoreResult:
    score: float  # 0-100
    components: dict[str, float] = field(default_factory=dict)
    weights: dict[str, float] = field(default_factory=dict)
    explanation: list[dict[str, Any]] = field(default_factory=list)
    substitutions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "components": self.components,
            "weights": self.weights,
            "explanation": self.explanation,
            "substitutions": self.substitutions,
        }


class RiskScorer:
    weights = {
        "reputation_hits": 0.25,
        "blocklist_confidence": 0.20,
        "kev_or_active_cve": 0.20,
        "leak_recency": 0.15,
        "graph_centrality": 0.10,
        "exposure_signals": 0.10,
    }

    def __init__(self, now: float | None = None) -> None:
        self._now = now or time.time()

    def score(self, observations: Iterable[Observation]) -> ScoreResult:
        obs_list = list(observations)
        components: dict[str, float] = {}
        explanation: list[dict[str, Any]] = []

        # --- 1. reputation_hits: severity-weighted hit count, sigmoid-capped ---
        sev_weight_map = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.7,
            Severity.MEDIUM: 0.4,
            Severity.LOW: 0.15,
            Severity.INFO: 0.0,
        }
        rep_raw = sum(sev_weight_map[o.severity] for o in obs_list)
        rep_norm = 1.0 - math.exp(-rep_raw / 2.0)
        components["reputation_hits"] = rep_norm
        explanation.append({
            "component": "reputation_hits",
            "weight": self.weights["reputation_hits"],
            "value": rep_norm,
            "inputs": {
                "weighted_sum": rep_raw,
                "by_severity": _by_severity(obs_list),
            },
        })

        # --- 2. blocklist_confidence: presence of public-feed blocklist obs ---
        block_kinds = {"blocklist_match", "phishing_domain", "malicious_url"}
        block_hits = [o for o in obs_list if o.kind in block_kinds]
        block_score = min(1.0, len(block_hits) / 3.0)
        components["blocklist_confidence"] = block_score
        explanation.append({
            "component": "blocklist_confidence",
            "weight": self.weights["blocklist_confidence"],
            "value": block_score,
            "inputs": {"hits": [o.value for o in block_hits]},
        })

        # --- 3. kev_or_active_cve: KEV present, or any EPSS > 0.5 ---
        kev_hits = [o for o in obs_list if o.kind == "kev_match"]
        epss_strong = [
            o for o in obs_list
            if o.kind == "epss_score" and float(o.payload.get("epss", 0)) > 0.5
        ]
        kev_score = 1.0 if (kev_hits or epss_strong) else 0.0
        components["kev_or_active_cve"] = kev_score
        explanation.append({
            "component": "kev_or_active_cve",
            "weight": self.weights["kev_or_active_cve"],
            "value": kev_score,
            "inputs": {
                "kev_matches": [o.value for o in kev_hits],
                "epss_strong": [o.value for o in epss_strong],
            },
        })

        # --- 4. leak_recency: exponential decay over 24 months for breach obs ---
        breach_obs = [o for o in obs_list if o.kind in {"breach", "credential_leak"}]
        recency = 0.0
        if breach_obs:
            most_recent_age_days = min(
                max(0.0, (self._now - o.timestamp) / 86400.0) for o in breach_obs
            )
            half_life_days = 365.0
            recency = math.exp(-most_recent_age_days * math.log(2) / half_life_days)
        components["leak_recency"] = recency
        explanation.append({
            "component": "leak_recency",
            "weight": self.weights["leak_recency"],
            "value": recency,
            "inputs": {"breach_count": len(breach_obs)},
        })

        # --- 5. graph_centrality: degree centrality fallback ---
        # Lite uses a heuristic: count of distinct linked subdomains/IPs/NS as
        # a proxy for centrality. Substitution recorded.
        edges = [
            o for o in obs_list
            if o.kind in {"subdomain", "nameserver", "dns_a", "dns_aaaa", "dns_mx"}
        ]
        cent = 1.0 - math.exp(-len(edges) / 20.0)
        components["graph_centrality"] = cent
        substitutions = [
            "graph_centrality computed via degree-centrality fallback "
            "(KuzuDB MAGE/PageRank only in Full profile)"
        ]
        explanation.append({
            "component": "graph_centrality",
            "weight": self.weights["graph_centrality"],
            "value": cent,
            "inputs": {"edge_count": len(edges)},
            "note": substitutions[0],
        })

        # --- 6. exposure_signals: subdomains exposed, secrets in code, services ---
        exposure_kinds = {
            "subdomain", "exposed_service", "tech_fingerprint",
            "secret_match", "open_port",
        }
        exposure_hits = [o for o in obs_list if o.kind in exposure_kinds]
        exposure_score = 1.0 - math.exp(-len(exposure_hits) / 10.0)
        components["exposure_signals"] = exposure_score
        explanation.append({
            "component": "exposure_signals",
            "weight": self.weights["exposure_signals"],
            "value": exposure_score,
            "inputs": {"hit_count": len(exposure_hits)},
        })

        # --- final aggregate ---
        total = sum(components[k] * self.weights[k] for k in self.weights) * 100.0
        total = max(0.0, min(100.0, total))

        return ScoreResult(
            score=round(total, 2),
            components={k: round(v, 4) for k, v in components.items()},
            weights=dict(self.weights),
            explanation=explanation,
            substitutions=substitutions,
        )


def _by_severity(obs_list: list[Observation]) -> dict[str, int]:
    out = {s.value: 0 for s in Severity}
    for o in obs_list:
        out[o.severity.value] += 1
    return out
