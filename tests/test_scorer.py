"""Risk scorer correctness + explainability."""

from __future__ import annotations

import time

from mitiphy.core.observation import Confidence, Observation, Severity
from mitiphy.score.scorer import RiskScorer


def make_obs(kind: str, value: str, sev: Severity = Severity.INFO, **payload: object) -> Observation:
    return Observation(
        kind=kind, value=value, source="test",
        severity=sev, confidence=Confidence.HIGH,
        payload=dict(payload),
    )


def test_empty_observations_zero_score() -> None:
    result = RiskScorer().score([])
    assert result.score == 0.0
    for v in result.components.values():
        assert v == 0.0


def test_score_clamped_between_0_and_100() -> None:
    obs = [
        make_obs("kev_match", f"CVE-2024-{i:04d}", Severity.CRITICAL) for i in range(50)
    ]
    obs += [make_obs("subdomain", f"s{i}.example.com") for i in range(100)]
    result = RiskScorer().score(obs)
    assert 0.0 <= result.score <= 100.0


def test_kev_match_lifts_kev_component_to_one() -> None:
    obs = [make_obs("kev_match", "CVE-2024-0001", Severity.CRITICAL)]
    r = RiskScorer().score(obs)
    assert r.components["kev_or_active_cve"] == 1.0


def test_epss_strong_lifts_kev_component_to_one() -> None:
    obs = [make_obs("epss_score", "CVE-2024-0001", Severity.HIGH, epss=0.8)]
    r = RiskScorer().score(obs)
    assert r.components["kev_or_active_cve"] == 1.0


def test_epss_weak_does_not_lift_kev_component() -> None:
    obs = [make_obs("epss_score", "CVE-2024-0001", Severity.LOW, epss=0.1)]
    r = RiskScorer().score(obs)
    assert r.components["kev_or_active_cve"] == 0.0


def test_recent_breach_yields_high_leak_recency() -> None:
    now = time.time()
    obs = [
        Observation(
            kind="breach", value="b", source="x",
            severity=Severity.HIGH, confidence=Confidence.HIGH,
            timestamp=now - 30 * 86400,  # 30 days ago
        )
    ]
    r = RiskScorer(now=now).score(obs)
    assert r.components["leak_recency"] > 0.9


def test_old_breach_decays() -> None:
    now = time.time()
    obs = [
        Observation(
            kind="breach", value="b", source="x",
            severity=Severity.HIGH, confidence=Confidence.HIGH,
            timestamp=now - 3 * 365 * 86400,  # 3 years ago
        )
    ]
    r = RiskScorer(now=now).score(obs)
    assert r.components["leak_recency"] < 0.2


def test_explanation_always_present() -> None:
    r = RiskScorer().score([])
    assert len(r.explanation) == 6
    components_named = {e["component"] for e in r.explanation}
    assert components_named == set(RiskScorer.weights.keys())


def test_substitution_recorded() -> None:
    r = RiskScorer().score([])
    assert any("graph_centrality" in s for s in r.substitutions)


def test_weights_sum_to_one() -> None:
    assert abs(sum(RiskScorer.weights.values()) - 1.0) < 1e-9


def test_to_dict_serializable() -> None:
    import json
    obs = [make_obs("kev_match", "CVE-1", Severity.CRITICAL)]
    r = RiskScorer().score(obs)
    s = json.dumps(r.to_dict())
    assert "score" in s
