"""ATT&CK enricher mapping."""

from __future__ import annotations

from mitiphy.core.observation import Confidence, Observation, Severity
from mitiphy.enrich.attck import ATTCKEnricher


def obs(kind: str, value: str = "x") -> Observation:
    return Observation(
        kind=kind, value=value, source="test",
        severity=Severity.INFO, confidence=Confidence.HIGH,
    )


def test_subdomain_maps_to_t1590() -> None:
    matches = ATTCKEnricher().enrich([obs("subdomain")])
    ids = {m.id for m in matches}
    assert "T1590" in ids


def test_kev_match_maps_to_t1190() -> None:
    matches = ATTCKEnricher().enrich([obs("kev_match")])
    ids = {m.id for m in matches}
    assert "T1190" in ids


def test_no_observations_no_matches() -> None:
    assert ATTCKEnricher().enrich([]) == []


def test_match_includes_matched_via() -> None:
    matches = ATTCKEnricher().enrich([obs("subdomain"), obs("dns_a")])
    t1590 = next(m for m in matches if m.id == "T1590")
    assert "subdomain" in t1590.matched_via
    assert "dns_a" in t1590.matched_via
