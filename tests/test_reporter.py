"""Reporter outputs."""

from __future__ import annotations

import json
from pathlib import Path

from mitiphy.core.observation import Confidence, Observation, Severity
from mitiphy.core.target import Target
from mitiphy.enrich.attck import ATTCKEnricher
from mitiphy.report.renderer import Case, Reporter
from mitiphy.score.scorer import RiskScorer


def _build_case(out_dir: Path) -> Case:
    target = Target.from_string("example.com")
    obs = [
        Observation(
            kind="subdomain", value="api.example.com", source="crt",
            severity=Severity.INFO, confidence=Confidence.HIGH,
        ),
        Observation(
            kind="kev_match", value="CVE-2024-3094", source="kev",
            severity=Severity.CRITICAL, confidence=Confidence.HIGH,
        ),
    ]
    techniques = ATTCKEnricher().enrich(obs)
    score = RiskScorer().score(obs)
    return Case(
        case_id="CASE-test",
        target=target,
        observations=[o.to_dict() for o in obs],
        techniques=techniques,
        score=score,
    )


def test_write_all_creates_json_md_html(tmp_path: Path) -> None:
    case = _build_case(tmp_path)
    rep = Reporter(tmp_path)
    out = rep.write_all(case)
    assert out["json"].exists()
    assert out["md"].exists()
    assert out["html"].exists()
    data = json.loads(out["json"].read_text(encoding="utf-8"))
    assert data["case_id"] == "CASE-test"
    assert data["target"]["value"] == "example.com"


def test_misp_export(tmp_path: Path) -> None:
    rep = Reporter(tmp_path)
    case = _build_case(tmp_path)
    path = rep.write_misp(case)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert "Event" in data
    assert data["Event"]["Attribute"]


def test_stix_export(tmp_path: Path) -> None:
    rep = Reporter(tmp_path)
    case = _build_case(tmp_path)
    path = rep.write_stix(case)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["type"] == "bundle"
    assert data["objects"]


def test_html_includes_score(tmp_path: Path) -> None:
    rep = Reporter(tmp_path)
    case = _build_case(tmp_path)
    path = rep.write_html(case)
    content = path.read_text(encoding="utf-8")
    assert "Mitiphy report" in content
    assert "example.com" in content
    assert "/ 100" in content
