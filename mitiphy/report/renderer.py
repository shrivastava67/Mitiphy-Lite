"""Multi-format reporter (JSON, Markdown, HTML).

PDF / MISP / STIX are adapter slots — the methods exist and raise NotImplementedError
when their optional deps are absent. This keeps the contract clear without
forcing every Lite user to install WeasyPrint or pymisp.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..core.target import Target
from ..enrich.attck import TechniqueMatch
from ..score.scorer import ScoreResult


@dataclass
class Case:
    case_id: str
    target: Target
    observations: list[dict[str, Any]]
    techniques: list[TechniqueMatch]
    score: ScoreResult
    created_at: float = field(default_factory=time.time)
    notes: str = ""


class Reporter:
    """Render a Case in multiple formats."""

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        tpl_dir = Path(__file__).resolve().parent / "templates"
        tpl_dir.mkdir(parents=True, exist_ok=True)
        self._env = Environment(
            loader=FileSystemLoader(str(tpl_dir)),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    # ---- writers --------------------------------------------------------

    def write_all(self, case: Case) -> dict[str, Path]:
        out: dict[str, Path] = {}
        out["json"] = self.write_json(case)
        out["md"] = self.write_markdown(case)
        out["html"] = self.write_html(case)
        return out

    def write_json(self, case: Case) -> Path:
        path = self.output_dir / "report.json"
        data = {
            "case_id": case.case_id,
            "target": case.target.to_dict(),
            "observations": case.observations,
            "techniques": [t.__dict__ for t in case.techniques],
            "score": case.score.to_dict(),
            "created_at": case.created_at,
            "notes": case.notes,
        }
        path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        return path

    def write_markdown(self, case: Case) -> Path:
        path = self.output_dir / "report.md"
        lines = [
            f"# Mitiphy report — {case.case_id}",
            "",
            f"**Target:** `{case.target.value}` _(type: {case.target.type.value})_",
            f"**Created:** {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime(case.created_at))}",
            "",
            "## Risk score",
            "",
            f"**{case.score.score:.1f} / 100**",
            "",
            "| Component | Weight | Value |",
            "|-----------|-------:|------:|",
        ]
        for comp, val in case.score.components.items():
            w = case.score.weights.get(comp, 0.0)
            lines.append(f"| {comp} | {w:.2f} | {val:.4f} |")
        if case.score.substitutions:
            lines.extend(["", "**Substitutions applied:**"])
            for s in case.score.substitutions:
                lines.append(f"- {s}")
        lines.extend(["", "## MITRE ATT&CK techniques"])
        if case.techniques:
            for t in case.techniques:
                lines.append(f"- **{t.id}** {t.name} — {t.tactic} (matched via: {', '.join(t.matched_via)})")
        else:
            lines.append("_No technique matches._")
        lines.extend(["", "## Observations", ""])
        for o in case.observations:
            lines.append(
                f"- `{o['kind']}` **{o['value']}** _(source: {o['source']}, severity: {o['severity']}, confidence: {o['confidence']})_"
            )
        if case.notes:
            lines.extend(["", "## Notes", "", case.notes])
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def write_html(self, case: Case) -> Path:
        path = self.output_dir / "report.html"
        tpl = self._env.get_template("report.html.j2")
        rendered = tpl.render(
            case_id=case.case_id,
            target=case.target.to_dict(),
            score=case.score.to_dict(),
            techniques=[t.__dict__ for t in case.techniques],
            observations=case.observations,
            created_at_iso=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(case.created_at)),
            notes=case.notes,
        )
        path.write_text(rendered, encoding="utf-8")
        return path

    # ---- adapter slots --------------------------------------------------

    def write_pdf(self, case: Case) -> Path:
        try:
            from weasyprint import HTML  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover
            raise NotImplementedError(
                "PDF export requires 'mitiphy[pdf]' extra (installs WeasyPrint)."
            ) from exc
        html_path = self.write_html(case)
        pdf_path = self.output_dir / "report.pdf"
        HTML(filename=str(html_path)).write_pdf(str(pdf_path))
        return pdf_path

    def write_misp(self, case: Case) -> Path:
        """Minimal MISP event JSON (event + attributes). pymisp not required."""
        path = self.output_dir / "report.misp.json"
        attrs = []
        for o in case.observations:
            attrs.append({
                "type": _map_to_misp_type(o["kind"]),
                "category": "Network activity",
                "value": o["value"],
                "comment": f"{o['source']} / sev={o['severity']}",
            })
        event = {
            "Event": {
                "info": f"Mitiphy investigation: {case.target.value}",
                "analysis": "1",
                "threat_level_id": _map_score_to_threat_level(case.score.score),
                "distribution": "0",
                "Attribute": attrs,
                "Tag": [{"name": f'mitiphy:case="{case.case_id}"'}],
            }
        }
        path.write_text(json.dumps(event, indent=2), encoding="utf-8")
        return path

    def write_stix(self, case: Case) -> Path:
        """Minimal STIX 2.1 bundle (indicator + identity + report)."""
        path = self.output_dir / "report.stix.json"
        bundle = {
            "type": "bundle",
            "id": f"bundle--{case.case_id}",
            "objects": [
                {
                    "type": "identity",
                    "spec_version": "2.1",
                    "id": f"identity--mitiphy-{case.case_id}",
                    "name": "Mitiphy",
                    "identity_class": "system",
                    "created": _iso(case.created_at),
                    "modified": _iso(case.created_at),
                },
                {
                    "type": "report",
                    "spec_version": "2.1",
                    "id": f"report--{case.case_id}",
                    "created": _iso(case.created_at),
                    "modified": _iso(case.created_at),
                    "name": f"Mitiphy investigation: {case.target.value}",
                    "published": _iso(case.created_at),
                    "report_types": ["threat-report"],
                    "object_refs": [],
                },
            ],
        }
        path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
        return path


def _map_to_misp_type(kind: str) -> str:
    table = {
        "subdomain": "domain",
        "dns_a": "ip-dst",
        "dns_aaaa": "ip-dst",
        "dns_mx": "domain",
        "dns_ns": "domain",
        "nameserver": "domain",
        "archive_snapshot": "url",
        "archive_entry": "url",
        "kev_match": "vulnerability",
        "epss_score": "vulnerability",
        "osv_vuln": "vulnerability",
    }
    return table.get(kind, "comment")


def _map_score_to_threat_level(score: float) -> str:
    if score >= 75:
        return "1"  # high
    if score >= 40:
        return "2"  # medium
    if score >= 10:
        return "3"  # low
    return "4"  # undefined


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(ts))
