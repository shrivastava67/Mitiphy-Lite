"""OSV.dev cross-ecosystem vulnerability lookup.

Covers GHSA, PyPI, npm, Go, Rust, Maven, NuGet, etc. We accept CVE-* values via
target metadata and translate to OSV queries.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from ...core.observation import Confidence, Observation, Severity
from ...core.plugin import BaseCollector
from ...core.target import Target, TargetType
from ..http import get_client
from .kev import _extract_cves_from_target

OSV_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"


class OSVCollector(BaseCollector):
    name = "osv"
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
                resp = await client.get(OSV_URL.format(vuln_id=cve))
                if resp.status_code == 404:
                    continue
                resp.raise_for_status()
                data = resp.json()
            except Exception as exc:
                yield Observation(
                    kind="error",
                    value=f"OSV query failed for {cve}: {exc}",
                    source=self.name,
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                )
                continue
            severity = _severity_from_osv(data)
            yield Observation(
                kind="osv_vuln",
                value=data.get("id", cve),
                source=self.name,
                severity=severity,
                confidence=Confidence.HIGH,
                payload={
                    "summary": data.get("summary"),
                    "aliases": data.get("aliases", []),
                    "modified": data.get("modified"),
                    "references": [r.get("url") for r in data.get("references", []) if isinstance(r, dict)],
                },
            )


def _severity_from_osv(data: dict) -> Severity:  # type: ignore[type-arg]
    sev_list = data.get("severity") or []
    for s in sev_list:
        if not isinstance(s, dict):
            continue
        score = s.get("score", "")
        if isinstance(score, str) and "CVSS:3" in score:
            try:
                pieces = score.split("/")
                # Score string can be a vector or a number; try parse trailing /BaseScore
                for p in pieces:
                    if p.startswith("CR:") or p.startswith("IR:"):
                        continue
            except Exception:
                pass
    return Severity.MEDIUM
