"""CISA Known Exploited Vulnerabilities feed.

Lazy-warmed: first call fetches + caches the catalog under ~/.mitiphy/feeds/kev.json.
Subsequent calls within TTL serve from cache.

Targets: CVE-shaped tokens passed as 'value' (matched via metadata) OR domain/IP
targets whose payload carries CVE references (used by orchestrator).
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from ...core.config import get_settings
from ...core.observation import Confidence, Observation, Severity
from ...core.plugin import BaseCollector
from ...core.target import Target, TargetType
from ..http import get_client

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_TTL = 24 * 3600  # 24 hours
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


class KEVCollector(BaseCollector):
    name = "kev"
    target_types = {TargetType.DOMAIN, TargetType.URL, TargetType.IP}
    cost = 1
    requires = ["network"]

    async def run(self, target: Target) -> AsyncIterator[Observation]:
        cves = _extract_cves_from_target(target)
        if not cves:
            return
        catalog = await _load_catalog()
        index = {entry["cveID"]: entry for entry in catalog.get("vulnerabilities", [])}
        for cve in cves:
            entry = index.get(cve)
            if entry:
                yield Observation(
                    kind="kev_match",
                    value=cve,
                    source=self.name,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    payload={
                        "vendor": entry.get("vendorProject"),
                        "product": entry.get("product"),
                        "name": entry.get("vulnerabilityName"),
                        "date_added": entry.get("dateAdded"),
                        "due_date": entry.get("dueDate"),
                        "required_action": entry.get("requiredAction"),
                    },
                )


def _extract_cves_from_target(target: Target) -> list[str]:
    cves: set[str] = set()
    cves.update(CVE_RE.findall(target.value))
    md = target.metadata or {}
    for v in md.values():
        if isinstance(v, str):
            cves.update(CVE_RE.findall(v))
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, str):
                    cves.update(CVE_RE.findall(item))
    return sorted(cves)


async def _load_catalog() -> dict[str, Any]:
    cache = _cache_path()
    if cache.exists() and (time.time() - cache.stat().st_mtime) < KEV_CACHE_TTL:
        try:
            return json.loads(cache.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    client = get_client()
    resp = await client.get(KEV_URL)
    resp.raise_for_status()
    data = resp.json()
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(data), encoding="utf-8")
    return data


def _cache_path() -> Path:
    return get_settings().feeds_dir / "kev.json"
