"""Wayback Machine availability + CDX summary."""

from __future__ import annotations

from collections.abc import AsyncIterator

from ...core.observation import Confidence, Observation, Severity
from ...core.plugin import BaseCollector
from ...core.target import Target, TargetType
from ..http import get_client

AVAILABLE_URL = "https://archive.org/wayback/available?url={url}"
CDX_URL = (
    "https://web.archive.org/cdx/search/cdx?url={url}&output=json"
    "&limit=10&fl=timestamp,original,statuscode,mimetype"
)


class WaybackCollector(BaseCollector):
    name = "wayback"
    target_types = {TargetType.URL, TargetType.DOMAIN}
    cost = 1
    requires = ["network"]

    async def run(self, target: Target) -> AsyncIterator[Observation]:
        url = target.value if target.type == TargetType.URL else f"http://{target.value}"
        client = get_client()

        try:
            resp = await client.get(AVAILABLE_URL.format(url=url))
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            yield Observation(
                kind="error",
                value=f"Wayback availability failed: {exc}",
                source=self.name,
                severity=Severity.LOW,
                confidence=Confidence.LOW,
            )
            return

        snap = (data.get("archived_snapshots") or {}).get("closest")
        if snap:
            yield Observation(
                kind="archive_snapshot",
                value=snap.get("url", ""),
                source=self.name,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                payload={
                    "timestamp": snap.get("timestamp"),
                    "status": snap.get("status"),
                    "available": snap.get("available"),
                },
            )

        try:
            cdx_resp = await client.get(CDX_URL.format(url=url))
            if cdx_resp.status_code == 200 and cdx_resp.text.strip():
                rows = cdx_resp.json()
                if rows and len(rows) > 1:
                    for row in rows[1:]:
                        if len(row) >= 2:
                            yield Observation(
                                kind="archive_entry",
                                value=row[1],
                                source=self.name,
                                severity=Severity.INFO,
                                confidence=Confidence.MEDIUM,
                                payload={
                                    "timestamp": row[0],
                                    "status": row[2] if len(row) > 2 else None,
                                    "mimetype": row[3] if len(row) > 3 else None,
                                },
                            )
        except Exception:
            pass
