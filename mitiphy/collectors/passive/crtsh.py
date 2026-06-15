"""crt.sh certificate transparency lookup."""

from __future__ import annotations

from collections.abc import AsyncIterator

from ...core.observation import Confidence, Observation, Severity
from ...core.plugin import BaseCollector
from ...core.target import Target, TargetType
from ..http import get_client

CRTSH_URL = "https://crt.sh/?q={domain}&output=json"


class CrtShCollector(BaseCollector):
    name = "crt"
    target_types = {TargetType.DOMAIN}
    cost = 1
    requires = ["network"]

    async def run(self, target: Target) -> AsyncIterator[Observation]:
        if target.type != TargetType.DOMAIN:
            return
        client = get_client()
        try:
            resp = await client.get(CRTSH_URL.format(domain=target.value))
            resp.raise_for_status()
            records = resp.json() if resp.text.strip() else []
        except Exception as exc:
            yield Observation(
                kind="error",
                value=f"crt.sh query failed: {exc}",
                source=self.name,
                severity=Severity.LOW,
                confidence=Confidence.LOW,
            )
            return

        seen: set[str] = set()
        for rec in records[:500]:
            name_value = rec.get("name_value", "")
            for entry in str(name_value).split("\n"):
                entry = entry.strip().lower().lstrip("*.")
                if not entry or entry in seen:
                    continue
                seen.add(entry)
                yield Observation(
                    kind="subdomain",
                    value=entry,
                    source=self.name,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    payload={
                        "issuer": rec.get("issuer_name"),
                        "not_before": rec.get("not_before"),
                    },
                )
