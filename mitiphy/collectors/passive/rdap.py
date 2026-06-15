"""RDAP lookup for domains + IPs (preferred over WHOIS — JSON, structured)."""

from __future__ import annotations

from collections.abc import AsyncIterator

from ...core.observation import Confidence, Observation, Severity
from ...core.plugin import BaseCollector
from ...core.target import Target, TargetType
from ..http import get_client

RDAP_DOMAIN = "https://rdap.org/domain/{target}"
RDAP_IP = "https://rdap.org/ip/{target}"


class RDAPCollector(BaseCollector):
    name = "rdap"
    target_types = {TargetType.DOMAIN, TargetType.IP}
    cost = 1
    requires = ["network"]

    async def run(self, target: Target) -> AsyncIterator[Observation]:
        client = get_client()
        url = (
            RDAP_DOMAIN.format(target=target.value)
            if target.type == TargetType.DOMAIN
            else RDAP_IP.format(target=target.value)
        )
        try:
            resp = await client.get(url)
            if resp.status_code == 404:
                yield Observation(
                    kind="rdap_not_found",
                    value=target.value,
                    source=self.name,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                )
                return
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            yield Observation(
                kind="error",
                value=f"RDAP query failed: {exc}",
                source=self.name,
                severity=Severity.LOW,
                confidence=Confidence.LOW,
            )
            return

        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", []) if isinstance(e, dict)}
        statuses = data.get("status", [])
        handle = data.get("handle")
        nameservers = [ns.get("ldhName", "") for ns in data.get("nameservers", []) if isinstance(ns, dict)]

        yield Observation(
            kind="rdap_summary",
            value=str(handle or target.value),
            source=self.name,
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            payload={
                "registration": events.get("registration"),
                "expiration": events.get("expiration"),
                "last_changed": events.get("last changed"),
                "status": statuses,
                "nameservers": nameservers,
            },
        )

        for ns in nameservers:
            if ns:
                yield Observation(
                    kind="nameserver",
                    value=ns.lower(),
                    source=self.name,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                )
