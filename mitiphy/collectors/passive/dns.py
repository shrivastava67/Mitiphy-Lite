"""Passive DNS lookups via dnspython.

A/AAAA/MX/NS/TXT/CNAME records. Public DNS, no probing of target HTTP services.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

from ...core.observation import Confidence, Observation, Severity
from ...core.plugin import BaseCollector
from ...core.target import Target, TargetType

_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")


class DNSCollector(BaseCollector):
    name = "dns"
    target_types = {TargetType.DOMAIN}
    cost = 1
    requires = ["network"]

    async def run(self, target: Target) -> AsyncIterator[Observation]:
        try:
            import dns.asyncresolver  # type: ignore[import-not-found]
            import dns.exception  # type: ignore[import-not-found]
        except ImportError:
            yield Observation(
                kind="error",
                value="dnspython not installed",
                source=self.name,
                severity=Severity.LOW,
                confidence=Confidence.LOW,
            )
            return

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        for rtype in _RECORD_TYPES:
            try:
                answer = await resolver.resolve(target.value, rtype)
            except dns.exception.DNSException:
                continue
            except Exception:
                continue
            for r in answer:
                yield Observation(
                    kind=f"dns_{rtype.lower()}",
                    value=str(r).strip('"'),
                    source=self.name,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    payload={"rtype": rtype, "ttl": getattr(answer, "rrset", None) and answer.rrset.ttl},
                )
            await asyncio.sleep(0)  # cooperative yield
