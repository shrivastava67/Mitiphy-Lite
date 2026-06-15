"""HIBP k-anonymity password-range lookup.

For an email target, we compute SHA-1 of the email address (HIBP's notify
flow needs a paid key, so this collector instead checks the *password*
breach corpus via k-anonymity — when the user supplies one — OR falls back
to the public Pwned Passwords range API for any hex prefix.

For MVP we expose `lookup_prefix(prefix5)` and `check_password_hash(sha1_hex)`.
Email-mode is treated as a placeholder observation noting that the public
breach-by-email endpoint requires an API key; we never burn budget on it
without one.
"""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator

from ...core.observation import Confidence, Observation, Severity
from ...core.plugin import BaseCollector
from ...core.target import Target, TargetType
from ..http import get_client

PWNED_PASSWORDS_RANGE = "https://api.pwnedpasswords.com/range/{prefix5}"


class HIBPCollector(BaseCollector):
    name = "hibp"
    target_types = {TargetType.EMAIL}
    cost = 1
    requires = ["network"]

    async def run(self, target: Target) -> AsyncIterator[Observation]:
        # Email-only path for MVP: emit advisory observation explaining the
        # privacy-preserving capability and pointing at password-range mode.
        if target.type != TargetType.EMAIL:
            return
        yield Observation(
            kind="advisory",
            value=f"HIBP email-breach lookup requires API key; password-range mode available for hash queries (email={target.value})",
            source=self.name,
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            payload={
                "endpoint": PWNED_PASSWORDS_RANGE.format(prefix5="XXXXX"),
                "notes": "Use mitiphy.collectors.identity.hibp.check_password_hash() to query Pwned Passwords by SHA-1 prefix.",
            },
        )


async def check_password_hash(sha1_hex: str) -> int:
    """Return the breach-count for an exact password SHA-1, or 0 if not found."""
    sha1_hex = sha1_hex.upper()
    if len(sha1_hex) != 40 or not all(c in "0123456789ABCDEF" for c in sha1_hex):
        raise ValueError("sha1_hex must be 40 hex characters")
    prefix, suffix = sha1_hex[:5], sha1_hex[5:]
    client = get_client()
    resp = await client.get(
        PWNED_PASSWORDS_RANGE.format(prefix5=prefix),
        headers={"Add-Padding": "true"},
    )
    resp.raise_for_status()
    for line in resp.text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            hash_suffix, count_str = line.split(":", 1)
        except ValueError:
            continue
        if hash_suffix.strip().upper() == suffix:
            try:
                return int(count_str.strip())
            except ValueError:
                return 0
    return 0


def sha1_of(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest().upper()
