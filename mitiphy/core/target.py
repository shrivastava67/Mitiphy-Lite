"""Target type detection and dataclass.

Auto-detects the kind of identifier the user passed in. Detection is regex +
heuristic; ambiguous inputs are resolved with a small priority ladder
(file hashes → IP → URL → email → phone → domain → username → person).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from ipaddress import AddressValueError, IPv4Address, IPv6Address
from typing import Any
from urllib.parse import urlparse


class TargetType(str, Enum):
    EMAIL = "email"
    USERNAME = "username"
    PHONE = "phone"
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    PERSON = "person"
    UNKNOWN = "unknown"


# Pre-compiled regex patterns. Conservative — false positives cost user trust.
_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)
_PHONE_RE = re.compile(r"^\+?[0-9][0-9\s\-().]{6,20}[0-9]$")
_USERNAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9._\-]{2,38}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)


def detect_type(value: str) -> TargetType:
    """Return the most likely TargetType for an input string.

    Priority is deliberately fixed so that ambiguous inputs (e.g. an all-hex
    string that could be a hash or a username) resolve to the more specific
    type first. The order below is the contract; tests pin it.
    """
    v = value.strip()
    if not v:
        return TargetType.UNKNOWN

    # File hashes — exact length + hex only.
    if _SHA256_RE.match(v):
        return TargetType.HASH_SHA256
    if _SHA1_RE.match(v):
        return TargetType.HASH_SHA1
    if _MD5_RE.match(v):
        return TargetType.HASH_MD5

    # URLs.
    if _URL_RE.match(v):
        try:
            parsed = urlparse(v)
            if parsed.netloc:
                return TargetType.URL
        except ValueError:
            pass

    # IP addresses (v4 or v6).
    try:
        IPv4Address(v)
        return TargetType.IP
    except (AddressValueError, ValueError):
        pass
    try:
        IPv6Address(v)
        return TargetType.IP
    except (AddressValueError, ValueError):
        pass

    # Email.
    if _EMAIL_RE.match(v):
        return TargetType.EMAIL

    # Phone — must contain a digit run and be plausibly long.
    digits = re.sub(r"\D", "", v)
    if _PHONE_RE.match(v) and 7 <= len(digits) <= 15:
        return TargetType.PHONE

    # Domain — requires at least one dot and a recognizable TLD shape.
    if _DOMAIN_RE.match(v):
        return TargetType.DOMAIN

    # Username — alphanum + limited punctuation, no spaces, no dots-only.
    if _USERNAME_RE.match(v) and " " not in v:
        return TargetType.USERNAME

    # Multi-word inputs default to PERSON for consent gating.
    if " " in v and all(part.isalpha() or part.replace("-", "").isalpha() for part in v.split()):
        return TargetType.PERSON

    return TargetType.UNKNOWN


@dataclass
class Target:
    """Normalized investigation target."""

    value: str
    type: TargetType
    raw: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_string(cls, value: str) -> Target:
        v = value.strip()
        return cls(value=v, type=detect_type(v), raw=value)

    @property
    def is_person(self) -> bool:
        """Whether consent gating applies."""
        return self.type in (TargetType.PERSON, TargetType.USERNAME, TargetType.EMAIL, TargetType.PHONE)

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "type": self.type.value,
            "raw": self.raw,
            "metadata": self.metadata,
        }
