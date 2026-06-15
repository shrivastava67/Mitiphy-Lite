"""Observation = a single fact produced by a Collector.

Collectors emit Observations onto the bus. Enricher, scorer, reporter consume
them downstream. Every observation is provenanced: source, when, raw payload
(redacted on write), confidence.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class Observation:
    """A single piece of evidence produced by a collector."""

    kind: str  # e.g. "subdomain", "breach", "kev_match", "cve", "ioc"
    value: str  # the headline fact
    source: str  # collector name
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.MEDIUM
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "value": self.value,
            "source": self.source,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "payload": self.payload,
            "timestamp": self.timestamp,
        }
