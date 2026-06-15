"""ATT&CK enrichment: map observation kinds to techniques."""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from ..core.observation import Observation


@dataclass
class TechniqueMatch:
    id: str
    name: str
    tactic: str
    matched_via: list[str]


@lru_cache(maxsize=1)
def _bundle() -> dict:  # type: ignore[type-arg]
    # Look for bundle in package data, repo data/, or relative to install root.
    candidates = [
        Path(__file__).resolve().parent.parent / "data" / "attck" / "techniques.json",
        Path(__file__).resolve().parent.parent.parent / "data" / "attck" / "techniques.json",
    ]
    for p in candidates:
        if p.exists():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
    return {"techniques": []}


class ATTCKEnricher:
    """Map observations to ATT&CK techniques using the bundled snapshot."""

    def __init__(self) -> None:
        self.techniques = _bundle().get("techniques", [])

    def enrich(self, observations: Iterable[Observation]) -> list[TechniqueMatch]:
        # Group observation kinds.
        kinds: dict[str, list[str]] = {}
        for o in observations:
            kinds.setdefault(o.kind, []).append(o.value)
        matches: list[TechniqueMatch] = []
        for t in self.techniques:
            ind = set(t.get("indicators", []))
            via = sorted(set(kinds) & ind)
            if via:
                matches.append(
                    TechniqueMatch(
                        id=t["id"],
                        name=t["name"],
                        tactic=t["tactic"],
                        matched_via=via,
                    )
                )
        return matches
