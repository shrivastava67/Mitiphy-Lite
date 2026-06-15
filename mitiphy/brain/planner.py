"""Lightweight planner.

Picks which collectors to run for a target, in what order, given:
  - target type
  - registry of available collectors (filtered by target_types)
  - safety constraints (active recon disabled in Lite)
  - quota budget

This is intentionally rule-based for Lite. The LangGraph adapter slot is the
hook for higher profiles to swap in an LLM-driven planner.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.plugin import Collector, CollectorRegistry
from ..core.target import Target


@dataclass
class Plan:
    target: Target
    steps: list[Collector] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)

    def summary(self) -> dict[str, object]:
        return {
            "target": self.target.to_dict(),
            "steps": [c.name for c in self.steps],
            "skipped": [{"collector": n, "reason": r} for n, r in self.skipped],
        }


class Planner:
    def __init__(
        self,
        registry: CollectorRegistry,
        allow_active: bool = False,
        allowed_capabilities: set[str] | None = None,
    ) -> None:
        self.registry = registry
        self.allow_active = allow_active
        self.allowed_capabilities = allowed_capabilities or {"network"}

    def plan(self, target: Target) -> Plan:
        candidates = self.registry.for_target(target)
        plan = Plan(target=target)
        for c in sorted(candidates, key=lambda c: (c.cost, c.name)):
            reqs = set(c.requires)
            if "authorized" in reqs and not self.allow_active:
                plan.skipped.append((c.name, "requires --authorized (active recon)"))
                continue
            unmet = reqs - self.allowed_capabilities - {"network", "authorized"}
            if unmet:
                plan.skipped.append((c.name, f"missing capabilities: {sorted(unmet)}"))
                continue
            plan.steps.append(c)
        return plan
