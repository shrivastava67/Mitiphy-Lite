"""Collector plugin contract + discovery.

Two discovery paths:
  1. Python entry-points group "mitiphy.collectors"
  2. Drop-in directory ~/.mitiphy/plugins/*.py auto-imported on start

Every collector implements the Protocol below. The safety layer enforces
`requires` capabilities before invocation.
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import sys
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from .observation import Observation
from .target import Target, TargetType

log = logging.getLogger(__name__)


@runtime_checkable
class Collector(Protocol):
    """Protocol every collector must satisfy."""

    name: str
    target_types: set[TargetType]
    cost: int
    requires: list[str]

    def run(self, target: Target) -> AsyncIterator[Observation]:
        # Implemented as `async def run(...)` with `yield` — returns an async generator,
        # which is an AsyncIterator. The Protocol intentionally declares this as a sync
        # signature returning AsyncIterator so mypy treats `collector.run(target)` as
        # iterable rather than as a coroutine of an iterable.
        ...


@dataclass
class CollectorRegistry:
    """Holds the active set of collectors discovered at startup."""

    collectors: dict[str, Collector]

    @classmethod
    def discover(cls, plugin_dir: Path | None = None) -> CollectorRegistry:
        """Discover via entry-points + drop-in dir."""
        found: dict[str, Collector] = {}

        # 1. Entry-points
        try:
            from importlib.metadata import entry_points

            eps = entry_points()
            if hasattr(eps, "select"):
                group = eps.select(group="mitiphy.collectors")
            else:
                group = eps.get("mitiphy.collectors", [])  # type: ignore[attr-defined,arg-type]
            for ep in group:
                try:
                    cls_obj = ep.load()
                    inst = cls_obj()
                    found[inst.name] = inst
                except Exception as exc:
                    log.warning("Failed to load entry-point %s: %s", ep.name, exc)
        except Exception as exc:
            log.debug("Entry-point discovery skipped: %s", exc)

        # 2. Drop-in directory
        if plugin_dir is not None and plugin_dir.is_dir():
            for py_file in plugin_dir.glob("*.py"):
                if py_file.name.startswith("_"):
                    continue
                mod_name = f"mitiphy_plugin_{py_file.stem}"
                spec = importlib.util.spec_from_file_location(mod_name, py_file)
                if spec is None or spec.loader is None:
                    continue
                try:
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[mod_name] = module
                    spec.loader.exec_module(module)
                    for attr in dir(module):
                        obj = getattr(module, attr)
                        if isinstance(obj, type) and obj is not Collector:
                            try:
                                inst = obj()
                                if isinstance(inst, Collector):
                                    found[inst.name] = inst
                            except Exception:
                                continue
                except Exception as exc:
                    log.warning("Failed to load drop-in plugin %s: %s", py_file, exc)

        return cls(collectors=found)

    def for_target(self, target: Target) -> list[Collector]:
        """Return collectors that accept this target type."""
        return [c for c in self.collectors.values() if target.type in c.target_types]

    def by_name(self, name: str) -> Collector | None:
        return self.collectors.get(name)


class BaseCollector:
    """Optional convenience base class; collectors can inherit instead of typing Protocol."""

    name: str = "unnamed"
    target_types: set[TargetType] = set()
    cost: int = 1
    requires: list[str] = ["network"]

    async def run(self, target: Target) -> AsyncIterator[Observation]:
        raise NotImplementedError
        yield  # pragma: no cover  # makes this an async generator for type purposes
