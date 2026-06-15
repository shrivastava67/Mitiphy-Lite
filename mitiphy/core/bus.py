"""In-process asyncio pub/sub bus.

Replaces Redis Streams for the Lite profile. Single-process, no external
service. Topics are simple strings; subscribers register a queue. Producers
publish observations. Bounded queues protect against runaway producers.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from collections.abc import AsyncIterator
from typing import Any

log = logging.getLogger(__name__)


class Bus:
    """Minimal in-proc pub/sub with bounded per-subscriber queues."""

    def __init__(self, queue_size: int = 1000) -> None:
        self._subs: dict[str, list[asyncio.Queue[Any]]] = defaultdict(list)
        self._queue_size = queue_size
        self._closed = False

    async def publish(self, topic: str, message: Any) -> None:
        if self._closed:
            return
        for q in list(self._subs.get(topic, [])):
            try:
                q.put_nowait(message)
            except asyncio.QueueFull:
                log.warning("Bus queue full on topic %s; dropping message", topic)

    def subscribe(self, topic: str) -> asyncio.Queue[Any]:
        q: asyncio.Queue[Any] = asyncio.Queue(maxsize=self._queue_size)
        self._subs[topic].append(q)
        return q

    async def stream(self, topic: str) -> AsyncIterator[Any]:
        q = self.subscribe(topic)
        try:
            while not self._closed:
                msg = await q.get()
                if msg is None:
                    break
                yield msg
        finally:
            try:
                self._subs[topic].remove(q)
            except ValueError:
                pass

    async def close(self) -> None:
        self._closed = True
        for queues in self._subs.values():
            for q in queues:
                try:
                    q.put_nowait(None)
                except asyncio.QueueFull:
                    pass
