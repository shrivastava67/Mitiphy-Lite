"""asyncio bus."""

from __future__ import annotations

import asyncio

import pytest

from mitiphy.core.bus import Bus


@pytest.mark.asyncio
async def test_publish_then_subscribe_one_message() -> None:
    bus = Bus()
    q = bus.subscribe("topic")
    await bus.publish("topic", "hello")
    msg = await asyncio.wait_for(q.get(), timeout=1.0)
    assert msg == "hello"


@pytest.mark.asyncio
async def test_multiple_subscribers_each_get_message() -> None:
    bus = Bus()
    q1 = bus.subscribe("t")
    q2 = bus.subscribe("t")
    await bus.publish("t", 42)
    assert await asyncio.wait_for(q1.get(), 1) == 42
    assert await asyncio.wait_for(q2.get(), 1) == 42


@pytest.mark.asyncio
async def test_publish_to_unknown_topic_no_error() -> None:
    bus = Bus()
    await bus.publish("nobody-listening", "nope")  # must not raise


@pytest.mark.asyncio
async def test_close_signals_subscribers() -> None:
    bus = Bus()
    q = bus.subscribe("t")
    await bus.close()
    msg = await asyncio.wait_for(q.get(), 1)
    assert msg is None
