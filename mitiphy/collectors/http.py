"""Shared HTTP client for collectors.

Single httpx.AsyncClient is reused. Honors the configured user-agent. All
collectors should use this rather than instantiating their own client so the
egress allowlist test can intercept every request.
"""

from __future__ import annotations

import httpx

from ..core.config import get_settings

_client: httpx.AsyncClient | None = None


def get_client() -> httpx.AsyncClient:
    global _client
    if _client is None or _client.is_closed:
        s = get_settings()
        _client = httpx.AsyncClient(
            timeout=httpx.Timeout(20.0, connect=10.0),
            headers={"User-Agent": s.user_agent},
            follow_redirects=True,
        )
    return _client


async def close_client() -> None:
    global _client
    if _client is not None and not _client.is_closed:
        await _client.aclose()
    _client = None
