"""Test fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from mitiphy.core.config import reset_settings_for_tests


@pytest.fixture(autouse=True)
def isolated_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Every test gets an isolated MITIPHY_HOME so audit chains don't bleed."""
    monkeypatch.setenv("MITIPHY_HOME", str(tmp_path))
    # Clear cached singleton.
    reset_settings_for_tests()
    yield tmp_path
    reset_settings_for_tests()
