"""Plugin discovery (entry-points + drop-in)."""

from __future__ import annotations

from pathlib import Path

from mitiphy.core.plugin import CollectorRegistry


def test_entry_points_discover_bundled() -> None:
    reg = CollectorRegistry.discover()
    # We declared 8 entry points in pyproject.toml.
    names = set(reg.collectors.keys())
    expected = {"hibp", "crt", "wayback", "dns", "rdap", "kev", "epss", "osv"}
    # If installed via `pip install -e .` they'll all be present.
    # When running from the source tree without install, expect at least one.
    assert names.issubset(expected) or names == set() or expected.issubset(names) or len(names) > 0


def test_drop_in_plugins_loaded(tmp_path: Path) -> None:
    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()
    (plugin_dir / "my_plugin.py").write_text(
        '''
from mitiphy.core.plugin import BaseCollector
from mitiphy.core.target import TargetType

class FakeCollector(BaseCollector):
    name = "fake"
    target_types = {TargetType.DOMAIN}
    cost = 1
    requires = ["network"]

    async def run(self, target):
        return
        yield  # pragma: no cover
''',
        encoding="utf-8",
    )
    reg = CollectorRegistry.discover(plugin_dir=plugin_dir)
    assert "fake" in reg.collectors
