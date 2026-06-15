# Contributing to Mitiphy

Thanks for considering a contribution.

## Quick start

```bash
git clone https://github.com/mitiphy/mitiphy.git
cd mitiphy
python -m venv .venv
. .venv/bin/activate            # on Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
ruff check .
mypy mitiphy
```

## Ground rules

1. **Recon power and resource budget are co-equal goals.** Anything that ships in Lite must run inside the published resource budget (≤ 7 GB RAM with 8B model, ≤ 4 GB without). Heavy capabilities belong in DEFAULT or FULL.
2. **No telemetry. Ever.** PRs that add outbound calls outside the authoritative-source allowlist will be rejected.
3. **Every external API call must be quota-counted.** Use `mitiphy.safety.quota.QuotaManager.consume()` before issuing a request.
4. **Person targets require consent.** If you add a collector whose primary target type is person/email/username/phone, it must respect the existing consent gate.
5. **Active recon stays gated.** Any collector that probes a target system must declare `requires = ["authorized", ...]`. Lite never installs active-recon binaries.
6. **Tests are not optional.** A new collector ships with at least one unit test (mocked HTTP). A new scoring component ships with at least one explainability test.
7. **Audit chain entries** for any state-changing action.

## Adding a collector

1. Subclass `mitiphy.core.plugin.BaseCollector`.
2. Set `name`, `target_types`, `cost`, `requires`.
3. Implement `async def run(self, target) -> AsyncIterator[Observation]`.
4. Register the entry-point under `[project.entry-points."mitiphy.collectors"]` in `pyproject.toml`.
5. Add tests under `tests/`.

## Adding a score component

Score components live in `mitiphy/score/scorer.py`. Each component:

- Has a fixed weight that sums (with the others) to **1.0**.
- Returns a float in `[0.0, 1.0]`.
- Emits an `explanation` entry with `component`, `weight`, `value`, `inputs`, and (if substituted) a `note`.

## Code style

- Ruff for lint, mypy for types.
- Public APIs are typed and documented with one-line docstrings.
- No `print()` in library code — use `structlog` or the `rich` console in CLI/TUI only.

## Pull request checklist

- [ ] `pytest` passes.
- [ ] `ruff check .` clean.
- [ ] `mypy mitiphy` clean.
- [ ] If you added a collector, you added a test.
- [ ] If you changed scoring, you added an explainability test.
- [ ] If you changed safety, you updated `AUP.md` or `DESIGN-LITE.md`.

## Reporting security issues

Open a private GitHub security advisory. Do not open a public issue for security reports.
