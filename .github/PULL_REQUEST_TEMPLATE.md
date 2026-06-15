<!-- Thanks for contributing! -->

## Summary

<!-- One paragraph describing the change. -->

## Motivation

<!-- Why is this needed? Link any related issues with "Closes #N". -->

## Changes

- [ ] ...
- [ ] ...

## Profile impact

- [ ] Lite resource budget unaffected (≤ 7 GB RAM with 8B model, ≤ 4 GB without)
- [ ] No new telemetry / outbound calls outside the documented allowlist
- [ ] If a new collector: declares `requires` capabilities accurately
- [ ] If touching active recon: gated by `--authorized` + signed `authorized_targets.yml`

## Tests

- [ ] `pytest` passes locally
- [ ] `ruff check .` clean
- [ ] `mypy mitiphy` clean
- [ ] Added tests for new logic

## Docs

- [ ] Updated `README.md` if user-facing
- [ ] Updated `DESIGN-LITE.md` if architectural
- [ ] Updated `CHANGELOG.md`
