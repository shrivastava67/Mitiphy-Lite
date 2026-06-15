# Changelog

All notable changes to Mitiphy will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-06

### Added (initial Lite release)

- Target auto-detection for email, username, phone, domain, IP, URL, MD5/SHA-1/SHA-256, person.
- Passive collectors: crt.sh, Wayback Machine, DNS (dnspython), RDAP.
- Identity collector: HIBP password-range (k-anonymity).
- Threat-feed collectors: CISA KEV (lazy-warmed cache), FIRST EPSS, OSV.dev.
- ATT&CK enricher with bundled technique snapshot.
- Six-component explainable risk scorer (reputation, blocklist, KEV/CVE, leak recency, graph centrality, exposure).
- Tamper-evident SQLite WAL audit chain with genesis row and verifier.
- Per-API quota counters with sliding window.
- AUP gate + person-target consent prompt with hashed acknowledgement.
- Reports: JSON, Markdown, HTML, MISP event, STIX 2.1 bundle. PDF deferred behind `[pdf]` extra.
- LLM provider abstraction: none / llamacpp / ollama. Default `none` keeps Lite fully usable without a model.
- CLI modes: run, chat, web, doctor, wizard, demo, report, explain, replay, cases, quotas, audit-verify, upgrade, aup.
- FastAPI REST + minimal static web UI on port 7331.
- Rich TUI for `mitiphy chat`.
- `install.sh` (Linux/macOS) and `install.ps1` (Windows) bash/PowerShell bootstrap installers — no Docker required.
- GitHub Actions CI matrix (Linux/macOS/Windows × Python 3.11/3.12) with ruff + mypy + pytest.
- Apache-2.0 license, AUP, CONTRIBUTING.
