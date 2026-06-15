# Mitiphy — Lite

> Free, self-hosted, AI-driven OSINT + threat-intelligence platform.
> **Lite profile:** lowest resource footprint, no container runtime required, single-process native install.

[![CI](https://github.com/mitiphy/mitiphy/actions/workflows/ci.yml/badge.svg)](https://github.com/mitiphy/mitiphy/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

Mitiphy takes any identifier (email, username, phone, domain, IP, file hash, URL) and produces a graph-backed, risk-scored, signed report. Everything runs on your own machine. Nothing leaves the box unless you choose to share.

This repository implements the **Lite** profile from [DESIGN-LITE.md](DESIGN-LITE.md): a single Python process, no Docker required, target footprint ~4–7 GB RAM, ~8 GB disk, ~5 minute install.

---

## Quick start

### Linux / macOS

```bash
git clone https://github.com/mitiphy/mitiphy.git
cd mitiphy
./install.sh
```

### Windows (PowerShell)

```powershell
git clone https://github.com/mitiphy/mitiphy.git
cd mitiphy
./install.ps1
```

### From PyPI (when published)

```bash
pip install mitiphy
mitiphy wizard
```

After install, start the analyst flow:

```bash
mitiphy chat                          # interactive TUI
# or
mitiphy run --target evil@example.com # one-shot investigation
# or
mitiphy web                           # local web UI on :7331
```

Reports land in `~/.mitiphy/cases/CASE-XXXX/` as HTML, Markdown, JSON, and (with `mitiphy[pdf]`) signed PDF.

---

## What the Lite profile does

- Auto-detects target type (email, username, phone, domain, IP, URL, file hash).
- Runs passive OSINT and threat-intel collectors against free public sources:
  - **CISA KEV** — known-exploited vulnerabilities.
  - **FIRST EPSS** — exploit-probability scoring.
  - **OSV.dev** — multi-ecosystem vulnerability database (covers GHSA, PyPI, npm, Go, Rust, etc.).
  - **abuse.ch** — URLhaus, ThreatFox, MalwareBazaar, Feodo (lazy warm).
  - **MITRE ATT&CK + CAPEC + D3FEND** — bundled offline.
  - **HIBP** — k-anonymity password-hash range query (no key, privacy-preserving).
  - **crt.sh** — Certificate Transparency for subdomain enumeration.
  - **Wayback Machine** — historical archive lookup.
  - **DNS / RDAP / WHOIS** — domain intel.
- Stores findings in an embedded knowledge graph and vector store (KuzuDB + LanceDB if installed; SQLite fallback otherwise).
- Computes an explainable 0–100 risk score with full provenance for every component.
- Maintains a tamper-evident append-only audit chain (SQLite WAL with hash chain anchored by a genesis row).
- Generates reports in HTML, Markdown, JSON, MISP event, STIX 2.1, and (optional) signed PDF.

## What the Lite profile does NOT do

These are intentionally deferred — graduate to the Default or Full profile when ready:

- Active recon binaries (subfinder, httpx, dnsx, testssl, wafw00f).
- Self-hosted SearXNG meta-search.
- Memgraph + MAGE advanced graph analytics.
- Grafana / Loki / Prometheus dashboards.
- Container runtime.

## Modes

```
mitiphy run         Run a one-shot investigation against a target.
mitiphy chat        Interactive analyst TUI.
mitiphy web         Start the local web UI on :7331.
mitiphy doctor      Self-check: DBs, model, feeds, quotas, audit chain.
mitiphy wizard      First-run interactive setup.
mitiphy demo        End-to-end smoke test against bundled fixtures.
mitiphy report      Re-render a saved case as HTML/MD/JSON.
mitiphy explain     Show the score breakdown for a saved case.
mitiphy replay      Re-run a saved case against current feeds.
mitiphy authorize   Manage authorized_targets.yml (for higher profiles).
mitiphy upgrade     Re-run preflight + dep sync + migrations + doctor.
```

## Safety defaults

- Active scans are **disabled by default** (and absent in Lite). Higher profiles require both `--authorized` and a signed `authorized_targets.yml` entry.
- Person-target detection triggers a consent prompt; the acknowledgement is hashed into the audit chain.
- Hard per-API quota counters in SQLite — operations refuse to proceed rather than leak into paid tiers.
- **Zero outbound telemetry**, asserted by a CI test against an egress allowlist.
- AUP must be acknowledged on first run; the acknowledgement is recorded with the AUP revision hash.

See [AUP.md](AUP.md) for the acceptable-use policy.

## Resource budget

| Metric                    | Default (8B Q4 model) | Fast (`--model fast`, 3B Q4) | Headless (no LLM, `--llm none`) |
| ------------------------- | --------------------- | ---------------------------- | ------------------------------- |
| RAM                       | ~7 GB                 | ~4 GB                        | ~500 MB                         |
| Disk                      | ~8 GB                 | ~5 GB                        | ~150 MB                         |
| Install                   | ~5 min                | ~3 min                       | <30 s                           |
| CPU                       | AVX2 x86_64 or arm64  | same                         | any                             |
| GPU                       | optional              | optional                     | n/a                             |

Headless mode is suitable for CI, batch jobs, and air-gapped recon where natural-language summarization is not required.

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│  Frontends                                                 │
│  CLI · Rich TUI · Static UI on :7331 · REST + WebSocket    │
└──────────────────────────┬─────────────────────────────────┘
                           ▼
              ┌─────────────────────────┐
              │  AI Brain (optional)    │
              │  Planner + Schema guard │
              │  RAG over evidence      │
              └────────────┬────────────┘
                           ▼
              ┌─────────────────────────┐
              │  asyncio in-proc bus    │
              └────────────┬────────────┘
                           ▼
   Passive · Identity · Code/Secret · Feeds · Reputation
                           ▼
            Normalize + Dedup + Metadata-strip
                           ▼
                 Enricher (ATT&CK / KEV / EPSS)
                           ▼
       Graph (KuzuDB | SQLite) + Vector (LanceDB | SQLite)
                           ▼
              Scorer (0–100, explainable)
                           ▼
         Reporter + Sign + Audit chain
```

## Repository layout

```
mitiphy-Lite/
├── mitiphy/              # Python package
│   ├── core/             # Target, bus, plugin ABC, config
│   ├── brain/            # Planner + schema guard + RAG
│   ├── collectors/       # Plugins (passive / identity / feeds)
│   ├── enrich/           # ATT&CK + KEV/EPSS + reputation
│   ├── graph/            # Embedded graph backend
│   ├── score/            # Risk scorer
│   ├── report/           # HTML / MD / JSON / MISP / STIX / PDF
│   ├── audit/            # Tamper-evident chain
│   ├── frontends/        # CLI / TUI / FastAPI server
│   ├── safety/           # AUP / consent / quota / authorized
│   ├── llm/              # llama.cpp + stub adapter
│   ├── storage/          # SQLite + adapters
│   ├── ops/              # doctor / wizard / bootstrap / demo
│   └── data/             # Bundled ATT&CK snapshot + fixtures
├── tests/                # pytest suite
├── scripts/              # installer support
├── docs/                 # extended docs
├── web/                  # static UI served by core
├── install.sh            # Linux/macOS bootstrap
├── install.ps1           # Windows bootstrap
├── DESIGN-LITE.md        # design document
├── AUP.md                # acceptable-use policy
├── LICENSE               # Apache-2.0
└── pyproject.toml
```

## Development

```bash
git clone https://github.com/mitiphy/mitiphy.git
cd mitiphy
python -m venv .venv
. .venv/bin/activate         # on Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest                       # run the test suite
ruff check .                 # lint
mypy mitiphy                 # type check
```

## Upgrading to Default or Full

A Lite install can graduate without losing data:

```bash
./install.sh --profile default   # adds Docker + SearXNG + active recon binaries
./install.sh --profile full      # adds Memgraph + observability stack
```

State in `~/.mitiphy/` (audit chain, KuzuDB, LanceDB, cases) is preserved.

## Contributing

Pull requests welcome. Before submitting:

1. Run `pytest`, `ruff check .`, `mypy mitiphy`.
2. Add tests for new collectors or scorers.
3. Update [DESIGN-LITE.md](DESIGN-LITE.md) if you change architecture.
4. New collectors must declare `requires` capabilities accurately so the safety gate enforces them.

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Acknowledgements

Built on the shoulders of the open-source security community: NVD, CISA, FIRST EPSS, abuse.ch, MITRE, OSV.dev, the certificate-transparency project, Internet Archive, sherlock/maigret/holehe/theHarvester/phoneinfoga maintainers, and the Python and llama.cpp ecosystems.

## Disclaimer

Mitiphy is provided **as-is** for defensive security and authorized OSINT work. The maintainers accept no liability for misuse. See [AUP.md](AUP.md).
