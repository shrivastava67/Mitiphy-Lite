# Mitiphy — Lite Profile Design

> Free, self-hosted, AI-driven OSINT + threat-intelligence platform.
> Surface-web only. Local-first. Zero recurring cost.
> **Lite profile:** lowest resource footprint, no container runtime required, single-process native install.

---

## 1. Vision

Same as `DESIGN.md`. Mitiphy takes any identifier (email, username, phone, domain, IP, wallet, file hash, URL, person, company) and produces a graph-backed, risk-scored, signed report. Lite ships the core analyst workflow with the smallest viable footprint so it runs on an M1 Air, a low-cost VPS, or an 8 GB workstation.

---

## 2. Scope (v0.1 Lite)

### In-scope
- Auto-detect target type (email, username, phone, domain, IP, URL, file hash).
- Local AI brain (llama.cpp + Llama 3.1 8B q4_K_M) for planning and summarizing.
- LangGraph planner + Outlines schema-guarded structured output.
- Passive collection: meta-search via direct adapters (Brave/DDG/Tavily), Wayback, public archives, public code search.
- Identity lookup: sherlock, maigret, holehe, theHarvester, phoneinfoga (Python plugins, in-process).
- HIBP k-anonymity password-hash range query.
- Passive HTTP via curl-impersonate (browser-fingerprint client).
- Threat feeds: public phishing, malware, blocklist, exit-list feeds (lazy warm).
- Vulnerability intel: CISA KEV, EPSS, NVD, OSV.
- Free public reputation lookup (URLs, IPs, domains, hashes).
- Knowledge graph (**KuzuDB embedded**) + vector store (**LanceDB embedded**).
- Explainable risk score 0–100 with provenance.
- Tamper-evident audit chain (SQLite append-only, WAL).
- Reports: interactive HTML, signed PDF, MISP event, STIX 2.1, Markdown, JSON.
- Frontends: CLI + Rich TUI + local web UI on `:7331` (static SPA served by core).
- Modes: `run`, `chat`, `web`, `doctor`, `wizard`, `demo`, `report`, `explain`, `replay`.
- Safety: lawful-only default, consent prompt on person targets, hard API quota caps, zero telemetry, AUP gate.

### Out-of-scope (defer to Default profile or higher)
- Active recon binaries (subfinder, httpx, dnsx, testssl, wafw00f) — available in Default.
- Multi-engine self-hosted search (SearXNG) — available in Default.
- Advanced graph analytics (Memgraph + MAGE: PageRank, community detection, centrality) — available in Full.
- Observability stack (Grafana + Loki + Prometheus) — available in Full.
- Container runtime requirement — Lite installs natively, no Docker/Podman.

### Out-of-scope (all profiles, deferred to v1.0)
Same deferral list as `DESIGN.md` §2: port + vuln scanning, crawl mining, sports vertical, ransomware-leak monitor, wallet intel, bots, MCP endpoint, watch mode, federation, evidence vault, multilingual UI.

---

## 3. Architecture (Lite)

```
┌────────────────────────────────────────────────────────────┐
│  Frontends                                                 │
│  CLI · Textual TUI · Static SPA on :7331 · REST + WS       │
└──────────────────────────┬─────────────────────────────────┘
                           ▼
              ┌─────────────────────────┐
              │  AI Brain (local)       │
              │  LangGraph planner      │
              │  Outlines schema guard  │
              │  RAG over LanceDB       │
              └────────────┬────────────┘
                           ▼
              ┌─────────────────────────┐
              │  asyncio in-proc bus    │
              └────────────┬────────────┘
   ┌───────────┬───────────┼────────────┬──────────┐
   ▼           ▼           ▼            ▼          ▼
Passive    Identity     Code/Secret  Feeds      Reputation
Search     Lookup       Discovery    + Vuln      Lookup
   │           │           │            │          │
   └───────────┴────┬──────┴────────────┴──────────┘
                    ▼
            Normalize + Dedup + Metadata-strip
                    ▼
                 Enricher
                    ▼
       Graph (KuzuDB) + Vector (LanceDB)
                    ▼
              Scorer (0–100)
                    ▼
         Reporter + Sign + Audit chain
                    ▼
                Delivery
```

Everything in one Python process. No external services. llama.cpp runs as sibling process for model isolation.

---

## 4. Tech Stack (Lite)

| Layer | Tool |
|-------|------|
| Language | Python 3.12 |
| Packaging | uv |
| AI runtime | llama.cpp (via llama-cpp-python) |
| Default model | Llama 3.1 8B Instruct q4_K_M (~4.7 GB) |
| Fast-mode model (`--model fast`) | Qwen2.5 3B Instruct q4 (~2 GB) |
| Planner | LangGraph + Outlines |
| Graph DB | **KuzuDB (embedded, MIT)** |
| Vector DB | **LanceDB (embedded, Apache-2.0)** |
| Message bus | **asyncio.Queue (in-proc) + SQLite WAL persistence** |
| API | FastAPI + Uvicorn + WebSocket |
| Web UI | Pre-built static SPA (Next.js export) served by FastAPI; Cytoscape.js + Leaflet for graph/geo |
| Terminal UI | Textual + Rich |
| HTTP | httpx + curl-impersonate |
| Search | Direct adapters: Brave Search API, DuckDuckGo HTML, Tavily (user keys optional) |
| Identity engines | sherlock, maigret, holehe, theHarvester, phoneinfoga (Python in-proc) |
| Threat-intel formats | MISP (pymisp), STIX 2.1 (stix2) |
| Reports | WeasyPrint, sigstore/cosign |
| Secrets | OS keyring (`keyring`); `age` fallback for headless |
| Storage | SQLite (audit + cache + bus persistence + quota counters) |
| Containers | **Not required** for Lite |
| Quality gates | Ruff, mypy, pytest, vcrpy |
| Supply chain | hash-pinned uv.lock, pip-audit, OSV-Scanner, Gitleaks, Semgrep, Syft (SBOM) |
| CI | GitHub Actions |

All free, all open-source, all local.

---

## 5. Repository Layout (Lite-specific notes)

Same tree as `DESIGN.md` §5 with these deltas:
- `compose.yaml` absent from Lite install path; the file exists in repo for upgrade-to-Default convenience.
- `deploy/grafana/`, `deploy/loki/`, `deploy/prometheus/`, `deploy/searxng/` absent at runtime (not pulled by Lite installer).
- `mitiphy/runtime/` adds:
  - `embedded/kuzu_client.py`
  - `embedded/lance_client.py`
  - `embedded/asyncio_bus.py`
  - `embedded/llamacpp_runner.py`

---

## 6. Plugin Contract

Identical to `DESIGN.md` §6:

```python
class Collector(Protocol):
    name: str
    target_types: set[TargetType]
    cost: int                       # quota cost per invocation
    requires: list[str]             # capabilities (network, api_key, binary)
    async def run(self, target: Target) -> AsyncIterator[Observation]: ...
```

Discovery: Python entry-points (`mitiphy.collectors`) **plus** drop-in `~/.mitiphy/plugins/*.py` auto-import.

Lite hosts plugins in-process. Untrusted third-party plugins flagged `requires: ["sandbox"]` are launched in a subprocess sandbox (post-MVP; MVP rejects them with a warning).

---

## 7. Risk Score (MVP formula)

Identical to `DESIGN.md` §7. All inputs available in Lite (graph centrality computed via KuzuDB built-in PageRank approximation; if unavailable, falls back to degree centrality with that substitution recorded in the score `explanation[]`).

---

## 8. Safety Defaults

Identical to `DESIGN.md` §8:
- Active scans default OFF; require `--authorized` AND signed `authorized_targets.yml`. Lite ships with no active-recon binaries, so this gate is doubly enforced.
- Person-target consent prompt; answer hashed into audit chain.
- Hard per-API quota counters persisted in SQLite.
- AUP displayed on first run; `--accept-aup` recorded.
- Zero outbound telemetry. CI test asserts no egress to non-allowlisted hosts.

---

## 9. Bootstrap Philosophy

User runs:

```bash
git clone https://github.com/<org>/mitiphy.git && cd mitiphy && ./install.sh --profile lite
```

`--profile lite` is auto-selected when detected RAM < 12 GB OR when Docker/Podman not present.

---

## 10. CI / Release

Identical to `DESIGN.md` §10. Lite ships as the default release artifact; Default and Full are opt-in profile flags on the same installer.

---

## 11. Roadmap

Same as `DESIGN.md` §11. Lite has the same v1.0 destination via the same plugin contract.

---

# Self-Host Flow — Lite

## 12. The One Command

**Linux / macOS**
```bash
git clone https://github.com/<org>/mitiphy.git
cd mitiphy
./install.sh --profile lite
```

**Windows (PowerShell)**
```powershell
git clone https://github.com/<org>/mitiphy.git
cd mitiphy
./install.ps1 -Profile lite
```

After completion:
```
Mitiphy Lite is ready.
Open http://localhost:7331  or run:  mitiphy chat
```

---

## 13. What `install.sh --profile lite` Does

Idempotent, resumable, every step prints one line with a status icon. **No container runtime touched.**

### Phase 1 — Preflight
1. Detect OS + arch (Linux/macOS/WSL, x86_64/arm64).
2. Detect existing tooling: git, curl, Python ≥ 3.12.
3. Free-resource check: RAM ≥ 6 GB, disk ≥ 8 GB, CPU cores ≥ 2, AVX2. Warn on short.
4. Network reachability to: PyPI, Hugging Face Hub, KEV/EPSS/abuse.ch/NVD/OSV endpoints. Mirror suggestion if blocked.
5. Privilege check: refuse root.

### Phase 2 — Install Missing Tooling
6. `uv` installed to `~/.local/bin` if missing.
7. `sigstore/cosign` for release-artifact verification.
8. `age` only if headless (no OS keyring backend detected).

No Docker, no Podman, no compose, no sops, no gpg.

### Phase 3 — Generate Local Config + Keys
9. Create `~/.mitiphy/` (state, audit DB, cases).
10. Generate dev-only signing keypair (cosign) in `~/.mitiphy/keys/cosign.*`.
11. Store API-key placeholders in OS keyring (or age-encrypted `~/.mitiphy/secrets.age` on headless).
12. Render runtime config (`~/.mitiphy/config.toml`) with chosen port (auto-pick if 7331 taken; print the picked port at end).

### Phase 4 — Python Environment + Embedded DBs
13. `uv sync --require-hashes` against committed lockfile.
14. Install `mitiphy` CLI shim on PATH via `uv tool install`.
15. Initialize KuzuDB database file at `~/.mitiphy/graph/kuzu.db`; load `schema.cypher`.
16. Initialize LanceDB collection at `~/.mitiphy/vectors/lance/`.
17. Initialize SQLite audit DB at `~/.mitiphy/audit.sqlite` with **genesis row** (hash of installer version + timestamp).
18. Initialize SQLite quota DB at `~/.mitiphy/quota.sqlite`.

### Phase 5 — Pull AI Model + Static Bundles
19. Download Llama 3.1 8B Instruct q4_K_M gguf (~4.7 GB) from Hugging Face Hub; checksum-verify against `data/checksums.json`.
20. **MITRE ATT&CK + CAPEC + D3FEND bundles** are baked into the wheel; no download. ~10 MB total.
21. **Lazy feed warm**: spawn background task that fetches first snapshot of KEV, EPSS, abuse.ch (URLhaus/ThreatFox/MalwareBazaar/Feodo), Spamhaus DROP/EDROP into `~/.mitiphy/feeds/`. Install does not block on this.

### Phase 6 — First-Run Verification
22. `mitiphy doctor` runs automatically: embedded DBs writable, model loadable, quotas at zero, audit DB anchored, web UI reachable, no egress to non-allowlisted hosts. Traffic-light output.
23. `mitiphy demo --dry-run` runs synthetic target end-to-end against bundled fixtures (vcrpy cassettes).

### Phase 7 — Persistence + Finish
24. Generate **systemd user unit** (Linux) or **launchd plist** (macOS) for auto-start on login (opt-in: `--enable-autostart`).
25. Write `~/.mitiphy/installed.json` with version, paths, port, key fingerprints, profile=`lite`.
26. Print success banner with the two ways to start.

Failure handling: exact error line, redacted log to `~/.mitiphy/install.log`, retry command (`./install.sh --resume phase=N`).

---

## 14. What Runs After Install

```
~/.mitiphy/ (state dir)
  ├── config.toml
  ├── audit.sqlite      (WAL)
  ├── quota.sqlite      (WAL)
  ├── graph/kuzu.db
  ├── vectors/lance/
  ├── feeds/            (lazy-warmed)
  ├── models/           (gguf)
  ├── keys/             (cosign + optional age)
  ├── plugins/          (drop-in)
  ├── cases/CASE-XXX/   (per-investigation outputs)
  └── logs/             (JSON)

Processes:
  mitiphy-core        (FastAPI + TUI + plugins + KuzuDB + LanceDB + asyncio bus)
  llama-cpp-server    (sibling, gguf model loaded)
```

No containers. No compose. No external services.

---

## 15. Auto-Integration After Boot

When `mitiphy` starts:

1. Discover collectors via entry-points + drop-in `~/.mitiphy/plugins/*.py`.
2. Probe llama.cpp sibling health; cache version.
3. Load AUP acceptance + signing keys.
4. Open asyncio streams for each collector group.
5. Subscribe enricher, scorer, reporter to the bus.
6. Start FastAPI on configured port; mount WebSocket for live case events; mount static SPA at `/`.
7. Start TUI listener if `mitiphy chat` invoked.
8. Register signal handlers for clean shutdown (flush audit chain, close KuzuDB transactions).
9. Emit `ready` event on bus.

---

## 16. Idempotency + Resume

- Checkpoint per phase in `~/.mitiphy/install.state.json`.
- `./install.sh --profile lite` skips completed phases.
- `--resume phase=N` re-runs from N.
- `--reset` wipes `~/.mitiphy/` after confirmation.
- `--offline` uses bundled tarball (CI-built nightly) with model + first feed snapshot for air-gapped boxes.

---

## 17. Upgrading

```bash
git pull
mitiphy upgrade
```

`mitiphy upgrade` steps:
1. Re-run preflight + tool checks.
2. `uv sync --require-hashes` against new lockfile.
3. Run schema migrations (alembic for SQLite; Cypher diff tool for KuzuDB).
4. Re-run `mitiphy doctor`.
5. Stop only if migration or doctor fails — previous version stays running.

Rollback: `git checkout <prev-tag> && mitiphy upgrade`.

---

## 18. Uninstall

```bash
./install.sh --uninstall
```

Removes `~/.mitiphy/` (with confirmation), CLI shim, systemd/launchd unit. Cases preserved unless `--purge-cases` passed.

---

## 19. Security of the Bootstrap Itself

- `install.sh` cosign-signed; README publishes verification command.
- All Python deps hash-pinned (`uv.lock`, `--require-hashes`).
- Model + feed snapshots checksum-verified against `data/checksums.json`.
- Installer refuses on checksum mismatch.
- No `curl | bash` from third-party hosts.
- Egress allowlist enforced in CI test.

---

## 20. End-to-End User Experience

```
1.  git clone https://github.com/<org>/mitiphy.git
2.  cd mitiphy
3.  ./install.sh --profile lite      ← 3–5 min depending on bandwidth
4.  mitiphy chat                      ← or open http://localhost:7331
5.  > investigate evil@example.com
6.  ← report.html + report.pdf (signed) in cases/CASE-XXX/
```

---

## 21. Resource Budget (Lite)

| Metric | Default model (8b q4) | Fast model (3b q4, `--model fast`) |
|--------|----------------------|------------------------------------|
| RAM working set | ~7 GB | ~4 GB |
| Disk | ~8 GB | ~5 GB |
| Install time | ~5 min | ~3 min |
| CPU floor | x86_64 AVX2 or arm64 | same |
| GPU | optional (Metal/CUDA/ROCm via llama.cpp) | optional |

Target boxes: M1/M2 Air, RPi 5 (8 GB) on fast-mode, $10–20/mo VPS, any analyst laptop.

---

## 22. Upgrade Path to Default / Full

A Lite install can graduate to Default or Full without re-bootstrap:

```bash
./install.sh --profile default   # adds Docker + SearXNG + active recon binaries
./install.sh --profile full      # adds Memgraph + observability stack
```

State (audit DB, KuzuDB, LanceDB, cases) is preserved. Schema migration tool reconciles graph dialect if user opts into Memgraph backend.

---

## 23. What Lite Trades Off

| Trade | Impact | Mitigation |
|-------|--------|-----------|
| No SearXNG aggregation | Narrower web search recall on obscure OSINT queries | Direct-adapter fan-out to Brave/DDG/Tavily; user can BYO keys |
| No active recon binaries | Cannot run subfinder/httpx/dnsx/testssl/wafw00f | Upgrade to Default profile (one command) |
| No Memgraph MAGE algos | Graph centrality falls back to KuzuDB built-in (or degree centrality) | Upgrade to Full profile if heavy analytics needed |
| No Grafana dashboards | No live ops dashboards | JSON logs + `mitiphy logs` cmd; OTel exporter opt-in via `--with otel` |
| Single-process, GIL-bound | Lower concurrent-user ceiling | Lite is single-analyst by design; team installs use Default/Full |
| Plugin crash kills core | Reduced isolation | Process supervisor (systemd/launchd) auto-restarts in ~3 s |

Recon authority sources, intel feeds, identity engines, reporting formats, audit chain, safety gates: **unchanged from `DESIGN.md`**.

---

That is the Lite MVP.
