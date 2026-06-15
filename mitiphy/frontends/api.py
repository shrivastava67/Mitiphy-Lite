"""FastAPI server.

Minimal surface for Lite:
  GET  /healthz       -> liveness
  GET  /readyz        -> readiness (audit chain verifies + quota DB ok)
  GET  /version       -> {"version": ..., "profile": "lite"}
  GET  /quotas        -> usage report
  POST /investigate   -> body {target: str, notes?: str}; returns case summary
  GET  /cases         -> list saved cases
  GET  /cases/{id}    -> case detail
  WS   /ws            -> live audit-chain events (post-MVP; placeholder)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .. import __profile__, __version__
from ..audit.chain import AuditChain
from ..core.config import get_settings
from ..core.target import Target
from ..ops.doctor import run_doctor
from ..ops.orchestrator import Orchestrator
from ..safety.quota import QuotaManager


def create_app() -> FastAPI:
    s = get_settings()
    s.ensure_dirs()

    app = FastAPI(
        title="Mitiphy",
        version=__version__,
        description="Self-hosted OSINT + threat-intelligence platform (Lite profile).",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost", f"http://{s.host}:{s.port}", f"http://127.0.0.1:{s.port}"],
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    # Static UI (web/static).
    static_dir = Path(__file__).resolve().parent.parent.parent / "web" / "static"
    if static_dir.is_dir():
        app.mount("/ui", StaticFiles(directory=str(static_dir), html=True), name="ui")

    @app.get("/", response_class=HTMLResponse)
    async def root() -> str:
        index = static_dir / "index.html"
        if index.exists():
            return index.read_text(encoding="utf-8")
        return (
            "<html><body><h1>Mitiphy</h1>"
            "<p>Lite profile API. UI assets not bundled.</p>"
            "<p>Endpoints: <code>/healthz</code>, <code>/readyz</code>, "
            "<code>/version</code>, <code>/quotas</code>, <code>/investigate</code>, "
            "<code>/cases</code></p></body></html>"
        )

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz() -> dict[str, Any]:
        report = run_doctor()
        return {
            "ready": report.ok,
            "checks": [c.__dict__ for c in report.checks],
        }

    @app.get("/version")
    async def version() -> dict[str, str]:
        return {"version": __version__, "profile": __profile__}

    @app.get("/quotas")
    async def quotas() -> list[dict[str, Any]]:
        q = QuotaManager(s.quota_db, default_limit=s.quota_default, window_seconds=s.quota_window_seconds)
        return q.usage_report()

    class InvestigateBody(BaseModel):
        target: str
        notes: str = ""
        allow_active: bool = False

    @app.post("/investigate")
    async def investigate(body: InvestigateBody) -> dict[str, Any]:
        orch = Orchestrator(allow_active=body.allow_active)
        target = Target.from_string(body.target)
        case = await orch.run(target, notes=body.notes)
        return {
            "case_id": case.case_id,
            "score": case.score.to_dict(),
            "techniques": [t.__dict__ for t in case.techniques],
            "observation_count": len(case.observations),
        }

    @app.get("/cases")
    async def list_cases() -> list[dict[str, str]]:
        if not s.cases_dir.exists():
            return []
        out = []
        for d in sorted(s.cases_dir.iterdir(), reverse=True):
            if d.is_dir() and (d / "report.json").exists():
                out.append({"case_id": d.name, "path": str(d)})
        return out[:200]

    @app.get("/cases/{case_id}")
    async def case_detail(case_id: str) -> dict[str, Any]:
        path = s.cases_dir / case_id / "report.json"
        if not path.exists():
            raise HTTPException(404, "case not found")
        return json.loads(path.read_text(encoding="utf-8"))

    @app.get("/cases/{case_id}/report.html", response_class=HTMLResponse)
    async def case_html(case_id: str) -> FileResponse:
        path = s.cases_dir / case_id / "report.html"
        if not path.exists():
            raise HTTPException(404, "report not found")
        return FileResponse(str(path))

    @app.get("/audit/verify")
    async def audit_verify() -> dict[str, Any]:
        chain = AuditChain(s.audit_db)
        ok, count, bad = chain.verify()
        return {"ok": ok, "rows": count, "first_bad_id": bad}

    return app


app = create_app()
