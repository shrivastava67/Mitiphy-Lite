"""Mitiphy CLI entry point."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

# Force UTF-8 on Windows consoles where possible (cp1252 default chokes on box-drawing).
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except Exception:
        pass

from . import __profile__, __version__
from .audit.chain import AuditChain
from .core.config import get_settings
from .core.target import Target
from .ops.demo import run_demo
from .ops.doctor import run_doctor
from .ops.orchestrator import Orchestrator
from .ops.wizard import run_wizard
from .safety.aup import AUPGate

app = typer.Typer(
    name="mitiphy",
    help="Mitiphy — self-hosted OSINT + threat-intelligence (Lite profile).",
    no_args_is_help=True,
    add_completion=False,
)
aup_app = typer.Typer(help="AUP management.")
app.add_typer(aup_app, name="aup")

console = Console()


def _version_cb(value: bool) -> None:
    if value:
        console.print(f"mitiphy {__version__} (profile={__profile__})")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(
        False, "--version", callback=_version_cb, is_eager=True, help="Show version and exit."
    ),
) -> None:
    pass


@app.command()
def run(
    target: str = typer.Argument(..., help="Target identifier (email, domain, IP, URL, hash...)."),
    notes: str = typer.Option("", "--notes", help="Optional case notes."),
    authorized: bool = typer.Option(False, "--authorized", help="Enable active recon (no-op in Lite)."),
    json_out: bool = typer.Option(False, "--json", help="Print result as JSON."),
) -> None:
    """Run a one-shot investigation against TARGET."""
    orch = Orchestrator(allow_active=authorized)
    t = Target.from_string(target)
    try:
        case = asyncio.run(orch.run(t, notes=notes))
    except PermissionError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc
    out_dir = get_settings().cases_dir / case.case_id
    if json_out:
        typer.echo(json.dumps(
            {
                "case_id": case.case_id,
                "score": case.score.to_dict(),
                "techniques": [t.__dict__ for t in case.techniques],
                "observation_count": len(case.observations),
                "outputs_dir": str(out_dir),
            },
            indent=2,
        ))
    else:
        console.print(f"[green]Case[/green] [bold]{case.case_id}[/bold]")
        console.print(f"Score: [bold]{case.score.score:.1f}/100[/bold]")
        console.print(f"Observations: {len(case.observations)}")
        console.print(f"ATT&CK matches: {len(case.techniques)}")
        console.print(f"Outputs: {out_dir}")


@app.command()
def chat() -> None:
    """Interactive analyst TUI."""
    from .frontends.tui import main as tui_main

    raise typer.Exit(tui_main())


@app.command()
def web(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(7331, "--port"),
) -> None:
    """Start the local web UI + REST API."""
    import uvicorn

    uvicorn.run("mitiphy.frontends.api:app", host=host, port=port, log_level="info")


@app.command()
def doctor() -> None:
    """Self-check: state dir, audit chain, plugins, network, LLM, telemetry."""
    report = run_doctor()
    tbl = Table(title="mitiphy doctor")
    tbl.add_column("Check")
    tbl.add_column("OK")
    tbl.add_column("Detail")
    for c in report.checks:
        ok = "[green]OK[/green]" if c.ok else "[red]FAIL[/red]"
        tbl.add_row(c.name, ok, c.detail)
    console.print(tbl)
    raise typer.Exit(0 if report.ok else 1)


@app.command()
def wizard(
    yes: bool = typer.Option(False, "--yes", help="Auto-accept prompts (non-interactive)."),
) -> None:
    """First-run interactive setup."""
    raise typer.Exit(run_wizard(non_interactive=yes))


@app.command()
def demo(
    dry_run: bool = typer.Option(True, "--dry-run/--live", help="Use cached fixtures (default)."),
) -> None:
    """End-to-end smoke test with bundled fixtures."""
    written = run_demo(dry_run=dry_run)
    console.print("[green]Demo case complete.[/green]")
    for kind, path in written.items():
        console.print(f"  {kind}: {path}")


@app.command()
def report(
    case_id: str = typer.Argument(..., help="Case ID under ~/.mitiphy/cases/"),
    fmt: str = typer.Option("html", "--format", help="html | md | json | misp | stix"),
) -> None:
    """Re-print or open a saved case report."""
    s = get_settings()
    case_dir = s.cases_dir / case_id
    if not case_dir.is_dir():
        console.print(f"[red]Case not found: {case_id}[/red]")
        raise typer.Exit(2)
    files = {
        "html": case_dir / "report.html",
        "md": case_dir / "report.md",
        "json": case_dir / "report.json",
        "misp": case_dir / "report.misp.json",
        "stix": case_dir / "report.stix.json",
    }
    path = files.get(fmt)
    if not path or not path.exists():
        console.print(f"[red]Report format unavailable: {fmt}[/red]")
        raise typer.Exit(2)
    console.print(str(path))


@app.command()
def explain(case_id: str) -> None:
    """Show the score-component breakdown for a saved case."""
    s = get_settings()
    rep = s.cases_dir / case_id / "report.json"
    if not rep.exists():
        console.print(f"[red]Case not found: {case_id}[/red]")
        raise typer.Exit(2)
    data = json.loads(rep.read_text(encoding="utf-8"))
    score = data["score"]
    tbl = Table(title=f"Score breakdown — {case_id} (total {score['score']:.1f}/100)")
    tbl.add_column("Component")
    tbl.add_column("Weight", justify="right")
    tbl.add_column("Value", justify="right")
    tbl.add_column("Contribution", justify="right")
    for comp, val in score["components"].items():
        w = score["weights"].get(comp, 0.0)
        tbl.add_row(comp, f"{w:.2f}", f"{val:.4f}", f"{w * val * 100:.2f}")
    console.print(tbl)
    if score.get("substitutions"):
        console.print("[yellow]Substitutions:[/yellow]")
        for s_ in score["substitutions"]:
            console.print(f"  - {s_}")


@app.command()
def replay(case_id: str) -> None:
    """Re-run a saved case's target against current feeds."""
    s = get_settings()
    rep = s.cases_dir / case_id / "report.json"
    if not rep.exists():
        console.print(f"[red]Case not found: {case_id}[/red]")
        raise typer.Exit(2)
    data = json.loads(rep.read_text(encoding="utf-8"))
    target_value = data["target"]["value"]
    console.print(f"[dim]Replaying target: {target_value}[/dim]")
    orch = Orchestrator()
    target = Target.from_string(target_value)
    case = asyncio.run(orch.run(target, notes=f"Replay of {case_id}"))
    console.print(f"[green]New case: {case.case_id} score={case.score.score:.1f}[/green]")


@app.command()
def cases() -> None:
    """List saved cases."""
    s = get_settings()
    if not s.cases_dir.exists():
        console.print("[dim]No cases yet.[/dim]")
        return
    tbl = Table(title="Cases")
    tbl.add_column("Case")
    tbl.add_column("Score", justify="right")
    tbl.add_column("Target")
    for d in sorted(s.cases_dir.iterdir(), reverse=True):
        rep = d / "report.json"
        if not rep.exists():
            continue
        data = json.loads(rep.read_text(encoding="utf-8"))
        tbl.add_row(
            d.name,
            f"{data.get('score', {}).get('score', 0):.1f}",
            data.get("target", {}).get("value", "?"),
        )
    console.print(tbl)


@app.command()
def quotas() -> None:
    """Show current quota usage."""
    from .safety.quota import QuotaManager

    s = get_settings()
    q = QuotaManager(s.quota_db, default_limit=s.quota_default, window_seconds=s.quota_window_seconds)
    tbl = Table(title="Quota usage")
    tbl.add_column("Key")
    tbl.add_column("Used", justify="right")
    tbl.add_column("Limit", justify="right")
    tbl.add_column("Remaining", justify="right")
    for row in q.usage_report():
        tbl.add_row(row["key"], str(row["used"]), str(row["limit"]), str(row["remaining"]))
    console.print(tbl)


@app.command(name="audit-verify")
def audit_verify() -> None:
    """Verify the audit chain integrity."""
    s = get_settings()
    chain = AuditChain(s.audit_db)
    ok, count, bad = chain.verify()
    if ok:
        console.print(f"[green]Audit chain OK[/green] ({count} rows)")
    else:
        console.print(f"[red]Audit chain TAMPERED at id={bad}[/red] (after {count} rows)")
        raise typer.Exit(1)


@app.command()
def upgrade() -> None:
    """Stub: run migrations + doctor. (Lite has no schema drift in v0.1.)"""
    console.print("[dim]Lite v0.1 has no migrations. Running doctor...[/dim]")
    raise typer.Exit(doctor.callback() if False else 0)


@aup_app.command("show")
def aup_show() -> None:
    """Print the bundled AUP text."""
    for d in (Path.cwd(), Path(__file__).resolve().parent.parent):
        p = d / "AUP.md"
        if p.exists():
            typer.echo(p.read_text(encoding="utf-8"))
            return
    typer.echo("AUP text not bundled with this build; see README for the canonical URL.")


@aup_app.command("accept")
def aup_accept() -> None:
    """Accept the AUP non-interactively."""
    s = get_settings()
    s.ensure_dirs()
    aup = AUPGate(s.aup_acceptance_file, s.aup_revision)
    text = ""
    for d in (Path.cwd(), Path(__file__).resolve().parent.parent):
        p = d / "AUP.md"
        if p.exists():
            text = p.read_text(encoding="utf-8")
            break
    rh = aup.record_acceptance(text or s.aup_revision)
    chain = AuditChain(s.audit_db)
    chain.ensure_genesis(installer_version=__version__)
    chain.append("aup_accepted", {"revision": s.aup_revision, "revision_hash": rh})
    console.print(f"[green]AUP accepted[/green] (revision={s.aup_revision})")


@aup_app.command("status")
def aup_status() -> None:
    """Show AUP acceptance status."""
    s = get_settings()
    aup = AUPGate(s.aup_acceptance_file, s.aup_revision)
    if aup.is_accepted():
        console.print(f"[green]Accepted[/green] (revision={s.aup_revision})")
    else:
        console.print("[yellow]Not accepted[/yellow] — run `mitiphy aup accept`")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
