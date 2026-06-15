"""Rich-based simple TUI for `mitiphy chat`.

Full Textual-app TUI is deferred — this is a serviceable Rich loop that lets
an analyst run targets, see scores, list cases.
"""

from __future__ import annotations

import asyncio
import json

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from ..core.config import get_settings
from ..core.target import Target
from ..ops.orchestrator import Orchestrator


def banner(console: Console) -> None:
    console.print(
        Panel.fit(
            "[bold cyan]Mitiphy[/bold cyan] — Lite profile\n"
            "Type a target (email/domain/ip/url/hash), or one of: "
            "[green]list[/green], [green]quota[/green], [green]quit[/green]",
            border_style="cyan",
        )
    )


async def chat() -> int:
    s = get_settings()
    s.ensure_dirs()
    console = Console()
    orch = Orchestrator()
    banner(console)
    while True:
        try:
            user = Prompt.ask("[bold]mitiphy[/bold]")
        except (EOFError, KeyboardInterrupt):
            console.print()
            return 0
        if not user.strip():
            continue
        cmd = user.strip().lower()
        if cmd in {"quit", "exit", ":q"}:
            return 0
        if cmd == "list":
            tbl = Table(title="Recent cases")
            tbl.add_column("Case")
            tbl.add_column("Score", justify="right")
            tbl.add_column("Target")
            for d in sorted(s.cases_dir.iterdir(), reverse=True)[:20]:
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
            continue
        if cmd == "quota":
            tbl = Table(title="Quota usage")
            tbl.add_column("Key")
            tbl.add_column("Used", justify="right")
            tbl.add_column("Limit", justify="right")
            tbl.add_column("Remaining", justify="right")
            for row in orch.quota.usage_report():
                tbl.add_row(row["key"], str(row["used"]), str(row["limit"]), str(row["remaining"]))
            console.print(tbl)
            continue

        target = Target.from_string(user)
        console.print(f"[dim]→ detected type: {target.type.value}[/dim]")
        try:
            case = await orch.run(target)
        except PermissionError as exc:
            console.print(f"[red]{exc}[/red]")
            continue
        s_val = case.score.score
        sev_color = "red" if s_val >= 70 else "yellow" if s_val >= 40 else "green"
        console.print(
            Panel.fit(
                f"Case [bold]{case.case_id}[/bold]\n"
                f"Score: [bold {sev_color}]{s_val:.1f}/100[/bold {sev_color}]\n"
                f"Observations: {len(case.observations)}\n"
                f"ATT&CK matches: {len(case.techniques)}\n"
                f"Outputs: ~/.mitiphy/cases/{case.case_id}/",
                title="Result",
                border_style=sev_color,
            )
        )


def main() -> int:
    return asyncio.run(chat())
