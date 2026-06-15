"""mitiphy wizard — first-run interactive setup."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.prompt import Confirm, Prompt

from .. import __version__
from ..audit.chain import AuditChain
from ..core.config import get_settings
from ..safety.aup import AUPGate

AUP_FILE_CANDIDATES = ["AUP.md"]


def _aup_text() -> str:
    for name in AUP_FILE_CANDIDATES:
        for d in (Path.cwd(), Path(__file__).resolve().parent.parent.parent):
            p = d / name
            if p.exists():
                return p.read_text(encoding="utf-8")
    return "AUP text not bundled with this build; see https://github.com/mitiphy/mitiphy/blob/main/AUP.md"


def run_wizard(non_interactive: bool = False) -> int:
    console = Console()
    s = get_settings()
    s.ensure_dirs()
    chain = AuditChain(s.audit_db)
    chain.ensure_genesis(installer_version=__version__)
    aup = AUPGate(s.aup_acceptance_file, s.aup_revision)

    console.rule("[bold cyan]Mitiphy first-run wizard")
    console.print(f"State directory: [green]{s.state_dir}[/green]")
    console.print(f"AUP revision:    [green]{s.aup_revision}[/green]")
    console.print()

    if aup.is_accepted():
        console.print("[green]AUP already accepted for this revision.[/green]")
    else:
        text = _aup_text()
        console.print(text)
        if non_interactive or Confirm.ask(
            "\nDo you accept the Acceptable Use Policy?", default=False
        ):
            rev_hash = aup.record_acceptance(text)
            chain.append("aup_accepted", {"revision": s.aup_revision, "revision_hash": rev_hash})
            console.print("[green]AUP accepted and recorded in audit chain.[/green]")
        else:
            console.print("[yellow]AUP not accepted — exiting.[/yellow]")
            return 1

    if not non_interactive:
        console.print()
        provider = Prompt.ask(
            "LLM provider", choices=["none", "llamacpp", "ollama"], default=s.llm_provider
        )
        if provider != s.llm_provider:
            console.print(
                f"[dim]Set MITIPHY_LLM_PROVIDER={provider} or add `llm_provider = \"{provider}\"` to "
                f"{s.config_file}[/dim]"
            )

    console.print()
    console.print("[bold green]Wizard complete.[/bold green] Try: [cyan]mitiphy demo[/cyan]")
    return 0
