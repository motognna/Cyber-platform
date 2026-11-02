"""Interfata de terminal (Rich) si export de rapoarte Markdown."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional

from rich.console import Console
from rich.live import Live
from rich.markup import escape
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from blue_team.aggregator import SecurityIncident
from blue_team.ai_tutor import TutorResult, normalize_headings
from blue_team.catalog import Severity
from blue_team.parser import LogType, ParsedEntry

console = Console()

_SEVERITY_STYLE: Dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold green",
}


def print_banner() -> None:
    """Afiseaza bannerul aplicatiei."""
    title = Text("AI LOG HUNTER & TUTOR", style="bold white")
    subtitle = Text("Analiza de log-uri, detectie MITRE ATT&CK si mentor AI local (Ollama)", style="cyan")
    console.print(Panel(Text.assemble(title, "\n", subtitle), border_style="cyan", expand=False))


def severity_badge(severity: Severity) -> Text:
    """Eticheta colorata pentru severitate."""
    return Text(f" {severity.value} ", style=_SEVERITY_STYLE[severity])


def print_log_summary(entries: List[ParsedEntry], log_type: LogType, file_path: str, total_lines: int) -> None:
    """Sumar de incarcare: fisier, format, linii recunoscute."""
    table = Table(title="1. Log incarcat", border_style="dim", show_header=False)
    table.add_column(style="cyan")
    table.add_column(style="bold white")
    table.add_row("Fisier", Text(str(file_path)))
    table.add_row("Format detectat", log_type.value.upper())
    table.add_row("Linii recunoscute", f"{len(entries)} / {total_lines}")
    if entries:
        table.add_row("Interval", Text(f"{entries[0].timestamp or 'n/a'}  ->  {entries[-1].timestamp or 'n/a'}"))
    console.print(table)
    skipped = total_lines - len(entries)
    if skipped > 0:
        console.print(f"[dim]{skipped} linii nerecunoscute au fost ignorate (goale sau format diferit).[/dim]")
    console.print()


def print_incidents_table(incidents: List[SecurityIncident]) -> None:
    """Tabelul incidentelor corelate, sortat dupa severitate."""
    if not incidents:
        console.print(
            Panel(
                "[bold green]Nu s-au detectat tipare malitioase in acest log.[/bold green]",
                title="2. Rezultat analiza",
                border_style="green",
            )
        )
        return

    table = Table(title="2. Incidente detectate", border_style="red", header_style="bold magenta", show_lines=True)
    table.add_column("ID", style="bold", no_wrap=True)
    table.add_column("Severitate", justify="center", no_wrap=True)
    table.add_column("Incident", overflow="fold", ratio=3)
    table.add_column("IP sursa", style="cyan", no_wrap=True)
    table.add_column("Nr.", justify="right", style="yellow", no_wrap=True)
    table.add_column("MITRE", style="dim", no_wrap=True)

    for inc in incidents:
        table.add_row(
            inc.incident_id,
            severity_badge(inc.severity),
            Text(inc.title),
            Text(inc.source_ip),
            str(inc.event_count),
            inc.mitre_id,
        )
    console.print(table)
    console.print()


class _LiveExplanation:
    """Panou cu continut Markdown actualizat pe masura ce modelul genereaza tokeni."""

    def __init__(self, title: str) -> None:
        self.title = title
        self.text = ""

    def __rich__(self) -> Panel:
        return Panel(
            Markdown(self.text or "_Modelul gandeste..._"),
            title=f"[bold green]{escape(self.title)}[/bold green]",
            border_style="bright_blue",
            padding=(1, 2),
        )


@contextmanager
def live_explanation(incident: SecurityIncident, model: str) -> Iterator[Callable[[str], None]]:
    """Context manager care afiseaza live raspunsul AI; ofera un callback `push(token)`."""
    view = _LiveExplanation(f"AI Tutor ({model}) - {incident.incident_id}: {incident.title}")
    with Live(view, console=console, refresh_per_second=8, vertical_overflow="visible"):

        def push(token: str) -> None:
            view.text += token

        yield push


def print_tutor_warning(result: TutorResult) -> None:
    """Avertisment cand modelul nu a respectat structura ceruta."""
    if not result.is_well_formed:
        console.print(
            f"[yellow]Atentie: raspunsul nu contine sectiunile: {escape(', '.join(result.missing_sections))}. "
            "Incearca un model mai capabil (--model).[/yellow]"
        )
    console.print(f"[dim]Generat local in {result.seconds:.1f}s - datele nu parasesc acest calculator.[/dim]\n")


def export_markdown_report(
    incidents: List[SecurityIncident],
    explanations: Dict[str, TutorResult],
    output_path: Path | str,
    log_source: str,
) -> Path:
    """Scrie un raport Markdown complet (sumar, dovezi, analiza AI)."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# Raport de triage - AI Log Hunter & Tutor",
        "",
        f"- **Sursa:** `{log_source}`",
        f"- **Generat:** {datetime.now():%Y-%m-%d %H:%M:%S}",
        f"- **Incidente:** {len(incidents)}",
        "",
        "## Sumar",
        "",
        "| ID | Severitate | Incident | IP sursa | Nr. | MITRE |",
        "|---|---|---|---|---|---|",
    ]
    for inc in incidents:
        lines.append(
            f"| {inc.incident_id} | {inc.severity.value} | {inc.title} | `{inc.source_ip}` | "
            f"{inc.event_count} | `{inc.mitre_id}` |"
        )

    lines += ["", "## Detalii incidente", ""]
    for inc in incidents:
        lines += [
            f"### {inc.incident_id} - {inc.title}",
            "",
            f"- **Severitate:** {inc.severity.value}",
            f"- **IP sursa:** `{inc.source_ip}`",
            f"- **Interval:** {inc.first_seen} -> {inc.last_seen}",
            f"- **MITRE ATT&CK:** {inc.mitre_id} ({inc.mitre_tactic})",
            f"- **Tinte:** {', '.join(inc.targeted_entities) or 'n/a'}",
            "",
            "**Dovezi (linii de log):**",
            "",
            "```log",
            *inc.sample_logs,
            "```",
            "",
        ]
        result = explanations.get(inc.incident_id)
        if result:
            lines += [
                f"#### Analiza AI Tutor (`{result.model}`)",
                "",
                normalize_headings(result.text, level=5),
                "",
            ]
        lines += ["---", ""]

    path.write_text("\n".join(lines), encoding="utf-8")
    return path
