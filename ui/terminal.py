"""Rich-powered terminal formatting, status banners, incident tables, and AI report rendering."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from blue_team.aggregator import SecurityIncident
from blue_team.detector import Severity
from blue_team.parser import LogType, ParsedEntry


console = Console()


def print_banner() -> None:
    """Display the AI Log Hunter & Tutor ASCII banner and intro."""
    banner_text = Text()
    banner_text.append("╔════════════════════════════════════════════════════════════════╗\n", style="bold cyan")
    banner_text.append("║                🛡️  AI LOG HUNTER & TUTOR  🔍                   ║\n", style="bold white on blue")
    banner_text.append("║      Hands-on Cyber Defense, Incident Triage & Local AI Mentor  ║\n", style="bold cyan")
    banner_text.append("╚════════════════════════════════════════════════════════════════╝", style="bold cyan")
    console.print(banner_text)
    console.print()


def print_log_summary(entries: List[ParsedEntry], log_type: LogType, file_path: str) -> None:
    """Print an initial high-level telemetry summary."""
    table = Table(title="[bold blue]1. Telemetrie & Incarcare Fisier Log[/bold blue]", border_style="dim")
    table.add_column("Proprietate", style="cyan", justify="left")
    table.add_column("Valoare", style="bold white", justify="left")

    table.add_row("Cale Fisier", str(file_path))
    table.add_row("Format Detectat", f"[magenta]{log_type.value.upper()}[/magenta]")
    table.add_row("Linii Parseate cu Succes", str(len(entries)))

    if entries:
        ts_first = entries[0].timestamp or "N/A"
        ts_last = entries[-1].timestamp or "N/A"
        table.add_row("Fereastra Temporala", f"{ts_first}  -->  {ts_last}")

    console.print(table)
    console.print()


def get_severity_badge(severity: Severity) -> str:
    """Return a styled color badge for the severity."""
    if severity == Severity.CRITICAL:
        return "[bold white on red] CRITICAL [/bold white on red]"
    elif severity == Severity.HIGH:
        return "[bold red] HIGH [/bold red]"
    elif severity == Severity.MEDIUM:
        return "[bold yellow] MEDIUM [/bold yellow]"
    return "[bold green] LOW [/bold green]"


def print_incidents_table(incidents: List[SecurityIncident]) -> None:
    """Render a structured summary table of all correlated security incidents."""
    if not incidents:
        console.print(
            Panel(
                "[bold green]✓ Nu s-au detectat tipare malițioase sau anomalii evidente în acest log.[/bold green]\n"
                "Toate liniile analizate par trafic sau autentificări de rutină.",
                title="[bold green]Rezultat Analiza Euristica[/bold green]",
                border_style="green",
            )
        )
        return

    table = Table(
        title="[bold red]2. Incidente de Securitate Detectate & Corelate[/bold red]",
        border_style="red",
        header_style="bold magenta",
        show_lines=True,
    )
    table.add_column("ID", style="bold white", width=9, justify="center")
    table.add_column("Severitate", width=12, justify="center")
    table.add_column("Titlu / Tip Atac", style="bold", min_width=28)
    table.add_column("IP Atacator", style="cyan", justify="center")
    table.add_column("Evenimente", style="yellow", justify="center")
    table.add_column("Cadru MITRE ATT&CK", style="dim white")

    for inc in incidents:
        table.add_row(
            inc.incident_id,
            get_severity_badge(inc.severity),
            inc.title,
            inc.source_ip,
            str(inc.event_count),
            inc.mitre_id,
        )

    console.print(table)
    console.print()


def print_ai_explanation(incident: SecurityIncident, explanation_markdown: str) -> None:
    """Display the AI Tutor explanation in a styled rich markdown panel."""
    header = f"🎓 AI TUTOR — Analiza Incident: {incident.incident_id} ({incident.title})"
    md = Markdown(explanation_markdown)

    panel = Panel(
        md,
        title=f"[bold green]{header}[/bold green]",
        subtitle="[dim]Generat local via Ollama LLM • Confidențialitate 100%[/dim]",
        border_style="bright_blue",
        padding=(1, 2),
    )
    console.print(panel)
    console.print()


def export_markdown_report(
    incidents: List[SecurityIncident],
    explanations: Dict[str, str],
    output_path: Path | str,
    log_source: str,
) -> Path:
    """Export the full triage session into a clean, professional Markdown report."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# Raport de Triage & Securitate Cibernetică",
        f"**Sursa Telemetrie:** `{log_source}`  ",
        f"**Număr Incidente Identificate:** {len(incidents)}  \n",
        "---",
        "## 1. Sumar Executiv al Incidentelor\n",
        "| ID Incident | Severitate | Tip Atac | IP Sursă | Evenimente | MITRE ATT&CK |",
        "|---|---|---|---|---|---|",
    ]

    for inc in incidents:
        lines.append(
            f"| **{inc.incident_id}** | {inc.severity.value} | {inc.title} | `{inc.source_ip}` | {inc.event_count} | `{inc.mitre_id}` |"
        )

    lines.append("\n---\n## 2. Detalii Tehnice & Analiza AI Tutor\n")

    for inc in incidents:
        lines.append(f"### Incident {inc.incident_id}: {inc.title}")
        lines.append(f"- **Adresă IP Atacator:** `{inc.source_ip}`")
        lines.append(f"- **Interval Timp:** {inc.first_seen} - {inc.last_seen}")
        lines.append(f"- **Tinte Vizate:** {', '.join(inc.targeted_entities) if inc.targeted_entities else 'N/A'}")
        lines.append("\n**Mostră Log-uri Reale:**")
        lines.append("```log")
        for log in inc.sample_logs:
            lines.append(log)
        lines.append("```\n")

        expl = explanations.get(inc.incident_id)
        if expl:
            lines.append(expl)
        lines.append("\n---\n")

    path.write_text("\n".join(lines), encoding="utf-8")
    return path
