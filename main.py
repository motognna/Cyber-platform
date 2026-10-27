#!/usr/bin/env python3
"""
AI Log Hunter & Tutor
---------------------
An educational Blue & Red team platform for log analysis, heuristic threat detection,
and AI-assisted incident triage via local Ollama LLMs.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Dict, Optional

from rich.console import Console

from blue_team.aggregator import aggregate_alerts
from blue_team.ai_tutor import DEFAULT_MODEL, OllamaClient
from blue_team.detector import scan_entries
from blue_team.parser import LogType, parse_log_file
from red_team.mock_logs import generate_synthetic_auth_log, generate_synthetic_web_log
from red_team.traffic_simulator import simulate_ssh_auth_traffic, simulate_web_traffic
from ui.terminal import (
    console,
    export_markdown_report,
    print_ai_explanation,
    print_banner,
    print_incidents_table,
    print_log_summary,
)


def handle_check_ollama(client: OllamaClient) -> None:
    """Check Ollama connectivity and display installed models."""
    console.print("[bold cyan]Verificare conectivitate Ollama (http://localhost:11434)...[/bold cyan]")
    health = client.check_connection()
    if health["online"]:
        models = health["models"]
        console.print("[bold green]✓ Serviciul Ollama ruleaza si este accesibil![/bold green]")
        if models:
            console.print("[cyan]Modele disponibile local:[/cyan]")
            for m in models:
                console.print(f"  • [bold white]{m}[/bold white]")
        else:
            console.print("[yellow]! Nu exista niciun model descărcat. Ruleaza: 'ollama pull llama3.2'[/yellow]")
    else:
        console.print(f"[bold red]✗ Conexiunea a esuat:[/bold red]\n{health['error']}")


def handle_generate_mock(output_file: str, log_type_str: str) -> None:
    """Generate mock log data for offline practice."""
    path = Path(output_file)
    if log_type_str == "web":
        generate_synthetic_web_log(path)
        console.print(f"[bold green]✓ Fisier mock Nginx generat cu succes la:[/bold green] [bold white]{path}[/bold white]")
    else:
        generate_synthetic_auth_log(path)
        console.print(f"[bold green]✓ Fisier mock SSH auth generat cu succes la:[/bold green] [bold white]{path}[/bold white]")


def handle_simulation(service: str, target: str, port: int) -> None:
    """Run safe lab traffic simulator."""
    console.print(f"[bold yellow]⚠️  Lansare simulator de trafic Red Team catre {target}:{port}...[/bold yellow]")
    try:
        if service == "ssh":
            simulate_ssh_auth_traffic(target_host=target, target_port=port)
        elif service == "web":
            simulate_web_traffic(target_host=target, target_port=port)
        else:
            console.print(f"[red]Serviciu necunoscut: {service}. Alege 'ssh' sau 'web'.[/red]")
    except ValueError as ve:
        console.print(f"[bold red]Eroare de siguranta:[/bold red] {ve}")
    except Exception as exc:
        console.print(f"[bold red]Eroare simulare:[/bold red] {exc}")


def handle_analysis(
    log_file: str,
    model_name: str,
    log_type_opt: Optional[str] = None,
    skip_ai: bool = False,
    export_path: Optional[str] = None,
) -> None:
    """Execute the full Blue Team analysis pipeline."""
    target_path = Path(log_file)
    if not target_path.exists():
        console.print(f"[bold red]Eroare:[/bold red] Fisierul de log nu exista: [bold white]{log_file}[/bold white]")
        sys.exit(1)

    forced_type = None
    if log_type_opt:
        forced_type = LogType.AUTH if log_type_opt.lower() == "auth" else LogType.WEB

    try:
        entries = parse_log_file(target_path, forced_type=forced_type)
    except PermissionError:
        console.print(
            f"[bold red]Eroare de permisiuni:[/bold red] Nu ai drepturi de citire pentru [bold white]{log_file}[/bold white].\n"
            "Foloseste 'sudo' sau copiaza log-ul intr-un director accesibil utilizatorului tau."
        )
        sys.exit(1)
    except Exception as exc:
        console.print(f"[bold red]Eroare la parsarea fisierului:[/bold red] {exc}")
        sys.exit(1)

    if not entries:
        console.print(f"[yellow]Fisierul {log_file} este gol sau nu contine linii compatibile de log.[/yellow]")
        return

    detected_type = entries[0].log_type
    print_log_summary(entries, detected_type, str(target_path))

    # Run detection rules
    alerts = scan_entries(entries)
    incidents = aggregate_alerts(alerts)

    print_incidents_table(incidents)

    explanations: Dict[str, str] = {}

    if incidents and not skip_ai:
        client = OllamaClient()
        health = client.check_connection()

        if not health["online"]:
            console.print(
                f"[bold yellow]⚠️  Ollama nu este disponibil.[/bold yellow] Sarim peste analiza AI.\n"
                f"[dim]{health['error']}[/dim]\n"
            )
        else:
            resolved_model = client.resolve_model(model_name)
            console.print(
                f"[bold cyan]🤖 Initiere AI Tutor cu modelul:[/bold cyan] [bold green]{resolved_model}[/bold green]\n"
            )

            for inc in incidents:
                with console.status(
                    f"[bold cyan]Ollama ({resolved_model}) analizeaza incidentul {inc.incident_id}...[/bold cyan]",
                    spinner="dots",
                ):
                    explanation = client.explain_incident(inc, model=resolved_model)

                explanations[inc.incident_id] = explanation
                print_ai_explanation(inc, explanation)

    # Optional report export
    if export_path:
        out = export_markdown_report(incidents, explanations, export_path, str(target_path))
        console.print(f"[bold green]✓ Raport Markdown salvat cu succes la:[/bold green] [bold white]{out}[/bold white]")


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="AI Log Hunter & Tutor - Educational Cybersecurity CLI & Local AI Mentor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemple de utilizare:
  # 1. Analizeaza un fisier auth.log cu modelul default llama3.2:
  python main.py --log sample_logs/auth_bruteforce.log

  # 2. Analizeaza log-uri web specificand modelul:
  python main.py --log sample_logs/nginx_sqli.log --model llama3.2

  # 3. Analizeaza fara AI (doar euristica & tabel incidente):
  python main.py --log sample_logs/auth_bruteforce.log --skip-ai

  # 4. Salveaza raport complet Markdown:
  python main.py --log sample_logs/auth_bruteforce.log --export raport_incident.md

  # 5. Genereaza log-uri mock pentru teste:
  python main.py --generate-mock test_ssh.log --type auth

  # 6. Verifica starea conexiunii Ollama:
  python main.py --check-ollama
        """,
    )

    parser.add_argument(
        "--log",
        "-l",
        type=str,
        help="Calea catre fisierul de log ce urmeaza sa fie analizat (ex: /var/log/auth.log sau sample_logs/auth_bruteforce.log)",
    )
    parser.add_argument(
        "--model",
        "-m",
        type=str,
        default=DEFAULT_MODEL,
        help=f"Numele modelului Ollama utilizat pentru explicatii (default: {DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--type",
        "-t",
        choices=["auth", "web"],
        help="Forteaza tipul de log (auth sau web). Daca este omis, tipul este detectat automat.",
    )
    parser.add_argument(
        "--skip-ai",
        action="store_true",
        help="Ruleaza doar parsarea si tabelul de incidente, fara interogarea modelului Ollama.",
    )
    parser.add_argument(
        "--export",
        "-e",
        type=str,
        help="Salveaza rezultatele si analiza AI intr-un raport Markdown la calea specificata.",
    )
    parser.add_argument(
        "--check-ollama",
        action="store_true",
        help="Verifica daca serviciul Ollama este activ si afiseaza lista de modele descarcate.",
    )
    parser.add_argument(
        "--generate-mock",
        type=str,
        metavar="OUTPUT_FILE",
        help="Genereaza un fisier de log sintetic pentru testare rapida (foloseste --type pentru auth sau web).",
    )
    parser.add_argument(
        "--simulate",
        choices=["ssh", "web"],
        help="Lanseaza simulatorul de trafic de laborator impotriva unei tinte locale (ex: --simulate ssh).",
    )
    parser.add_argument(
        "--target",
        type=str,
        default="127.0.0.1",
        help="Adresa IP a tintei locale pentru simulare (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--port",
        "-p",
        type=int,
        help="Portul tintei pentru simulare (default: 22 pentru ssh, 80 pentru web).",
    )

    return parser


def main() -> None:
    """CLI application entrypoint."""
    parser = build_parser()
    args = parser.parse_args()

    print_banner()

    if args.check_ollama:
        handle_check_ollama(OllamaClient())
        return

    if args.generate_mock:
        handle_generate_mock(args.generate_mock, args.type or "auth")
        return

    if args.simulate:
        default_port = 22 if args.simulate == "ssh" else 80
        port = args.port or default_port
        handle_simulation(args.simulate, args.target, port)
        return

    if args.log:
        handle_analysis(
            log_file=args.log,
            model_name=args.model,
            log_type_opt=args.type,
            skip_ai=args.skip_ai,
            export_path=args.export,
        )
        return

    # If no primary action passed, display help
    parser.print_help()


if __name__ == "__main__":
    main()
