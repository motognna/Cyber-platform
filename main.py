#!/usr/bin/env python3
"""AI Log Hunter & Tutor - CLI.

Analizeaza log-uri (auth.log / access.log), detecteaza atacuri, le coreleaza in incidente si
cere unui model Ollama local sa le explice educational.

Exemplu:  python main.py --log sample_logs/auth_bruteforce.log --model llama3.2
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from rich.markup import escape

from blue_team.aggregator import SecurityIncident, aggregate_alerts
from blue_team.ai_tutor import DEFAULT_MODEL, OllamaClient, OllamaError, TutorResult
from blue_team.detector import DEFAULT_BRUTEFORCE_THRESHOLD, scan_entries
from blue_team.parser import LogType, parse_log_file
from red_team.mock_logs import generate_synthetic_auth_log, generate_synthetic_web_log
from red_team.traffic_simulator import SimulationError, simulate_ssh_bruteforce, simulate_web_attacks
from ui.terminal import (
    console,
    export_markdown_report,
    live_explanation,
    print_banner,
    print_incidents_table,
    print_log_summary,
    print_tutor_warning,
)

EXIT_OK = 0
EXIT_ERROR = 1
DEFAULT_AI_INCIDENTS = 5


def build_parser() -> argparse.ArgumentParser:
    """Defineste argumentele liniei de comanda."""
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="AI Log Hunter & Tutor - detectie de atacuri in log-uri + mentor AI local (Ollama).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""exemple:
  python main.py --log sample_logs/auth_bruteforce.log --model llama3.2
  python main.py --log sample_logs/nginx_sqli.log --skip-ai
  python main.py --log sample_logs/auth_compromise.log --export raport.md
  python main.py --generate-mock demo.log --type auth --compromise
  python main.py --simulate ssh --target 127.0.0.1 --port 2222
  python main.py --check-ollama
""",
    )
    analysis = parser.add_argument_group("analiza (Blue Team)")
    analysis.add_argument("--log", "-l", metavar="FISIER", help="fisierul de log de analizat")
    analysis.add_argument(
        "--model", "-m", default=None, metavar="MODEL",
        help=f"modelul Ollama (implicit: {DEFAULT_MODEL}, sau $LOGHUNTER_MODEL)",
    )
    analysis.add_argument("--type", "-t", choices=["auth", "web"], help="forteaza tipul logului (implicit: autodetectie)")
    analysis.add_argument("--skip-ai", action="store_true", help="doar detectie, fara explicatii AI")
    analysis.add_argument(
        "--ai-top", type=int, default=DEFAULT_AI_INCIDENTS, metavar="N",
        help=f"explica prin AI doar primele N incidente dupa severitate (implicit: {DEFAULT_AI_INCIDENTS}, 0 = toate)",
    )
    analysis.add_argument(
        "--threshold", type=int, default=DEFAULT_BRUTEFORCE_THRESHOLD, metavar="N",
        help=f"nr. minim de autentificari esuate pentru brute force (implicit: {DEFAULT_BRUTEFORCE_THRESHOLD})",
    )
    analysis.add_argument("--export", "-e", metavar="RAPORT.md", help="salveaza raportul in format Markdown")

    lab = parser.add_argument_group("laborator (Red Team)")
    lab.add_argument("--simulate", choices=["ssh", "web"], help="genereaza trafic de atac catre o tinta de laborator")
    lab.add_argument("--target", default="127.0.0.1", help="IP-ul tintei (doar loopback/privat; implicit: 127.0.0.1)")
    lab.add_argument("--port", "-p", type=int, help="portul tintei (implicit: 22 pentru ssh, 80 pentru web)")
    lab.add_argument(
        "--with-valid-login", action="store_true",
        help="la --simulate ssh: adauga la final un login reusit (user victim) pentru a demonstra detectia compromiterii",
    )
    lab.add_argument("--generate-mock", metavar="FISIER", help="genereaza un log sintetic (cu --type auth|web)")
    lab.add_argument("--compromise", action="store_true", help="la --generate-mock auth: include un login reusit al atacatorului")

    parser.add_argument("--check-ollama", action="store_true", help="verifica Ollama si listeaza modelele instalate")
    return parser


def _count_nonempty_lines(path: Path) -> int:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        return sum(1 for line in handle if line.strip())


def cmd_check_ollama(client: OllamaClient) -> int:
    """Verifica conectivitatea cu Ollama."""
    health = client.check_connection()
    if not health["online"]:
        console.print(f"[bold red]Ollama indisponibil:[/bold red] {escape(str(health['error']))}")
        return EXIT_ERROR
    console.print(f"[bold green]Ollama ruleaza[/bold green] ({escape(client.base_url)})")
    if health["models"]:
        console.print("Modele instalate:")
        for name in health["models"]:
            console.print(f"  - {escape(name)}")
    else:
        console.print("[yellow]Niciun model instalat. Ruleaza: ollama pull llama3.2[/yellow]")
    return EXIT_OK


def cmd_generate_mock(path: str, log_type: str, compromise: bool) -> int:
    """Genereaza un log sintetic."""
    try:
        if log_type == "web":
            out = generate_synthetic_web_log(path)
        else:
            out = generate_synthetic_auth_log(path, include_compromise=compromise)
    except OSError as exc:
        console.print(f"[bold red]Nu pot scrie fisierul:[/bold red] {escape(str(exc))}")
        return EXIT_ERROR
    console.print(f"[bold green]Log {log_type} generat:[/bold green] {escape(str(out))}")
    return EXIT_OK


def cmd_simulate(service: str, target: str, port: Optional[int], with_valid_login: bool) -> int:
    """Ruleaza simulatorul Red Team."""
    port = port or (22 if service == "ssh" else 80)
    console.print(f"[bold yellow]Red Team: simulare {service.upper()} -> {target}:{port}[/bold yellow]")
    try:
        if service == "ssh":
            creds = ("victim", "password123") if with_valid_login else None
            result = simulate_ssh_bruteforce(target, port, valid_credentials=creds, progress=lambda m: console.print(escape(m)))
        else:
            result = simulate_web_attacks(target, port, progress=lambda m: console.print(escape(m)))
    except SimulationError as exc:
        console.print(f"[bold red]Simulare esuata:[/bold red] {escape(str(exc))}")
        return EXIT_ERROR
    console.print(
        f"[bold green]Gata:[/bold green] {result.attempts} actiuni trimise catre {escape(result.target)}"
        + (f", {result.successes} reusite" if result.service == "ssh" else "")
        + ".\nUrmatorul pas: extrage log-ul din laborator (./lab_setup/setup_lab.sh logs) si analizeaza-l cu --log."
    )
    return EXIT_OK


def _run_ai(
    incidents: List[SecurityIncident], client: OllamaClient, requested_model: Optional[str], top: int
) -> Dict[str, TutorResult]:
    """Genereaza explicatii AI pentru primele `top` incidente. Nu opreste analiza la erori."""
    results: Dict[str, TutorResult] = {}
    try:
        model = client.resolve_model(requested_model)
    except OllamaError as exc:
        console.print(f"[bold yellow]Explicatiile AI sunt omise:[/bold yellow] {escape(str(exc))}\n")
        return results

    selected = incidents if top <= 0 else incidents[:top]
    if len(selected) < len(incidents):
        console.print(f"[dim]AI: explic primele {len(selected)} din {len(incidents)} incidente (--ai-top).[/dim]")
    console.print(f"[bold cyan]AI Tutor:[/bold cyan] model [bold green]{escape(model)}[/bold green]\n")

    for incident in selected:
        try:
            with live_explanation(incident, model) as push:
                result = client.explain_incident(incident, model=model, on_token=push)
        except OllamaError as exc:
            console.print(f"[bold red]AI esuat pentru {incident.incident_id}:[/bold red] {escape(str(exc))}\n")
            if "conecta" in str(exc) or "intrerupt" in str(exc):
                break  # serviciul a cazut: nu mai insista pe restul incidentelor
            continue
        results[incident.incident_id] = result
        print_tutor_warning(result)
    return results


def cmd_analyze(args: argparse.Namespace) -> int:
    """Pipeline complet: parsare -> detectie -> agregare -> explicatii AI -> raport."""
    path = Path(args.log)
    forced = LogType(args.type) if args.type else None

    try:
        entries = parse_log_file(path, forced_type=forced)
        total = _count_nonempty_lines(path)
    except FileNotFoundError:
        console.print(f"[bold red]Fisierul nu exista:[/bold red] {escape(str(path))}")
        return EXIT_ERROR
    except IsADirectoryError:
        console.print(f"[bold red]Este un director, nu un fisier:[/bold red] {escape(str(path))}")
        return EXIT_ERROR
    except PermissionError:
        console.print(
            f"[bold red]Permisiune refuzata la citirea[/bold red] {escape(str(path))}.\n"
            f"Copiaza logul intr-un loc accesibil (ex. 'sudo cp {path} ./log.copy && sudo chown $USER ./log.copy') "
            "sau ruleaza cu un utilizator care il poate citi."
        )
        return EXIT_ERROR

    if not entries:
        console.print(
            f"[bold red]Nicio linie recunoscuta[/bold red] in {escape(str(path))}. Formatele suportate: syslog/auth.log si "
            "access.log Nginx/Apache (combined). Incearca --type auth sau --type web."
        )
        return EXIT_ERROR

    print_log_summary(entries, entries[0].log_type, str(path), total)

    alerts = scan_entries(entries, bruteforce_threshold=args.threshold)
    incidents = aggregate_alerts(alerts, bruteforce_threshold=args.threshold)
    print_incidents_table(incidents)

    explanations: Dict[str, TutorResult] = {}
    if incidents and not args.skip_ai:
        explanations = _run_ai(incidents, OllamaClient(), args.model, args.ai_top)

    if args.export:
        try:
            out = export_markdown_report(incidents, explanations, args.export, str(path))
        except OSError as exc:
            console.print(f"[bold red]Nu pot scrie raportul:[/bold red] {escape(str(exc))}")
            return EXIT_ERROR
        console.print(f"[bold green]Raport salvat:[/bold green] {escape(str(out))}")
    return EXIT_OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Punct de intrare. Returneaza codul de iesire al procesului."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.threshold < 1:
        parser.error("--threshold trebuie sa fie >= 1")

    print_banner()
    try:
        if args.check_ollama:
            return cmd_check_ollama(OllamaClient())
        if args.generate_mock:
            return cmd_generate_mock(args.generate_mock, args.type or "auth", args.compromise)
        if args.simulate:
            return cmd_simulate(args.simulate, args.target, args.port, args.with_valid_login)
        if args.log:
            return cmd_analyze(args)
    except KeyboardInterrupt:
        console.print("\n[yellow]Intrerupt de utilizator.[/yellow]")
        return 130

    parser.print_help()
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
