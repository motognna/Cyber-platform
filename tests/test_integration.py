"""Teste de integrare: client Ollama (server fals local), CLI end-to-end, simulator, raport."""

import contextlib
import io
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

from blue_team.aggregator import aggregate_alerts
from blue_team.ai_tutor import (
    OllamaClient,
    OllamaError,
    find_missing_sections,
    normalize_headings,
)
from blue_team.detector import scan_entries
from blue_team.parser import LogType, parse_log_file
from red_team.mock_logs import generate_synthetic_auth_log, generate_synthetic_web_log
from red_team.traffic_simulator import SimulationError, is_safe_target, simulate_ssh_bruteforce
import main as cli

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "sample_logs"

GOOD = (
    "## 1. Tip Atac\nSSH brute force\n## 2. Ce a incercat atacatorul\nSa ghiceasca parole\n"
    "## 3. Explicație Tehnică\nMulte autentificari esuate\n## 4. Soluție de Remediere\n1. fail2ban\n"
    "## 5. Provocare pentru tine\nDe ce?"
)


class FakeOllama:
    """Server HTTP minimal care imita /api/tags si /api/chat (streaming NDJSON)."""

    def __init__(self, models=("llama3.2:latest",), replies=(GOOD,), chat_status=200, error_chunk=None):
        self.models, self.replies, self.chat_status, self.error_chunk = list(models), list(replies), chat_status, error_chunk
        self.chat_calls = 0
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # tacut
                pass

            def do_GET(self):
                body = json.dumps({"models": [{"name": m} for m in outer.models]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                reply = outer.replies[min(outer.chat_calls, len(outer.replies) - 1)]
                outer.chat_calls += 1
                self.send_response(outer.chat_status)
                self.end_headers()
                if outer.chat_status != 200:
                    self.wfile.write(b"model not found")
                    return
                if outer.error_chunk:
                    self.wfile.write((json.dumps({"error": outer.error_chunk}) + "\n").encode())
                    return
                for word in reply.split(" "):
                    self.wfile.write((json.dumps({"message": {"content": word + " "}, "done": False}) + "\n").encode())
                self.wfile.write((json.dumps({"message": {"content": ""}, "done": True}) + "\n").encode())

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def first_incident():
    entries = parse_log_file(SAMPLES / "auth_bruteforce.log")
    return aggregate_alerts(scan_entries(entries))[0]


class TestOllamaClient(unittest.TestCase):
    def test_streaming_and_structure_ok(self):
        fake = FakeOllama()
        self.addCleanup(fake.close)
        tokens = []
        result = OllamaClient(fake.url).explain_incident(first_incident(), on_token=tokens.append)
        self.assertTrue(result.is_well_formed)
        self.assertEqual(result.model, "llama3.2:latest")
        self.assertGreater(len(tokens), 5)  # raspunsul a sosit in bucati
        self.assertEqual(fake.chat_calls, 1)

    def test_malformed_answer_is_retried_once(self):
        fake = FakeOllama(replies=("raspuns fara structura", GOOD))
        self.addCleanup(fake.close)
        result = OllamaClient(fake.url).explain_incident(first_incident())
        self.assertEqual(fake.chat_calls, 2)
        self.assertTrue(result.is_well_formed)

    def test_still_malformed_after_retry_reports_missing(self):
        fake = FakeOllama(replies=("nimic util",))
        self.addCleanup(fake.close)
        result = OllamaClient(fake.url).explain_incident(first_incident())
        self.assertFalse(result.is_well_formed)
        self.assertIn("Tip Atac", result.missing_sections)

    def test_model_resolution(self):
        fake = FakeOllama(models=("llama3.2:latest", "qwen2.5:7b"))
        self.addCleanup(fake.close)
        c = OllamaClient(fake.url)
        self.assertEqual(c.resolve_model("llama3.2"), "llama3.2:latest")
        self.assertEqual(c.resolve_model("qwen2.5:7b"), "qwen2.5:7b")
        with self.assertRaises(OllamaError) as ctx:
            c.resolve_model("llama3")
        self.assertIn("ollama pull llama3", str(ctx.exception))
        # fara model explicit si implicit lipsa -> primul instalat
        self.assertEqual(OllamaClient(fake.url, model="nu-exista").resolve_model(), "llama3.2:latest")

    def test_service_down_gives_clear_error(self):
        with self.assertRaises(OllamaError) as ctx:
            OllamaClient("http://127.0.0.1:1").list_models()
        self.assertIn("ollama serve", str(ctx.exception))
        self.assertFalse(OllamaClient("http://127.0.0.1:1").check_connection()["online"])

    def test_error_chunk_and_http_errors(self):
        fake = FakeOllama(error_chunk="out of memory")
        self.addCleanup(fake.close)
        with self.assertRaises(OllamaError) as ctx:
            OllamaClient(fake.url).explain_incident(first_incident())
        self.assertIn("out of memory", str(ctx.exception))

        fake404 = FakeOllama(chat_status=404)
        self.addCleanup(fake404.close)
        with self.assertRaises(OllamaError):
            OllamaClient(fake404.url).explain_incident(first_incident())

    def test_section_validation_is_accent_insensitive(self):
        self.assertEqual(find_missing_sections("tip atac, explicatie tehnica, solutie de remediere"), [])

    def test_normalize_headings_keeps_code_comments(self):
        md = "## Titlu\ntext\n```bash\n# comentariu\nls\n```\n\n# Alt titlu"
        out = normalize_headings(md, level=5)
        self.assertIn("##### Titlu", out)
        self.assertIn("##### Alt titlu", out)
        self.assertIn("\n# comentariu\n", out)
        self.assertIn("\n\n", out)  # liniile goale raman


def run_cli(*argv):
    out = io.StringIO()
    original = cli.console.file
    cli.console.file = out
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            code = cli.main(list(argv))
    finally:
        cli.console.file = original
    return code, out.getvalue()


class TestCli(unittest.TestCase):
    def test_skip_ai_detects_and_exports(self):
        with tempfile.TemporaryDirectory() as d:
            report = Path(d) / "sub" / "r.md"
            code, out = run_cli("--log", str(SAMPLES / "auth_compromise.log"), "--skip-ai", "--export", str(report))
            self.assertEqual(code, 0)
            self.assertIn("INC-001", out)
            text = report.read_text()
            self.assertIn("T1078", text)
            self.assertIn("203.0.113.45", text)

    def test_errors_return_nonzero(self):
        self.assertEqual(run_cli("--log", "/nonexistent.log")[0], 1)
        self.assertEqual(run_cli("--log", str(SAMPLES))[0], 1)
        with tempfile.TemporaryDirectory() as d:
            junk = Path(d) / "junk.log"
            junk.write_text("not a log\n")
            code, out = run_cli("--log", str(junk))
            self.assertEqual(code, 1)
            self.assertIn("Nicio linie recunoscuta", out)

    def test_unreadable_file_reports_permission_error(self):
        with mock.patch("main.parse_log_file", side_effect=PermissionError):
            code, out = run_cli("--log", str(SAMPLES / "auth_bruteforce.log"))
        self.assertEqual(code, 1)
        self.assertIn("Permisiune refuzata", out)

    def test_full_pipeline_with_fake_ollama_and_report(self):
        fake = FakeOllama()
        self.addCleanup(fake.close)
        with tempfile.TemporaryDirectory() as d, mock.patch("main.OllamaClient", lambda: OllamaClient(fake.url)):
            report = Path(d) / "r.md"
            code, out = run_cli("--log", str(SAMPLES / "auth_bruteforce.log"), "--model", "llama3.2", "--export", str(report))
            self.assertEqual(code, 0)
            self.assertIn("llama3.2:latest", out)
            self.assertIn("AI Tutor (llama3.2:latest)", out)
            body = report.read_text()
            self.assertIn("Soluție de Remediere", body)
            self.assertIn("```log", body)

    def test_bracketed_paths_are_not_rich_markup(self):
        with tempfile.TemporaryDirectory() as d:
            odd = Path(d) / "log[bold red].log"
            odd.write_text((SAMPLES / "auth_bruteforce.log").read_text())
            code, out = run_cli("--log", str(odd), "--skip-ai")
            self.assertEqual(code, 0)
            self.assertIn("log[bold red].log", out)
            code, out = run_cli("--log", str(Path(d) / "lipsa[x].log"))
            self.assertEqual(code, 1)
            self.assertIn("lipsa[x].log", out)

    def test_ai_down_does_not_break_analysis(self):
        with mock.patch("main.OllamaClient", lambda: OllamaClient("http://127.0.0.1:1")):
            code, out = run_cli("--log", str(SAMPLES / "auth_bruteforce.log"))
        self.assertEqual(code, 0)
        self.assertIn("INC-001", out)
        self.assertIn("omise", out)

    def test_unknown_model_does_not_break_analysis(self):
        fake = FakeOllama()
        self.addCleanup(fake.close)
        with mock.patch("main.OllamaClient", lambda: OllamaClient(fake.url)):
            code, out = run_cli("--log", str(SAMPLES / "auth_bruteforce.log"), "--model", "llama3")
        self.assertEqual(code, 0)
        self.assertIn("ollama pull llama3", out.replace("\n", " "))

    def test_ai_top_limits_explained_incidents(self):
        fake = FakeOllama()
        self.addCleanup(fake.close)
        with mock.patch("main.OllamaClient", lambda: OllamaClient(fake.url)):
            run_cli("--log", str(SAMPLES / "nginx_sqli.log"), "--ai-top", "2")
        self.assertEqual(fake.chat_calls, 2)

    def test_check_ollama_and_help(self):
        fake = FakeOllama()
        self.addCleanup(fake.close)
        with mock.patch("main.OllamaClient", lambda: OllamaClient(fake.url)):
            self.assertEqual(run_cli("--check-ollama")[0], 0)
        with mock.patch("main.OllamaClient", lambda: OllamaClient("http://127.0.0.1:1")):
            self.assertEqual(run_cli("--check-ollama")[0], 1)
        self.assertEqual(run_cli()[0], 0)  # fara argumente -> help

    def test_generate_mock_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            auth, web = Path(d) / "a.log", Path(d) / "w.log"
            self.assertEqual(run_cli("--generate-mock", str(auth), "--type", "auth", "--compromise")[0], 0)
            self.assertEqual(run_cli("--generate-mock", str(web), "--type", "web")[0], 0)
            code, out = run_cli("--log", str(auth), "--skip-ai")
            self.assertEqual(code, 0)
            self.assertIn("MITRE", out)
            code, out = run_cli("--log", str(web), "--skip-ai")
            self.assertEqual(code, 0)


class TestMockLogsAndSimulator(unittest.TestCase):
    def test_mock_auth_log_is_detected_as_attack(self):
        with tempfile.TemporaryDirectory() as d:
            p = generate_synthetic_auth_log(Path(d) / "a.log", num_failed=12, include_compromise=True, seed=1)
            incidents = aggregate_alerts(scan_entries(parse_log_file(p, LogType.AUTH)))
            self.assertEqual(incidents[0].attack_type.value, "ssh_compromise")
            self.assertTrue(any(i.event_count >= 12 for i in incidents))

    def test_mock_web_log_has_attacks_but_not_legit_ip(self):
        with tempfile.TemporaryDirectory() as d:
            p = generate_synthetic_web_log(Path(d) / "w.log", seed=2)
            incidents = aggregate_alerts(scan_entries(parse_log_file(p)))
            self.assertGreaterEqual(len(incidents), 5)
            self.assertTrue(all(i.source_ip == "192.168.1.188" for i in incidents))

    def test_only_private_targets_allowed(self):
        self.assertTrue(is_safe_target("127.0.0.1"))
        self.assertTrue(is_safe_target("192.168.56.101"))
        self.assertTrue(is_safe_target("localhost"))
        self.assertFalse(is_safe_target("8.8.8.8"))
        self.assertFalse(is_safe_target("203.0.113.5"))
        self.assertFalse(is_safe_target("nu-exista.invalid"))
        with self.assertRaises(SimulationError):
            simulate_ssh_bruteforce("8.8.8.8", 22)

    def test_ssh_simulation_to_closed_port_fails_clearly(self):
        with self.assertRaises(SimulationError) as ctx:
            simulate_ssh_bruteforce("127.0.0.1", 1, users=["a"], passwords=["b"], delay=0)
        self.assertIn("setup_lab.sh start", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
