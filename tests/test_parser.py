"""Unit tests for the log parser, detector, and aggregator."""

import unittest
from pathlib import Path
import tempfile

from blue_team.parser import LogType, parse_auth_line, parse_web_line, parse_log_file, detect_log_type
from blue_team.detector import scan_entries, AttackType, Severity
from blue_team.aggregator import aggregate_alerts
from red_team.mock_logs import generate_synthetic_auth_log, generate_synthetic_web_log


class TestLogParser(unittest.TestCase):
    """Test parsing logic for both auth and web log lines."""

    def test_parse_auth_failed_invalid_user(self):
        line = "Oct 22 18:14:02 victim-server sshd[28412]: Failed password for invalid user admin from 192.168.1.150 port 49152 ssh2"
        entry = parse_auth_line(line, 1)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.service, "sshd")
        self.assertEqual(entry.event_type, "invalid_user")
        self.assertEqual(entry.username, "admin")
        self.assertEqual(entry.source_ip, "192.168.1.150")
        self.assertEqual(entry.port, 49152)

    def test_parse_auth_failed_known_user(self):
        line = "Oct 22 18:14:15 victim-server sshd[28425]: Failed password for ubuntu from 192.168.1.150 port 49164 ssh2"
        entry = parse_auth_line(line, 2)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.event_type, "failed_password")
        self.assertEqual(entry.username, "ubuntu")
        self.assertEqual(entry.source_ip, "192.168.1.150")

    def test_parse_auth_accepted(self):
        line = "Oct 22 18:25:30 victim-server sshd[28601]: Accepted publickey for sysadmin from 192.168.1.10 port 52341 ssh2: RSA SHA256:abc123def456"
        entry = parse_auth_line(line, 3)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.event_type, "accepted")
        self.assertEqual(entry.username, "sysadmin")
        self.assertEqual(entry.source_ip, "192.168.1.10")

    def test_parse_web_line_sqli(self):
        line = '192.168.1.150 - - [22/Oct/2026:18:30:15 +0300] "GET /products.php?id=1%20OR%201=1 HTTP/1.1" 200 4520 "-" "sqlmap/1.6#stable"'
        entry = parse_web_line(line, 1)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.source_ip, "192.168.1.150")
        self.assertEqual(entry.method, "GET")
        self.assertEqual(entry.url_path, "/products.php")
        self.assertIn("1 OR 1=1", entry.query_string)
        self.assertEqual(entry.status_code, 200)
        self.assertEqual(entry.user_agent, "sqlmap/1.6#stable")


class TestDetectionAndAggregation(unittest.TestCase):
    """Test heuristic detection rules and incident correlation."""

    def test_detect_and_aggregate_ssh_bruteforce(self):
        lines = [
            "Oct 22 18:14:02 srv sshd[101]: Failed password for invalid user admin from 10.0.0.5 port 50001 ssh2",
            "Oct 22 18:14:04 srv sshd[102]: Failed password for invalid user root from 10.0.0.5 port 50002 ssh2",
            "Oct 22 18:14:06 srv sshd[103]: Failed password for test from 10.0.0.5 port 50003 ssh2",
        ]
        entries = [parse_auth_line(l, idx) for idx, l in enumerate(lines, 1)]
        alerts = scan_entries(entries)
        self.assertEqual(len(alerts), 3)

        incidents = aggregate_alerts(alerts)
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc.source_ip, "10.0.0.5")
        self.assertEqual(inc.event_count, 3)
        self.assertIn("admin", inc.targeted_entities)
        self.assertIn("root", inc.targeted_entities)
        self.assertIn("test", inc.targeted_entities)

    def test_detect_web_sqli_and_path_traversal(self):
        lines = [
            '10.0.0.9 - - [22/Oct/2026:12:00:00 +0000] "GET /page.php?id=-1%20UNION%20SELECT%201,2-- HTTP/1.1" 200 100 "-" "Mozilla/5.0"',
            '10.0.0.9 - - [22/Oct/2026:12:00:05 +0000] "GET /view.php?file=../../../../etc/passwd HTTP/1.1" 403 50 "-" "Mozilla/5.0"',
        ]
        entries = [parse_web_line(l, idx) for idx, l in enumerate(lines, 1)]
        alerts = scan_entries(entries)
        self.assertTrue(any(a.attack_type == AttackType.SQL_INJECTION for a in alerts))
        self.assertTrue(any(a.attack_type == AttackType.PATH_TRAVERSAL for a in alerts))

        incidents = aggregate_alerts(alerts)
        self.assertEqual(len(incidents), 2)


class TestMockLogGeneration(unittest.TestCase):
    """Test generating synthetic log files."""

    def test_generate_auth_mock(self):
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            generate_synthetic_auth_log(tmp_path, num_failed=5)
            self.assertTrue(tmp_path.exists())
            entries = parse_log_file(tmp_path, forced_type=LogType.AUTH)
            self.assertGreaterEqual(len(entries), 5)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()


if __name__ == "__main__":
    unittest.main()
