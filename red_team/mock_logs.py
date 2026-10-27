"""Mock log generator for generating authentic telemetry for educational training and testing."""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional


SAMPLE_USERS = ["root", "admin", "ubuntu", "test", "user", "guest", "support", "developer", "postgres", "backup"]
SAMPLE_USER_AGENTS = [
    "sqlmap/1.6#stable",
    "Nikto/2.1.6",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "curl/7.88.1",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
]
SAMPLE_WEB_PATHS = [
    ("/index.html", 200, 1420),
    ("/products.php?id=1%20OR%201=1", 200, 4310),
    ("/products.php?id=-1%20UNION%20SELECT%201,table_name%20FROM%20information_schema.tables--", 200, 5820),
    ("/download.php?file=../../../../etc/passwd", 403, 287),
    ("/.env", 404, 162),
    ("/wp-config.php.bak", 404, 162),
    ("/phpmyadmin/", 404, 162),
    ("/about.html", 200, 2150),
    ("/api/v1/health", 200, 32),
]


def generate_synthetic_auth_log(
    output_path: Path | str,
    attacker_ip: str = "192.168.1.188",
    num_failed: int = 15,
    include_success: bool = True
) -> Path:
    """Generate realistic Linux auth.log lines simulating an SSH brute-force attack."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    lines: List[str] = []
    base_time = datetime.now() - timedelta(minutes=10)

    for i in range(num_failed):
        ts = (base_time + timedelta(seconds=i * 2 + random.randint(1, 3))).strftime("%b %d %H:%M:%S")
        user = random.choice(SAMPLE_USERS)
        port = random.randint(40000, 60000)
        pid = 12000 + i

        if random.random() < 0.6:
            lines.append(f"{ts} lab-server sshd[{pid}]: Failed password for invalid user {user} from {attacker_ip} port {port} ssh2\n")
        else:
            lines.append(f"{ts} lab-server sshd[{pid}]: Failed password for {user} from {attacker_ip} port {port} ssh2\n")

    # Add background noise
    ts_noise = (base_time + timedelta(seconds=num_failed * 3)).strftime("%b %d %H:%M:%S")
    lines.append(f"{ts_noise} lab-server CRON[13000]: pam_unix(cron:session): session opened for user root by (uid=0)\n")
    lines.append(f"{ts_noise} lab-server CRON[13000]: pam_unix(cron:session): session closed for user root\n")

    if include_success:
        ts_ok = (base_time + timedelta(seconds=num_failed * 3 + 15)).strftime("%b %d %H:%M:%S")
        lines.append(f"{ts_ok} lab-server sshd[13050]: Accepted publickey for sysadmin from 192.168.1.10 port 51234 ssh2: RSA SHA256:abc789def\n")
        lines.append(f"{ts_ok} lab-server sshd[13050]: pam_unix(sshd:session): session opened for user sysadmin by (uid=1000)\n")

    path.write_text("".join(lines), encoding="utf-8")
    return path


def generate_synthetic_web_log(
    output_path: Path | str,
    attacker_ip: str = "192.168.1.188",
    legit_ip: str = "192.168.1.55"
) -> Path:
    """Generate realistic Nginx/Apache Combined access.log lines with web attack patterns."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    lines: List[str] = []
    base_time = datetime.now() - timedelta(minutes=5)

    for i, (req_path, status, size) in enumerate(SAMPLE_WEB_PATHS):
        ts = (base_time + timedelta(seconds=i * 5)).strftime("%d/%b/%Y:%H:%M:%S +0300")
        is_attack = any(k in req_path for k in ["OR%201=1", "UNION", "..", ".env", "wp-config", "phpmyadmin"])
        ip = attacker_ip if is_attack else legit_ip
        ua = "sqlmap/1.6#stable" if "UNION" in req_path or "OR" in req_path else (
            "Nikto/2.1.6" if any(k in req_path for k in [".env", "wp-config"]) else "Mozilla/5.0"
        )
        referrer = "https://lab-server/" if not is_attack else "-"

        line = f'{ip} - - [{ts}] "GET {req_path} HTTP/1.1" {status} {size} "{referrer}" "{ua}"\n'
        lines.append(line)

    path.write_text("".join(lines), encoding="utf-8")
    return path
