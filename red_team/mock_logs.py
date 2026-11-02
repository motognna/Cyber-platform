"""Generator de log-uri sintetice (offline) pentru exercitii si teste."""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

SAMPLE_USERS = ["root", "admin", "ubuntu", "test", "user", "guest", "support", "oracle", "postgres"]

WEB_ATTACK_REQUESTS = [
    ("/products.php?id=1%20OR%201=1", 200, 4310, "sqlmap/1.6#stable"),
    ("/products.php?id=-1%20UNION%20SELECT%201,table_name%20FROM%20information_schema.tables--", 200, 5820, "sqlmap/1.6#stable"),
    ("/download.php?file=../../../../etc/passwd", 403, 287, "Mozilla/5.0"),
    ("/search?q=%3Cscript%3Ealert(1)%3C/script%3E", 200, 912, "Mozilla/5.0"),
    ("/.env", 404, 162, "Nikto/2.1.6"),
    ("/wp-config.php.bak", 404, 162, "Nikto/2.1.6"),
    ("/phpmyadmin/", 404, 162, "Mozilla/5.0"),
]
WEB_LEGIT_REQUESTS = [
    ("/index.html", 200, 1420),
    ("/about.html", 200, 2150),
    ("/api/v1/health", 200, 32),
    ("/style.css", 200, 3411),
]


def generate_synthetic_auth_log(
    output_path: Path | str,
    attacker_ip: str = "192.168.1.188",
    num_failed: int = 15,
    include_compromise: bool = False,
    seed: Optional[int] = None,
) -> Path:
    """Genereaza un auth.log realist cu un brute force SSH (+ optional login reusit al atacatorului).

    Args:
        include_compromise: adauga un login reusit de la IP-ul atacatorului dupa esecuri.
        seed: face generarea deterministica (utila in teste).
    """
    rng = random.Random(seed)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    base = datetime.now() - timedelta(minutes=10)
    lines: List[str] = []
    pid = 12000

    for i in range(num_failed):
        ts = (base + timedelta(seconds=i * 2)).strftime("%b %d %H:%M:%S")
        user = rng.choice(SAMPLE_USERS)
        port = rng.randint(40000, 60000)
        pid += 1
        if user in ("root", "admin", "ubuntu") and rng.random() < 0.5:
            lines.append(f"{ts} lab-server sshd[{pid}]: Failed password for {user} from {attacker_ip} port {port} ssh2\n")
        else:
            lines.append(f"{ts} lab-server sshd[{pid}]: Invalid user {user} from {attacker_ip} port {port}\n")
            lines.append(f"{ts} lab-server sshd[{pid}]: Failed password for invalid user {user} from {attacker_ip} port {port} ssh2\n")

    noise_ts = (base + timedelta(seconds=num_failed * 2 + 5)).strftime("%b %d %H:%M:%S")
    lines.append(f"{noise_ts} lab-server CRON[13000]: pam_unix(cron:session): session opened for user root by (uid=0)\n")
    lines.append(f"{noise_ts} lab-server CRON[13000]: pam_unix(cron:session): session closed for user root\n")
    lines.append(f"{noise_ts} lab-server sshd[13050]: Accepted publickey for sysadmin from 192.168.1.10 port 51234 ssh2: RSA SHA256:abc789def\n")

    if include_compromise:
        ts = (base + timedelta(seconds=num_failed * 2 + 20)).strftime("%b %d %H:%M:%S")
        lines.append(f"{ts} lab-server sshd[13099]: Accepted password for ubuntu from {attacker_ip} port 55555 ssh2\n")

    path.write_text("".join(lines), encoding="utf-8")
    return path


def generate_synthetic_web_log(
    output_path: Path | str,
    attacker_ip: str = "192.168.1.188",
    legit_ip: str = "192.168.1.55",
    seed: Optional[int] = None,
) -> Path:
    """Genereaza un access.log (format combined) cu trafic legitim si atacuri web."""
    rng = random.Random(seed)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    base = datetime.now() - timedelta(minutes=5)
    events = [(legit_ip, p, s, z, "Mozilla/5.0") for p, s, z in WEB_LEGIT_REQUESTS]
    events += [(attacker_ip, p, s, z, ua) for p, s, z, ua in WEB_ATTACK_REQUESTS]
    rng.shuffle(events)

    lines = []
    for i, (ip, req, status, size, ua) in enumerate(events):
        ts = (base + timedelta(seconds=i * 4)).strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(f'{ip} - - [{ts}] "GET {req} HTTP/1.1" {status} {size} "-" "{ua}"\n')

    path.write_text("".join(lines), encoding="utf-8")
    return path
