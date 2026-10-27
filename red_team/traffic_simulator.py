"""Safe Lab Traffic Simulator: Generates controlled network telemetry against local VM/containers."""

from __future__ import annotations

import ipaddress
import socket
import subprocess
import time
from typing import List, Optional
import requests


# Safety guard: only private and loopback IP addresses allowed for lab simulations
ALLOWED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
]


def is_safe_target(host: str) -> bool:
    """Validate that the target host resolves strictly to a local or private RFC 1918 address."""
    if host.lower() in ("localhost", "127.0.0.1", "::1"):
        return True

    try:
        resolved_ip = socket.gethostbyname(host)
        ip_obj = ipaddress.ip_address(resolved_ip)
        return any(ip_obj in net for net in ALLOWED_NETWORKS)
    except Exception:
        return False


def simulate_ssh_auth_traffic(
    target_host: str = "127.0.0.1",
    target_port: int = 22,
    usernames: Optional[List[str]] = None,
    delay: float = 0.5
) -> int:
    """Safely generate failed SSH authentication events on the target lab VM/container."""
    if not is_safe_target(target_host):
        raise ValueError(
            f"Tinta '{target_host}' nu este o adresa IP de laborator privat/local!\n"
            f"Simulatorul refuza sa execute conexiuni catre adrese publice din motive de securitate."
        )

    targets = usernames or ["admin", "root", "guest", "test_user", "support"]
    attempts_done = 0

    print(f"[*] Pornire simulare SSH pe {target_host}:{target_port} (Total tinte: {len(targets)})...")

    for user in targets:
        print(f"  [-] Trimitere incercare autentificare pentru utilizatorul: '{user}'...")
        # Use system ssh command in batch mode with strict timeout and no password prompt
        cmd = [
            "ssh",
            "-p", str(target_port),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=2",
            "-o", "PreferredAuthentications=password",
            f"{user}@{target_host}",
            "exit"
        ]
        try:
            subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=4
            )
            attempts_done += 1
        except subprocess.TimeoutExpired:
            attempts_done += 1
        except Exception as exc:
            print(f"  [!] Notificare: Conexiunea a intampinat o eroare: {exc}")

        time.sleep(delay)

    print(f"[+] Simulare finalizata! S-au inregistrat {attempts_done} evenimente de test catre {target_host}.")
    return attempts_done


def simulate_web_traffic(
    target_host: str = "127.0.0.1",
    target_port: int = 80,
    delay: float = 0.3
) -> int:
    """Send harmless, benign test HTTP requests that mimic known security scan signatures."""
    if not is_safe_target(target_host):
        raise ValueError(f"Tinta '{target_host}' nu este o adresa IP locala!")

    test_payloads = [
        ("/", {"User-Agent": "Mozilla/5.0"}),
        ("/products.php?id=1%20OR%201=1", {"User-Agent": "sqlmap/1.6#stable"}),
        ("/products.php?id=-1%20UNION%20SELECT%201,table_name%20FROM%20information_schema.tables--", {"User-Agent": "sqlmap/1.6#stable"}),
        ("/download.php?file=../../../../etc/passwd", {"User-Agent": "Mozilla/5.0"}),
        ("/.env", {"User-Agent": "Nikto/2.1.6"}),
        ("/wp-config.php.bak", {"User-Agent": "Nikto/2.1.6"}),
        ("/phpmyadmin/", {"User-Agent": "Mozilla/5.0"}),
    ]

    print(f"[*] Trimitere {len(test_payloads)} cereri HTTP de test catre http://{target_host}:{target_port}...")
    count = 0

    for path, headers in test_payloads:
        url = f"http://{target_host}:{target_port}{path}"
        try:
            resp = requests.get(url, headers=headers, timeout=3)
            print(f"  [-] Cerere: {path[:45]}... -> Status HTTP {resp.status_code}")
            count += 1
        except requests.exceptions.ConnectionError:
            print(f"  [!] Serverul web nu raspunde pe http://{target_host}:{target_port}. Asigura-te ca serviciul este pornit.")
            break
        except Exception as exc:
            print(f"  [!] Eroare: {exc}")

        time.sleep(delay)

    print(f"[+] Finalizat! S-au trimis {count} cereri.")
    return count
