"""Motor de parsare pentru log-uri Linux auth (syslog) si web (Nginx/Apache combined)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List, Optional
from urllib.parse import unquote


class LogType(str, Enum):
    """Tipuri de log suportate."""

    AUTH = "auth"
    WEB = "web"
    UNKNOWN = "unknown"


@dataclass
class ParsedEntry:
    """Reprezentarea de baza a unei linii de log parsate."""

    line_number: int
    raw_line: str
    timestamp: Optional[str]
    source_ip: Optional[str]
    log_type: LogType


@dataclass
class AuthEntry(ParsedEntry):
    """Eveniment de autentificare Linux (sshd, cron, sudo etc.)."""

    service: str = "unknown"
    # failed_password | invalid_user | accepted | closed | other
    event_type: str = "other"
    username: Optional[str] = None
    port: Optional[int] = None
    pid: Optional[int] = None
    auth_method: Optional[str] = None
    raw_message: str = ""


@dataclass
class WebEntry(ParsedEntry):
    """Cerere HTTP dintr-un access log Nginx/Apache (format combined/common)."""

    method: str = "GET"
    url_path: str = "/"
    query_string: str = ""
    raw_request: str = "/"
    status_code: int = 0
    response_size: int = 0
    referrer: Optional[str] = None
    user_agent: Optional[str] = None


_IP = r"[0-9a-fA-F:.]+"

# Antet syslog: RFC 3164 ("Oct 22 18:14:02") sau ISO 8601 ("2026-10-22T18:14:02+03:00")
SYSLOG_REGEX = re.compile(
    r"^(?:(?P<ts_bsd>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})"
    r"|(?P<ts_iso>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?))\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<service>[\w.\-/]+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

SSH_FAILED_INVALID = re.compile(
    rf"Failed\s+(?P<method>\S+)\s+for\s+invalid\s+user\s+(?P<user>.+?)\s+from\s+(?P<ip>{_IP})\s+port\s+(?P<port>\d+)"
)
SSH_FAILED_USER = re.compile(
    rf"Failed\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>{_IP})\s+port\s+(?P<port>\d+)"
)
SSH_INVALID_USER = re.compile(
    rf"Invalid\s+user\s+(?P<user>.*?)\s+from\s+(?P<ip>{_IP})(?:\s+port\s+(?P<port>\d+))?"
)
SSH_ACCEPTED = re.compile(
    rf"Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>{_IP})\s+port\s+(?P<port>\d+)"
)
SSH_CLOSED = re.compile(
    rf"(?:Connection\s+closed\s+by|Disconnected\s+from)\s+(?:(?:authenticating|invalid)\s+user\s+(?P<user>\S+)\s+)?"
    rf"(?P<ip>{_IP})\s+port\s+(?P<port>\d+)"
)

# IP - user [timestamp] "METHOD request [HTTP/x]" status size ["referrer" "user-agent"]
WEB_REGEX = re.compile(
    rf'^(?P<ip>{_IP})\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Za-z]+)\s+(?P<request>.*?)(?:\s+HTTP/[\d.]+)?"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)


def _to_int(value: Optional[str]) -> Optional[int]:
    """Converteste in int un grup optional de regex."""
    return int(value) if value else None


def parse_auth_line(line: str, line_number: int = 1) -> Optional[AuthEntry]:
    """Parseaza o linie syslog/auth.log. Returneaza None daca nu respecta formatul."""
    match = SYSLOG_REGEX.match(line.strip())
    if not match:
        return None

    g = match.groupdict()
    message = g["message"] or ""
    event_type = "other"
    username: Optional[str] = None
    ip: Optional[str] = None
    port: Optional[int] = None
    method: Optional[str] = None

    # Ordinea conteaza: "Failed ... invalid user" trebuie testat inaintea lui "Failed ... user".
    for event, regex in (
        ("invalid_user", SSH_FAILED_INVALID),
        ("failed_password", SSH_FAILED_USER),
        ("invalid_user", SSH_INVALID_USER),
        ("accepted", SSH_ACCEPTED),
        ("closed", SSH_CLOSED),
    ):
        m = regex.search(message)
        if m:
            event_type = event
            groups = m.groupdict()
            username = groups.get("user")
            ip = groups.get("ip")
            port = _to_int(groups.get("port"))
            method = groups.get("method")
            break

    return AuthEntry(
        line_number=line_number,
        raw_line=line.rstrip("\r\n"),
        timestamp=g.get("ts_bsd") or g.get("ts_iso"),
        source_ip=ip,
        log_type=LogType.AUTH,
        service=g.get("service") or "unknown",
        event_type=event_type,
        username=username,
        port=port,
        pid=_to_int(g.get("pid")),
        auth_method=method,
        raw_message=message,
    )


def parse_web_line(line: str, line_number: int = 1) -> Optional[WebEntry]:
    """Parseaza o linie de access log web. Returneaza None daca nu respecta formatul."""
    match = WEB_REGEX.match(line.strip())
    if not match:
        return None

    g = match.groupdict()
    raw_request = g["request"] or "/"
    # Separam pe cererea BRUTA: '#' sau '?' din payload nu trebuie sa piarda partea de query.
    path, _, query = raw_request.partition("?")
    size = g["size"]

    return WebEntry(
        line_number=line_number,
        raw_line=line.rstrip("\r\n"),
        timestamp=g["timestamp"],
        source_ip=g["ip"],
        log_type=LogType.WEB,
        method=g["method"].upper(),
        url_path=unquote(path) or "/",
        query_string=unquote(query),
        raw_request=raw_request,
        status_code=int(g["status"]),
        response_size=int(size) if size.isdigit() else 0,
        referrer=g.get("referrer"),
        user_agent=g.get("user_agent"),
    )


def detect_log_type(file_path: Path | str, sample_lines: int = 50) -> LogType:
    """Detecteaza tipul logului dupa majoritatea liniilor din primele `sample_lines` linii."""
    path = Path(file_path)
    auth_hits = web_hits = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for index, line in enumerate(handle):
            if index >= sample_lines:
                break
            if not line.strip():
                continue
            # Web testat primul: o linie web nu se potriveste niciodata antetului syslog.
            if parse_web_line(line):
                web_hits += 1
            elif parse_auth_line(line):
                auth_hits += 1

    if not auth_hits and not web_hits:
        return LogType.UNKNOWN
    return LogType.WEB if web_hits >= auth_hits else LogType.AUTH


def parse_log_file(
    file_path: Path | str, forced_type: Optional[LogType] = None
) -> List[ParsedEntry]:
    """Citeste un fisier de log si returneaza intrarile parsate.

    Raises:
        FileNotFoundError: fisierul nu exista.
        IsADirectoryError: calea indica un director.
        PermissionError: lipsesc drepturile de citire.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Fisierul de log nu exista: {path}")
    if not path.is_file():
        raise IsADirectoryError(f"Calea nu este un fisier: {path}")

    log_type = forced_type or detect_log_type(path)
    entries: List[ParsedEntry] = []

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            entry: Optional[ParsedEntry] = None
            if log_type == LogType.AUTH:
                entry = parse_auth_line(line, number)
            elif log_type == LogType.WEB:
                entry = parse_web_line(line, number)
            if entry:
                entries.append(entry)

    return entries
