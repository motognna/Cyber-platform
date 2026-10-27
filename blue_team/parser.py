"""Log parsing engine supporting Linux auth.log and Web access logs (Nginx/Apache)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List, Optional
from urllib.parse import unquote, urlparse


class LogType(str, Enum):
    """Supported log categories."""
    AUTH = "auth"
    WEB = "web"
    UNKNOWN = "unknown"


@dataclass
class ParsedEntry:
    """Base dataclass representing a parsed log line."""
    line_number: int
    raw_line: str
    timestamp: Optional[str]
    source_ip: Optional[str]
    log_type: LogType


@dataclass
class AuthEntry(ParsedEntry):
    """Parsed representation of a Linux authentication log entry."""
    service: str
    event_type: str  # failed_password, invalid_user, accepted, closed, pam_session, other
    username: Optional[str] = None
    port: Optional[int] = None
    auth_method: Optional[str] = None  # password, publickey
    raw_message: str = ""


@dataclass
class WebEntry(ParsedEntry):
    """Parsed representation of an Nginx/Apache Combined/Common log entry."""
    method: str = "GET"
    url_path: str = "/"
    query_string: str = ""
    status_code: int = 200
    response_size: int = 0
    referrer: Optional[str] = None
    user_agent: Optional[str] = None


# --- Regex Definitions ---

# Standard Syslog header: (Timestamp) (Host) (Process)[PID]: (Message)
# Supports both RFC 3164 (Oct 22 18:14:02) and RFC 5424 / ISO 8601 (2026-10-22T18:14:02.123+03:00)
SYSLOG_REGEX = re.compile(
    r"^(?:(?P<ts_bsd>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})|(?P<ts_iso>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?))\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<service>[\w\-]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

# Inner SSH auth messages
SSH_FAILED_INVALID = re.compile(
    r"Failed\s+(?P<method>password|publickey)\s+for\s+invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>[\d\.:a-fA-F]+)\s+port\s+(?P<port>\d+)"
)
SSH_FAILED_USER = re.compile(
    r"Failed\s+(?P<method>password|publickey)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>[\d\.:a-fA-F]+)\s+port\s+(?P<port>\d+)"
)
SSH_INVALID_USER = re.compile(
    r"Invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>[\d\.:a-fA-F]+)(?:\s+port\s+(?P<port>\d+))?"
)
SSH_ACCEPTED = re.compile(
    r"Accepted\s+(?P<method>password|publickey)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>[\d\.:a-fA-F]+)\s+port\s+(?P<port>\d+)"
)
SSH_CLOSED = re.compile(
    r"Connection\s+closed\s+by\s+(?:authenticating\s+user\s+)?(?P<user>\S+)?\s*(?P<ip>[\d\.:a-fA-F]+)\s+port\s+(?P<port>\d+)"
)

# Nginx/Apache Combined Log format
# IP - User [Timestamp] "METHOD /path HTTP/x.x" STATUS SIZE "Referrer" "User-Agent"
WEB_COMBINED_REGEX = re.compile(
    r'^(?P<ip>[\d\.:a-fA-F]+)\s+(?P<ident>\S+)\s+(?P<authuser>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<request>[^\s"]+)(?:\s+HTTP/[\d\.]+)?\"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)


def parse_auth_line(line: str, line_number: int) -> Optional[AuthEntry]:
    """Parse a single auth.log syslog line into an AuthEntry object."""
    match = SYSLOG_REGEX.match(line.strip())
    if not match:
        return None

    groups = match.groupdict()
    timestamp = groups.get("ts_bsd") or groups.get("ts_iso")
    service = groups.get("service") or "unknown"
    message = groups.get("message") or ""

    event_type = "other"
    username = None
    ip = None
    port = None
    auth_method = None

    # Check SSH specific patterns
    m_failed_inv = SSH_FAILED_INVALID.search(message)
    if m_failed_inv:
        event_type = "invalid_user"
        auth_method = m_failed_inv.group("method")
        username = m_failed_inv.group("user")
        ip = m_failed_inv.group("ip")
        port = int(m_failed_inv.group("port"))
    else:
        m_failed = SSH_FAILED_USER.search(message)
        if m_failed:
            event_type = "failed_password"
            auth_method = m_failed.group("method")
            username = m_failed.group("user")
            ip = m_failed.group("ip")
            port = int(m_failed.group("port"))
        else:
            m_inv = SSH_INVALID_USER.search(message)
            if m_inv:
                event_type = "invalid_user"
                username = m_inv.group("user")
                ip = m_inv.group("ip")
                if m_inv.group("port"):
                    port = int(m_inv.group("port"))
            else:
                m_acc = SSH_ACCEPTED.search(message)
                if m_acc:
                    event_type = "accepted"
                    auth_method = m_acc.group("method")
                    username = m_acc.group("user")
                    ip = m_acc.group("ip")
                    port = int(m_acc.group("port"))
                else:
                    m_close = SSH_CLOSED.search(message)
                    if m_close:
                        event_type = "closed"
                        username = m_close.group("user")
                        ip = m_close.group("ip")
                        port = int(m_close.group("port"))
                    elif "pam_unix" in message:
                        event_type = "pam_session"

    return AuthEntry(
        line_number=line_number,
        raw_line=line.rstrip("\r\n"),
        timestamp=timestamp,
        source_ip=ip,
        log_type=LogType.AUTH,
        service=service,
        event_type=event_type,
        username=username,
        port=port,
        auth_method=auth_method,
        raw_message=message,
    )


def parse_web_line(line: str, line_number: int) -> Optional[WebEntry]:
    """Parse a single web server access log line into a WebEntry object."""
    match = WEB_COMBINED_REGEX.match(line.strip())
    if not match:
        return None

    groups = match.groupdict()
    ip = groups.get("ip")
    timestamp = groups.get("timestamp")
    method = groups.get("method") or "GET"
    raw_request = groups.get("request") or "/"
    status = int(groups.get("status") or 0)
    size_str = groups.get("size") or "0"
    size = int(size_str) if size_str.isdigit() else 0
    referrer = groups.get("referrer")
    user_agent = groups.get("user_agent")

    # Split request into path and query string (decoding URL entities)
    decoded_request = unquote(raw_request)
    parsed_url = urlparse(decoded_request)
    path = parsed_url.path or "/"
    query = parsed_url.query or ""

    return WebEntry(
        line_number=line_number,
        raw_line=line.rstrip("\r\n"),
        timestamp=timestamp,
        source_ip=ip,
        log_type=LogType.WEB,
        method=method,
        url_path=path,
        query_string=query,
        status_code=status,
        response_size=size,
        referrer=referrer,
        user_agent=user_agent,
    )


def detect_log_type(file_path: Path | str) -> LogType:
    """Inspect the first non-empty lines to determine log type."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Log file not found: {path}")

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for _ in range(20):
            line = f.readline()
            if not line:
                break
            line_str = line.strip()
            if not line_str:
                continue

            if parse_auth_line(line_str, 1) is not None:
                return LogType.AUTH
            if parse_web_line(line_str, 1) is not None:
                return LogType.WEB

    return LogType.UNKNOWN


def parse_log_file(file_path: Path | str, forced_type: Optional[LogType] = None) -> List[ParsedEntry]:
    """Read and parse all valid lines from the given log file."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Fisierul de log nu exista: {path}")

    log_type = forced_type or detect_log_type(path)
    entries: List[ParsedEntry] = []

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for idx, line in enumerate(f, start=1):
            if not line.strip():
                continue

            if log_type == LogType.AUTH:
                entry = parse_auth_line(line, idx)
                if entry:
                    entries.append(entry)
            elif log_type == LogType.WEB:
                entry = parse_web_line(line, idx)
                if entry:
                    entries.append(entry)
            else:
                # Try both as fallback
                entry_a = parse_auth_line(line, idx)
                if entry_a:
                    entries.append(entry_a)
                else:
                    entry_w = parse_web_line(line, idx)
                    if entry_w:
                        entries.append(entry_w)

    return entries
