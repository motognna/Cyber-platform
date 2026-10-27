"""Detection engine with heuristic rules, signature matching, and MITRE ATT&CK mapping."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional
from urllib.parse import unquote

from blue_team.parser import AuthEntry, ParsedEntry, WebEntry


class Severity(str, Enum):
    """Alert severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AttackType(str, Enum):
    """Categorized attack types."""
    SSH_INVALID_USER = "SSH User Enumeration / Guessing"
    SSH_FAILED_LOGIN = "SSH Failed Authentication"
    SQL_INJECTION = "SQL Injection (SQLi)"
    PATH_TRAVERSAL = "Path / Directory Traversal"
    RECON_SCANNER = "Automated Vulnerability Scanner"
    SENSITIVE_PROBE = "Sensitive File / Endpoint Probing"
    SUSPICIOUS = "Suspicious Activity"


@dataclass
class DetectionAlert:
    """Represents a suspicious or malicious hit detected on a log entry."""
    attack_type: AttackType
    severity: Severity
    mitre_id: str
    mitre_tactic: str
    description: str
    matched_detail: str
    entry: ParsedEntry


# --- Signature Patterns for Web Attacks ---

SQLI_PATTERNS = [
    (re.compile(r"(\bUNION\b\s+(?:ALL\s+)?\bSELECT\b)", re.IGNORECASE), "UNION SELECT construct"),
    (re.compile(r"(?:'|\")\s*(?:OR|AND)\s+['\"0-9\w]+\s*=\s*['\"0-9\w]+", re.IGNORECASE), "Boolean-based OR/AND clause"),
    (re.compile(r"(?:'\s*OR\s*1\s*=\s*1|'\s*OR\s*'1'\s*=\s*'1')", re.IGNORECASE), "Tautology bypass (' OR 1=1)"),
    (re.compile(r"\binformation_schema\b", re.IGNORECASE), "Metadata table access (information_schema)"),
    (re.compile(r"\b(SLEEP|BENCHMARK|WAITFOR\s+DELAY)\b", re.IGNORECASE), "Time-based blind SQLi payload"),
    (re.compile(r"(?:--|\#|/\*).*", re.IGNORECASE), "SQL comment injection"),
]

PATH_TRAVERSAL_PATTERNS = [
    (re.compile(r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f)", re.IGNORECASE), "Relative directory traversal (../)"),
    (re.compile(r"(?:/etc/(?:passwd|shadow|hosts|group)|c:[\\/]windows)", re.IGNORECASE), "Sensitive OS file targeting"),
]

SCANNER_USER_AGENTS = [
    (re.compile(r"\bsqlmap\b", re.IGNORECASE), "SQLMap automated SQLi tool"),
    (re.compile(r"\bnikto\b", re.IGNORECASE), "Nikto web vulnerability scanner"),
    (re.compile(r"\b(nmap|masscan)\b", re.IGNORECASE), "Port & network scanner"),
    (re.compile(r"\b(dirbuster|gobuster|ffuf|wfuzz)\b", re.IGNORECASE), "Web content / directory bruteforcer"),
    (re.compile(r"\bnuclei\b", re.IGNORECASE), "Nuclei vulnerability scanner"),
]

SENSITIVE_ENDPOINTS = [
    (re.compile(r"(?:/\.env|/\.git|/\.aws|/\.ssh|/wp-config\.php(?:\.bak)?|/phpmyadmin|/admin\.php\.bak)", re.IGNORECASE), "Sensitive configuration / environment file"),
]


def analyze_entry(entry: ParsedEntry) -> List[DetectionAlert]:
    """Analyze a single parsed log entry and return any alerts triggered."""
    alerts: List[DetectionAlert] = []

    if isinstance(entry, AuthEntry):
        # 1. Invalid user attempts (User Enumeration)
        if entry.event_type == "invalid_user":
            alerts.append(
                DetectionAlert(
                    attack_type=AttackType.SSH_INVALID_USER,
                    severity=Severity.MEDIUM,
                    mitre_id="T1078 / T1110.001",
                    mitre_tactic="Initial Access / Credential Access",
                    description=f"Incercare de autentificare SSH cu cont inexistent ('{entry.username}').",
                    matched_detail=f"User: {entry.username}, IP: {entry.source_ip}",
                    entry=entry,
                )
            )
        # 2. Failed password attempts on existing/known users
        elif entry.event_type == "failed_password":
            severity = Severity.HIGH if entry.username in ("root", "admin", "administrator") else Severity.MEDIUM
            alerts.append(
                DetectionAlert(
                    attack_type=AttackType.SSH_FAILED_LOGIN,
                    severity=severity,
                    mitre_id="T1110.001",
                    mitre_tactic="Credential Access",
                    description=f"Autentificare esuata pe contul '{entry.username}'. Risc de ghicire parola (Brute Force).",
                    matched_detail=f"User: {entry.username}, Method: {entry.auth_method}",
                    entry=entry,
                )
            )

    elif isinstance(entry, WebEntry):
        full_target = unquote(f"{entry.url_path}?{entry.query_string}" if entry.query_string else entry.url_path)

        # 1. SQL Injection signatures
        for pattern, desc in SQLI_PATTERNS:
            match = pattern.search(full_target)
            if match:
                alerts.append(
                    DetectionAlert(
                        attack_type=AttackType.SQL_INJECTION,
                        severity=Severity.HIGH,
                        mitre_id="T1190",
                        mitre_tactic="Initial Access / Exploitation",
                        description=f"Tipar de SQL Injection detectat in cerere: {desc}.",
                        matched_detail=match.group(0),
                        entry=entry,
                    )
                )
                break

        # 2. Path Traversal signatures
        for pattern, desc in PATH_TRAVERSAL_PATTERNS:
            match = pattern.search(full_target)
            if match:
                alerts.append(
                    DetectionAlert(
                        attack_type=AttackType.PATH_TRAVERSAL,
                        severity=Severity.HIGH,
                        mitre_id="T1083 / T1005",
                        mitre_tactic="Discovery / Collection",
                        description=f"Incercare de traversare de directoare (Path Traversal): {desc}.",
                        matched_detail=match.group(0),
                        entry=entry,
                    )
                )
                break

        # 3. Known scanner user agents
        if entry.user_agent:
            for pattern, desc in SCANNER_USER_AGENTS:
                match = pattern.search(entry.user_agent)
                if match:
                    alerts.append(
                        DetectionAlert(
                            attack_type=AttackType.RECON_SCANNER,
                            severity=Severity.MEDIUM,
                            mitre_id="T1595.002",
                            mitre_tactic="Reconnaissance",
                            description=f"User-Agent asociat unui scanner automatizat: {desc}.",
                            matched_detail=match.group(0),
                            entry=entry,
                        )
                    )
                    break

        # 4. Probing for sensitive endpoints
        for pattern, desc in SENSITIVE_ENDPOINTS:
            match = pattern.search(entry.url_path)
            if match:
                alerts.append(
                    DetectionAlert(
                        attack_type=AttackType.SENSITIVE_PROBE,
                        severity=Severity.MEDIUM,
                        mitre_id="T1596",
                        mitre_tactic="Reconnaissance",
                        description=f"Cautare activa de fisiere critice expuse: {desc}.",
                        matched_detail=match.group(0),
                        entry=entry,
                    )
                )
                break

    return alerts


def scan_entries(entries: List[ParsedEntry]) -> List[DetectionAlert]:
    """Scan an entire collection of parsed entries and aggregate all triggered alerts."""
    all_alerts: List[DetectionAlert] = []
    for entry in entries:
        alerts = analyze_entry(entry)
        all_alerts.extend(alerts)
    return all_alerts
