"""Motor de detectie: reguli euristice/semnaturi + corelare intre evenimente."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Pattern, Set, Tuple
from urllib.parse import unquote

from blue_team.catalog import AttackType, Severity
from blue_team.parser import AuthEntry, ParsedEntry, WebEntry

DEFAULT_BRUTEFORCE_THRESHOLD = 3


@dataclass
class DetectionAlert:
    """O potrivire de regula pe o singura linie de log."""

    attack_type: AttackType
    severity: Severity
    description: str
    matched_detail: str
    entry: ParsedEntry


_I = re.IGNORECASE

SQLI_RULES: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"\bunion\b(?:\s|/\*.*?\*/)+(?:all\s+)?select\b", _I), "UNION SELECT"),
    (re.compile(r"\b(?:or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+", _I), "tautologie booleana (OR 1=1)"),
    (re.compile(r"['\"]\s*(?:or|and)\b", _I), "ghilimele urmate de OR/AND"),
    (re.compile(r"['\"]\s*(?:--|#|;|/\*)"), "ghilimele urmate de comentariu SQL"),
    (re.compile(r";\s*(?:drop|insert|update|delete|exec|select)\b", _I), "interogari stivuite"),
    (re.compile(r"\binformation_schema\b|\bsqlite_master\b", _I), "enumerare schema (information_schema)"),
    (
        re.compile(
            r"\bsleep\s*\(|\bpg_sleep\b|\bbenchmark\s*\(|\bwaitfor\s+delay\b|\bload_file\s*\(|"
            r"\binto\s+(?:out|dump)file\b|\bextractvalue\s*\(|\bupdatexml\s*\(",
            _I,
        ),
        "functie SQL periculoasa (SLEEP/LOAD_FILE/...)",
    ),
    (re.compile(r"\bselect\b.+\bfrom\b", _I), "SELECT ... FROM in parametru"),
]

TRAVERSAL_RULES: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"\.\.[/\\]|[/\\]\.\.(?:$|[?#])"), "secventa '../'"),
    (re.compile(r"/etc/(?:passwd|shadow|group|hosts)\b|/proc/self/", _I), "fisier de sistem Linux"),
    (re.compile(r"\b(?:boot|win)\.ini\b|\bc:[/\\]windows", _I), "fisier de sistem Windows"),
]

RCE_RULES: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"\$\{\s*jndi\s*:", _I), "Log4Shell (${jndi:...})"),
    (re.compile(r"\(\)\s*\{\s*:\s*;\s*\}"), "Shellshock (() { :;})"),
    (
        re.compile(
            r"(?:;|\|\|?|&&|`|\$\()\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|ncat|bash|sh|python[23]?|perl|"
            r"php|powershell|cmd|chmod|rm)\b",
            _I,
        ),
        "operator shell urmat de comanda",
    ),
    (re.compile(r"/bin/(?:ba)?sh\b|cmd\.exe|base64\s+-d", _I), "invocare shell/decodare payload"),
    (re.compile(r"\b(?:system|passthru|shell_exec|eval)\s*\(", _I), "functie de executie (system/eval)"),
]

XSS_RULES: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"<\s*script\b", _I), "tag <script>"),
    (re.compile(r"javascript\s*:", _I), "URI javascript:"),
    (re.compile(r"<[^>]{0,60}\bon\w+\s*=", _I), "handler de eveniment inline (onerror=...)"),
]

SCANNER_USER_AGENTS: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"\bsqlmap\b", _I), "sqlmap (SQL injection automat)"),
    (re.compile(r"\bnikto\b", _I), "Nikto (scanner web)"),
    (re.compile(r"\b(?:nmap|masscan|zgrab)\b", _I), "scanner de retea (nmap/masscan)"),
    (re.compile(r"\b(?:dirbuster|gobuster|ffuf|wfuzz|feroxbuster)\b", _I), "brute-force de directoare"),
    (re.compile(r"\b(?:nuclei|acunetix|nessus|openvas|wpscan|whatweb)\b", _I), "scanner de vulnerabilitati"),
    (re.compile(r"\bhydra\b", _I), "THC-Hydra (brute force)"),
]

SENSITIVE_PATHS: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"/\.(?:env|git|svn|aws|ssh|htpasswd|DS_Store)(?:/|$|\.)", _I), "fisier ascuns/credentiale"),
    (re.compile(r"wp-config\.php|/id_rsa\b|/server-status\b|/actuator(?:/|$)", _I), "configurare/endpoint intern"),
    (re.compile(r"/(?:phpmyadmin|pma|adminer)(?:/|\.php|$)", _I), "panou de administrare baza de date"),
    (re.compile(r"\.(?:bak|old|orig|swp|sql|dump|zip|tar\.gz)(?:$|\?)", _I), "backup/dump expus"),
]

_ADMIN_USERS = frozenset({"root", "admin", "administrator"})


def _first_match(
    rules: List[Tuple[Pattern[str], str]], text: str
) -> Optional[Tuple[str, str]]:
    """Returneaza (descriere_regula, text_potrivit) pentru prima regula care se potriveste."""
    for pattern, description in rules:
        found = pattern.search(text)
        if found:
            return description, found.group(0)
    return None


def _decode_payload(raw_request: str) -> str:
    """Decodeaza URL de doua ori (prinde %252e%252e) si transforma '+' in spatiu."""
    return unquote(unquote(raw_request.replace("+", " ")))


def _analyze_auth(entry: AuthEntry) -> List[DetectionAlert]:
    """Reguli pentru evenimente de autentificare SSH."""
    if entry.event_type not in ("invalid_user", "failed_password"):
        return []

    user = entry.username or "?"
    if entry.event_type == "invalid_user":
        description = f"Autentificare SSH cu utilizator inexistent '{user}'"
        severity = Severity.MEDIUM
    else:
        description = f"Parola gresita pentru contul existent '{user}'"
        severity = Severity.HIGH if user in _ADMIN_USERS else Severity.MEDIUM

    return [
        DetectionAlert(
            attack_type=AttackType.SSH_BRUTE_FORCE,
            severity=severity,
            description=description,
            matched_detail=f"user={user} ip={entry.source_ip}",
            entry=entry,
        )
    ]


def _analyze_web(entry: WebEntry) -> List[DetectionAlert]:
    """Reguli pentru cereri HTTP (payload in URL/query, User-Agent, Referer)."""
    alerts: List[DetectionAlert] = []
    payload = _decode_payload(entry.raw_request)
    ok_status = 200 <= entry.status_code < 300

    def add(kind: AttackType, severity: Severity, description: str, detail: str) -> None:
        alerts.append(DetectionAlert(kind, severity, description, detail, entry))

    hit = _first_match(SQLI_RULES, payload)
    if hit:
        add(AttackType.SQL_INJECTION, Severity.HIGH, f"Tipar SQL injection: {hit[0]}", hit[1])

    hit = _first_match(TRAVERSAL_RULES, payload)
    if hit:
        severity = Severity.CRITICAL if ok_status else Severity.HIGH
        suffix = " (raspuns 2xx: posibila divulgare de fisier!)" if ok_status else ""
        add(AttackType.PATH_TRAVERSAL, severity, f"Path traversal: {hit[0]}{suffix}", hit[1])

    # Log4Shell/Shellshock se ascund frecvent in headere, nu doar in URL.
    header_blob = f"{entry.user_agent or ''} {entry.referrer or ''}"
    hit = _first_match(RCE_RULES, payload) or _first_match(RCE_RULES, header_blob)
    if hit:
        severity = Severity.CRITICAL if ok_status else Severity.HIGH
        add(AttackType.RCE_ATTEMPT, severity, f"Injectie de comenzi/cod: {hit[0]}", hit[1])

    hit = _first_match(XSS_RULES, payload)
    if hit:
        add(AttackType.XSS, Severity.MEDIUM, f"Tipar XSS: {hit[0]}", hit[1])

    if entry.user_agent:
        hit = _first_match(SCANNER_USER_AGENTS, entry.user_agent)
        if hit:
            add(AttackType.RECON_SCANNER, Severity.MEDIUM, f"User-Agent de scanner: {hit[0]}", hit[1])

    hit = _first_match(SENSITIVE_PATHS, entry.url_path)
    if hit:
        add(AttackType.SENSITIVE_PROBE, Severity.MEDIUM, f"Cautare resursa sensibila: {hit[0]}", hit[1])

    return alerts


def analyze_entry(entry: ParsedEntry) -> List[DetectionAlert]:
    """Analizeaza o singura intrare de log si returneaza alertele declansate."""
    if isinstance(entry, AuthEntry):
        return _analyze_auth(entry)
    if isinstance(entry, WebEntry):
        return _analyze_web(entry)
    return []


def _attempt_key(entry: AuthEntry) -> Tuple[Optional[int], Optional[str], Optional[str]]:
    """Cheie de deduplicare: sshd scrie 'Invalid user' SI 'Failed password' pentru aceeasi incercare."""
    return entry.pid, entry.source_ip, entry.username


def _correlate_compromise(entries: List[ParsedEntry], threshold: int) -> List[DetectionAlert]:
    """Detecteaza login reusit venit dupa >= `threshold` esecuri de la aceeasi adresa IP."""
    failed: Dict[str, Set[Tuple[Optional[int], Optional[str], Optional[str]]]] = {}
    alerts: List[DetectionAlert] = []

    for entry in entries:
        if not isinstance(entry, AuthEntry) or not entry.source_ip:
            continue
        if entry.event_type in ("invalid_user", "failed_password"):
            failed.setdefault(entry.source_ip, set()).add(_attempt_key(entry))
        elif entry.event_type == "accepted":
            count = len(failed.get(entry.source_ip, ()))
            if count >= threshold:
                alerts.append(
                    DetectionAlert(
                        attack_type=AttackType.SSH_COMPROMISE,
                        severity=Severity.CRITICAL,
                        description=(
                            f"Login reusit pentru '{entry.username}' dupa {count} esecuri "
                            f"de la aceeasi sursa"
                        ),
                        matched_detail=f"user={entry.username} ip={entry.source_ip} metoda={entry.auth_method}",
                        entry=entry,
                    )
                )
    return alerts


def scan_entries(
    entries: List[ParsedEntry], bruteforce_threshold: int = DEFAULT_BRUTEFORCE_THRESHOLD
) -> List[DetectionAlert]:
    """Ruleaza toate regulile pe o lista de intrari, plus corelarea intre evenimente."""
    alerts: List[DetectionAlert] = []
    for entry in entries:
        alerts.extend(analyze_entry(entry))
    alerts.extend(_correlate_compromise(entries, bruteforce_threshold))
    return alerts
