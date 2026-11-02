"""Catalog central de atacuri: metadate MITRE ATT&CK, severitate si masuri defensive de referinta.

Aceleasi informatii sunt folosite de detector, agregator si de promptul AI Tutor, astfel
incat explicatiile (inclusiv ale modelelor mici) raman ancorate in fapte corecte.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Tuple


class Severity(str, Enum):
    """Niveluri de severitate pentru alerte si incidente."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


SEVERITY_RANK: Dict[Severity, int] = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class AttackType(str, Enum):
    """Categorii de atac detectate de motorul euristic."""

    SSH_BRUTE_FORCE = "ssh_brute_force"
    SSH_COMPROMISE = "ssh_compromise"
    SQL_INJECTION = "sql_injection"
    PATH_TRAVERSAL = "path_traversal"
    RCE_ATTEMPT = "rce_attempt"
    XSS = "xss"
    RECON_SCANNER = "recon_scanner"
    SENSITIVE_PROBE = "sensitive_probe"


@dataclass(frozen=True)
class AttackInfo:
    """Metadate statice despre un tip de atac."""

    title: str
    mitre_id: str
    mitre_tactic: str
    summary: str
    defenses: Tuple[str, ...]


ATTACK_CATALOG: Dict[AttackType, AttackInfo] = {
    AttackType.SSH_BRUTE_FORCE: AttackInfo(
        title="SSH Brute Force / Password Guessing",
        mitre_id="T1110.001",
        mitre_tactic="Credential Access",
        summary="Incercari repetate de autentificare SSH cu utilizatori si parole ghicite.",
        defenses=(
            "Autentificare doar cu chei SSH: 'PasswordAuthentication no' in /etc/ssh/sshd_config",
            "Dezactivare root login: 'PermitRootLogin no' si limitare cu 'AllowUsers'",
            "Blocare automata a IP-urilor: instalare fail2ban (jail 'sshd') sau reguli firewalld rate-limit",
            "'MaxAuthTries 3' si 'LoginGraceTime 20' in sshd_config; mutarea/ascunderea portului 22 e doar o masura minora",
        ),
    ),
    AttackType.SSH_COMPROMISE: AttackInfo(
        title="Autentificare reusita dupa brute force (posibila compromitere)",
        mitre_id="T1078",
        mitre_tactic="Initial Access / Persistence",
        summary="Aceeasi sursa care a esuat repetat s-a autentificat apoi cu succes: contul poate fi compromis.",
        defenses=(
            "Raspuns la incident: blocheaza IP-ul, inchide sesiunea ('pkill -u <user>'), schimba parola/cheile contului",
            "Verifica persistenta: ~/.ssh/authorized_keys, crontab -l, 'last -a', 'journalctl -u sshd'",
            "Trecere la autentificare doar cu chei + MFA pentru acces privilegiat",
            "Auditeaza comenzile rulate in sesiune (auditd / history) si cauta miscare laterala",
        ),
    ),
    AttackType.SQL_INJECTION: AttackInfo(
        title="SQL Injection",
        mitre_id="T1190",
        mitre_tactic="Initial Access",
        summary="Payload SQL injectat in parametri HTTP pentru a manipula interogarile bazei de date.",
        defenses=(
            "Interogari parametrizate / prepared statements (nu concatenare de stringuri SQL)",
            "Validare stricta a input-ului (tipuri, liste albe) si ORM folosit corect",
            "Utilizator de baza de date cu drepturi minime (fara FILE, DROP, acces la alte scheme)",
            "WAF (ModSecurity + OWASP CRS) si alerte pe raspunsuri 200 anormal de mari",
        ),
    ),
    AttackType.PATH_TRAVERSAL: AttackInfo(
        title="Path / Directory Traversal",
        mitre_id="T1083",
        mitre_tactic="Discovery / Collection",
        summary="Secvente '../' folosite pentru a citi fisiere din afara directorului web.",
        defenses=(
            "Nu construi cai de fisier din input utilizator; foloseste identificatori mapati pe o lista alba",
            "Normalizeaza calea (realpath) si verifica ca ramane in directorul permis",
            "Ruleaza serviciul web cu un utilizator fara drepturi, eventual in chroot/container",
            "Regula WAF/nginx care respinge '..' si '%2e%2e' in URL",
        ),
    ),
    AttackType.RCE_ATTEMPT: AttackInfo(
        title="Command / Code Injection (RCE)",
        mitre_id="T1059",
        mitre_tactic="Execution",
        summary="Incercare de executie de comenzi pe server (shell injection, Log4Shell, Shellshock).",
        defenses=(
            "Nu pasa input utilizator catre shell; foloseste API-uri fara shell (subprocess cu lista de argumente)",
            "Actualizeaza componentele vulnerabile (Log4j >= 2.17, bash, framework-uri web)",
            "Ruleaza aplicatiile cu drepturi minime si blocheaza iesirea la internet (egress filtering)",
            "Monitorizeaza procese copil neobisnuite ale serverului web (auditd, EDR)",
        ),
    ),
    AttackType.XSS: AttackInfo(
        title="Cross-Site Scripting (XSS)",
        mitre_id="T1189",
        mitre_tactic="Initial Access",
        summary="Cod JavaScript injectat in parametri pentru a rula in browserul altor utilizatori.",
        defenses=(
            "Codifica (escape) output-ul HTML in functie de context; foloseste template engine cu autoescape",
            "Content-Security-Policy restrictiva si cookie-uri cu 'HttpOnly' + 'Secure' + 'SameSite'",
            "Valideaza si sanitizeaza input-ul (ex. biblioteca DOMPurify pentru HTML permis)",
        ),
    ),
    AttackType.RECON_SCANNER: AttackInfo(
        title="Scanner automat de vulnerabilitati",
        mitre_id="T1595.002",
        mitre_tactic="Reconnaissance",
        summary="Trafic generat de unelte automate (sqlmap, Nikto, Nmap, gobuster etc.).",
        defenses=(
            "Rate limiting si blocare dupa User-Agent/comportament (nginx limit_req, fail2ban filter nginx-botsearch)",
            "WAF care recunoaste semnaturi de scannere",
            "Tine software-ul actualizat: scannerele cauta versiuni si configurari cunoscute vulnerabile",
        ),
    ),
    AttackType.SENSITIVE_PROBE: AttackInfo(
        title="Cautare de fisiere/endpoint-uri sensibile",
        mitre_id="T1595.003",
        mitre_tactic="Reconnaissance",
        summary="Cereri catre .env, .git, backup-uri, phpMyAdmin sau fisiere de configurare expuse.",
        defenses=(
            "Nu pastra .env, .git, backup-uri sau dump-uri SQL in radacina web",
            "Blocheaza accesul la fisiere ascunse in nginx: 'location ~ /\\. { deny all; }'",
            "Restrictioneaza panourile de administrare (VPN/IP allowlist/autentificare suplimentara)",
        ),
    ),
}


def info_for(attack_type: AttackType) -> AttackInfo:
    """Returneaza metadatele catalogului pentru un tip de atac."""
    return ATTACK_CATALOG[attack_type]
