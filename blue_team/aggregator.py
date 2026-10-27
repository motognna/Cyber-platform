"""Incident Aggregator: Correlates raw detection alerts into cohesive, actionable security incidents."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from blue_team.detector import AttackType, DetectionAlert, Severity
from blue_team.parser import AuthEntry, WebEntry


@dataclass
class SecurityIncident:
    """Consolidated representation of multiple related security alerts."""
    incident_id: str
    title: str
    attack_type: AttackType
    severity: Severity
    source_ip: str
    mitre_id: str
    mitre_tactic: str
    event_count: int
    first_seen: str
    last_seen: str
    targeted_entities: List[str] = field(default_factory=list)
    sample_logs: List[str] = field(default_factory=list)
    description: str = ""

    def to_llm_context(self) -> str:
        """Format the incident details into a concise, high-context prompt block for the LLM."""
        entities_str = ", ".join(self.targeted_entities[:8])
        if len(self.targeted_entities) > 8:
            entities_str += f" (+{len(self.targeted_entities) - 8} others)"

        sample_lines = "\n".join([f"  - {line}" for line in self.sample_logs[:4]])

        return (
            f"=== SECURITY INCIDENT REPORT [{self.incident_id}] ===\n"
            f"Tip Atac Identificat: {self.attack_type.value}\n"
            f"Severitate: {self.severity.value}\n"
            f"Cadru MITRE ATT&CK: {self.mitre_id} ({self.mitre_tactic})\n"
            f"Adresa IP Sursa (Atacator): {self.source_ip}\n"
            f"Numar Total Evenimente: {self.event_count}\n"
            f"Fereastra Temporala: {self.first_seen} pana la {self.last_seen}\n"
            f"Tinte Vizate (Utilizatori/URL-uri): {entities_str or 'N/A'}\n"
            f"Linii de Log Reprezentative:\n{sample_lines}\n"
        )


def aggregate_alerts(alerts: List[DetectionAlert]) -> List[SecurityIncident]:
    """Group individual alerts by source IP and primary attack category into cohesive incidents."""
    if not alerts:
        return []

    # Map groups: (source_ip, attack_category) -> List[DetectionAlert]
    groups: Dict[Tuple[str, str], List[DetectionAlert]] = {}

    for alert in alerts:
        ip = alert.entry.source_ip or "Unknown IP"

        # Group SSH user enumeration & failed logins together as brute force if from same IP
        if alert.attack_type in (AttackType.SSH_INVALID_USER, AttackType.SSH_FAILED_LOGIN):
            category = "SSH_BRUTE_FORCE_CAMPAIGN"
        else:
            category = alert.attack_type.name

        key = (ip, category)
        groups.setdefault(key, []).append(alert)

    incidents: List[SecurityIncident] = []

    for idx, ((ip, category), alert_list) in enumerate(groups.items(), start=1):
        first_alert = alert_list[0]
        last_alert = alert_list[-1]

        # Extract timestamps
        first_ts = first_alert.entry.timestamp or "N/A"
        last_ts = last_alert.entry.timestamp or "N/A"

        # Collect unique targeted entities (usernames or web paths)
        targets = set()
        sample_logs: List[str] = []

        # Determine highest severity in group
        highest_sev = Severity.LOW
        sev_rank = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}

        for a in alert_list:
            if sev_rank[a.severity] > sev_rank[highest_sev]:
                highest_sev = a.severity

            if isinstance(a.entry, AuthEntry) and a.entry.username:
                targets.add(a.entry.username)
            elif isinstance(a.entry, WebEntry) and a.entry.url_path:
                targets.add(a.entry.url_path)

            if len(sample_logs) < 3 and a.entry.raw_line not in sample_logs:
                sample_logs.append(a.entry.raw_line)

        # Decide title and description based on category
        count = len(alert_list)
        if category == "SSH_BRUTE_FORCE_CAMPAIGN":
            attack_type = AttackType.SSH_FAILED_LOGIN
            title = f"SSH Brute Force & Credential Guessing ({count} incercari)"
            mitre_id = "T1110.001 (Password Guessing)"
            mitre_tactic = "Credential Access"
            # Elevate severity if count is high
            if count >= 5:
                highest_sev = Severity.HIGH
            desc = f"Atacator de la IP {ip} a efectuat {count} incercari repetate de autentificare SSH."
        elif category == AttackType.SQL_INJECTION.name:
            attack_type = AttackType.SQL_INJECTION
            title = f"Campanie SQL Injection ({count} cereri malițioase)"
            mitre_id = "T1190"
            mitre_tactic = "Initial Access / Exploitation"
            desc = f"Atacatorul a injectat clauze SQL in parametrii aplicatiei web pentru a manipula baza de date."
        elif category == AttackType.PATH_TRAVERSAL.name:
            attack_type = AttackType.PATH_TRAVERSAL
            title = f"Path Traversal & Arbitrary File Read ({count} cereri)"
            mitre_id = "T1083 / T1005"
            mitre_tactic = "Discovery / Collection"
            desc = f"Incercari de a accesa fisiere de sistem folosind secvente relative ../."
        elif category == AttackType.RECON_SCANNER.name:
            attack_type = AttackType.RECON_SCANNER
            title = f"Scanare Automata de Securitate ({count} cereri)"
            mitre_id = "T1595.002"
            mitre_tactic = "Reconnaissance"
            desc = f"Trafic generat de unelte automate de recunoastere si auditare a vulnerabilitatilor."
        elif category == AttackType.SENSITIVE_PROBE.name:
            attack_type = AttackType.SENSITIVE_PROBE
            title = f"Probing Fisiere Critice & Configurari ({count} cereri)"
            mitre_id = "T1596"
            mitre_tactic = "Reconnaissance"
            desc = f"Incercari de accesare a fisierelor de mediu (.env, config) si panourilor de administrare."
        else:
            attack_type = first_alert.attack_type
            title = f"{first_alert.attack_type.value} ({count} evenimente)"
            mitre_id = first_alert.mitre_id
            mitre_tactic = first_alert.mitre_tactic
            desc = first_alert.description

        incident = SecurityIncident(
            incident_id=f"INC-{idx:03d}",
            title=title,
            attack_type=attack_type,
            severity=highest_sev,
            source_ip=ip,
            mitre_id=mitre_id,
            mitre_tactic=mitre_tactic,
            event_count=count,
            first_seen=first_ts,
            last_seen=last_ts,
            targeted_entities=sorted(list(targets)),
            sample_logs=sample_logs,
            description=desc,
        )
        incidents.append(incident)

    return incidents
